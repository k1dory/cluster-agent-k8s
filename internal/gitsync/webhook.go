package gitsync

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"agent-sandbox/internal/gitrepo"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/render"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// Webhooks: the provider tells the platform what happened in the repository, and the platform
// does what the CI templates would: a push to the followed ref syncs it, a pull (merge) request
// gets the plan of its head as a comment and a commit status. Nothing is installed in the
// repository but the webhook itself. A delivery is accepted only when it is signed with the
// repository's webhook secret (a credential by reference) and names the registered repository.

// Providers.
const (
	ProviderGitHub = "github"
	ProviderGitLab = "gitlab"
)

// Hook events as the platform names them.
const (
	EventPush         = "push"
	EventPullRequest  = "pull_request"
	EventMergeRequest = "merge_request"
)

// Delivery is what a webhook payload said, reduced to what the platform acts on.
type Delivery struct {
	Provider string
	Event    string // EventPush, EventPullRequest, EventMergeRequest, or the provider's name for anything else
	ID       string // the provider's delivery id
	Ref      string // push: the full ref name
	After    string // push: the new head ("" when the ref was deleted)
	RepoURLs []string
	PR       *PullRequest
}

// PullRequest is a pull or merge request as a delivery describes it.
type PullRequest struct {
	Number  int
	Action  string // the provider's action
	HeadSHA string
	HeadRef string // the ref the platform fetches the head from (refs/pull/N/head, refs/merge-requests/N/head)
}

var (
	// ErrUnknownProvider: the headers name neither GitHub nor GitLab.
	ErrUnknownProvider = errors.New("unknown webhook provider")
	// ErrBadSignature: the delivery is not signed with the repository's webhook secret.
	ErrBadSignature = errors.New("the webhook signature does not match")
	// ErrNoWebhook: the repository has no webhook secret, so it accepts no deliveries.
	ErrNoWebhook = errors.New("the repository accepts no webhooks (no webhook_secret in its spec)")
)

// ParseDelivery reduces a GitHub or GitLab payload to a Delivery. The provider comes from the
// headers; an event the platform does not act on is returned with the provider's name and no
// error, so the caller can record it as ignored.
func ParseDelivery(hdr http.Header, body []byte) (Delivery, error) {
	switch {
	case hdr.Get("X-GitHub-Event") != "":
		return parseGitHub(hdr.Get("X-GitHub-Event"), hdr.Get("X-GitHub-Delivery"), body)
	case hdr.Get("X-Gitlab-Event") != "":
		return parseGitLab(hdr.Get("X-Gitlab-Event"), hdr.Get("X-Gitlab-Event-UUID"), body)
	}
	return Delivery{}, ErrUnknownProvider
}

func parseGitHub(event, id string, body []byte) (Delivery, error) {
	d := Delivery{Provider: ProviderGitHub, Event: event, ID: id}
	var p struct {
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Deleted    bool   `json:"deleted"`
		Action     string `json:"action"`
		Number     int    `json:"number"`
		Repository struct {
			CloneURL string `json:"clone_url"`
			HTMLURL  string `json:"html_url"`
			SSHURL   string `json:"ssh_url"`
		} `json:"repository"`
		PullRequest *struct {
			Number int `json:"number"`
			Head   struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return d, fmt.Errorf("payload: %w", err)
	}
	d.RepoURLs = []string{p.Repository.CloneURL, p.Repository.HTMLURL}
	switch event {
	case "push":
		d.Event, d.Ref = EventPush, p.Ref
		if !p.Deleted && shaRe.MatchString(p.After) && p.After != strings.Repeat("0", 40) {
			d.After = p.After
		}
	case "pull_request":
		if p.PullRequest == nil {
			return d, errors.New("payload: pull_request missing")
		}
		n := p.PullRequest.Number
		if n == 0 {
			n = p.Number
		}
		d.Event = EventPullRequest
		d.PR = &PullRequest{Number: n, Action: p.Action, HeadSHA: p.PullRequest.Head.SHA, HeadRef: fmt.Sprintf("refs/pull/%d/head", n)}
	}
	return d, nil
}

func parseGitLab(event, id string, body []byte) (Delivery, error) {
	d := Delivery{Provider: ProviderGitLab, Event: event, ID: id}
	var p struct {
		ObjectKind string `json:"object_kind"`
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Project    struct {
			WebURL  string `json:"web_url"`
			HTTPURL string `json:"http_url"`
			GitHTTP string `json:"git_http_url"`
		} `json:"project"`
		Attributes *struct {
			IID        int    `json:"iid"`
			Action     string `json:"action"`
			LastCommit struct {
				ID string `json:"id"`
			} `json:"last_commit"`
		} `json:"object_attributes"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return d, fmt.Errorf("payload: %w", err)
	}
	d.RepoURLs = []string{p.Project.HTTPURL, p.Project.GitHTTP, p.Project.WebURL}
	switch p.ObjectKind {
	case "push", "tag_push":
		d.Event, d.Ref = EventPush, p.Ref
		if shaRe.MatchString(p.After) && p.After != strings.Repeat("0", 40) {
			d.After = p.After
		}
	case "merge_request":
		if p.Attributes == nil {
			return d, errors.New("payload: object_attributes missing")
		}
		d.Event = EventMergeRequest
		d.PR = &PullRequest{Number: p.Attributes.IID, Action: p.Attributes.Action, HeadSHA: p.Attributes.LastCommit.ID, HeadRef: fmt.Sprintf("refs/merge-requests/%d/head", p.Attributes.IID)}
	}
	return d, nil
}

// Verify checks the delivery against the repository's webhook secret: GitHub signs the body
// (X-Hub-Signature-256, HMAC-SHA256), GitLab sends the secret itself (X-Gitlab-Token).
func Verify(provider string, hdr http.Header, body []byte, secret string) error {
	if secret == "" {
		return ErrNoWebhook
	}
	switch provider {
	case ProviderGitHub:
		sig := strings.TrimPrefix(hdr.Get("X-Hub-Signature-256"), "sha256=")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := hex.EncodeToString(mac.Sum(nil))
		if sig == "" || subtle.ConstantTimeCompare([]byte(strings.ToLower(sig)), []byte(want)) != 1 {
			return ErrBadSignature
		}
	case ProviderGitLab:
		if got := hdr.Get("X-Gitlab-Token"); got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(secret)) != 1 {
			return ErrBadSignature
		}
	default:
		return ErrUnknownProvider
	}
	return nil
}

// SameRepository reports whether one of the URLs a delivery names is the registered one:
// same host (case-insensitive) and path, ".git" and a trailing slash aside.
func SameRepository(registered string, candidates []string) bool {
	want, ok := repoKey(registered)
	if !ok {
		return false
	}
	for _, c := range candidates {
		if got, ok := repoKey(c); ok && got == want {
			return true
		}
	}
	return false
}

func repoKey(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	path := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
	return strings.ToLower(u.Hostname()) + path, true
}

// HookHTTPStatus is the status code of a Hook result: 202 when the platform does something
// with the delivery, 200 when it records it as ignored.
func HookHTTPStatus(h *model.GitHook) int {
	if h != nil && h.Action != model.HookActionIgnored {
		return http.StatusAccepted
	}
	return http.StatusOK
}

// Hook handles one delivery for the repository (tenant "" is the shared scope): verifies it,
// decides what to do, records the decision in the hook half of the record and, when there is
// something to do, persists a job for it. A job is claimed and run by one replica at a time
// (Run); a delivery the provider sends twice is one job. The returned record is the decision
// (with the job id); the outcome follows in the status once the job ran.
func (s *Service) Hook(ctx context.Context, tenant, name string, hdr http.Header, body []byte) (*model.GitHook, error) {
	it, err := s.Repos.Store.GetItem(ctx, model.KindGitRepository, tenant, name, 0)
	if err != nil {
		return nil, err
	}
	sp, err := gitrepo.Decode(it)
	if err != nil {
		return nil, fmt.Errorf("%s: stored spec: %w", name, err)
	}
	if sp.WebhookSecret == "" {
		return nil, fmt.Errorf("%w: %w", res.ErrNotFound, ErrNoWebhook)
	}
	if s.Secrets == nil {
		return nil, fmt.Errorf("%w: webhook_secret %q: no secrets provider is configured", ErrCredential, sp.WebhookSecret)
	}
	secret, err := s.Secrets.Get(ctx, it.Tenant, sp.WebhookSecret)
	if err != nil {
		return nil, fmt.Errorf("%w: webhook_secret %q is not available to tenant %q", ErrCredential, sp.WebhookSecret, it.Tenant)
	}
	d, err := ParseDelivery(hdr, body)
	if err != nil {
		if errors.Is(err, ErrUnknownProvider) {
			return nil, fmt.Errorf("%w: %v", res.ErrInvalid, err)
		}
		// Not yet verified: a parse error says nothing about the sender. Verify first.
		if verr := Verify(d.Provider, hdr, body, secret); verr != nil {
			return nil, verr
		}
		return nil, fmt.Errorf("%w: %v", res.ErrInvalid, err)
	}
	if err := Verify(d.Provider, hdr, body, secret); err != nil {
		return nil, err
	}
	h := &model.GitHook{Provider: d.Provider, Event: d.Event, Ref: d.Ref, Commit: d.After, Delivery: d.ID, At: s.now(), Action: model.HookActionIgnored}
	if d.PR != nil {
		h.Number, h.Commit = d.PR.Number, d.PR.HeadSHA
	}
	switch {
	case !SameRepository(sp.URL, d.RepoURLs):
		h.Reason = "the delivery names another repository than the registered one"
	case d.Event == EventPush && d.After == "":
		h.Reason = "the ref was deleted"
	case d.Event == EventPush && d.Ref != "refs/heads/"+sp.Ref && d.Ref != "refs/tags/"+sp.Ref && d.Ref != sp.Ref:
		h.Reason = "a push to another ref than " + sp.Ref
	case d.Event == EventPush:
		h.Action = model.HookActionSync
	case d.PR != nil && !shaRe.MatchString(d.PR.HeadSHA):
		h.Reason = "the pull request names no head commit"
	case d.PR != nil && !planActions[d.Provider][d.PR.Action]:
		h.Reason = "pull request action " + d.PR.Action + " needs no plan"
	case d.PR != nil:
		h.Action = model.HookActionPlan
	default:
		h.Reason = "event " + d.Event + " is not one the platform acts on"
	}
	if h.Action == model.HookActionIgnored {
		h.Outcome = model.HookIgnored
		if err := s.Store.RecordGitHook(ctx, it.Tenant, it.Name, *h); err != nil {
			return nil, err
		}
		s.emit(ctx, it, "git.hook", h)
		return h, nil
	}
	// The job: the delivery reduced, keyed by provider and delivery id (a redelivery finds it).
	payload, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	key := d.Provider + ":" + d.Event + ":" + d.ID
	if d.ID == "" {
		key = fmt.Sprintf("%s:%s:%s:%d:%s", d.Provider, d.Event, h.Commit, h.Number, h.At.UTC().Format(time.RFC3339Nano))
	}
	job := &model.GitJob{ID: newJobID(), Tenant: it.Tenant, Name: it.Name, Action: h.Action, Delivery: key, Payload: payload}
	jobs := s.jobs()
	if jobs == nil {
		return nil, errors.New("webhooks need a job store")
	}
	if err := jobs.EnqueueGitJob(ctx, job); err != nil {
		if !errors.Is(err, store.ErrConflict) {
			return nil, err
		}
		existing, gerr := jobs.GetGitJobByDelivery(ctx, it.Tenant, it.Name, key)
		if gerr != nil {
			return nil, err
		}
		return s.redelivered(ctx, it, h, existing)
	}
	h.Job = job.ID
	if err := s.Store.RecordGitHook(ctx, it.Tenant, it.Name, *h); err != nil {
		return nil, err
	}
	s.emit(ctx, it, "git.hook", h)
	return s.inline(ctx, it, h)
}

// redelivered answers a delivery whose job exists. A job that ran reports how it went, and the
// record keeps the summary it has (an acceptance is never written over an outcome, an older
// job's over a newer one's); a job that gave up (failed), or waits for its next attempt after
// an error, runs again now with its attempts reset, so a redelivery is the way to run a
// delivery the platform could not handle at the time; a job due or running is just named.
func (s *Service) redelivered(ctx context.Context, it *model.CatalogItem, h *model.GitHook, job *model.GitJob) (*model.GitHook, error) {
	h.Job = job.ID
	switch {
	case job.Status == model.GitJobDone:
		h.Outcome, h.Error, h.Reason = job.Outcome, job.Error, "a redelivery: the job already ran"
		s.emit(ctx, it, "git.hook", h)
		return h, nil
	case job.Status == model.GitJobFailed, job.Status == model.GitJobPending && job.LeaseUntil != nil && job.LeaseUntil.After(s.now()):
		if err := s.jobs().RequeueGitJob(ctx, job.ID); err != nil && !errors.Is(err, store.ErrConflict) {
			return nil, err
		}
		h.Reason = "a redelivery: the job had given up (" + job.Error + ") and runs again"
		if job.Status == model.GitJobPending {
			h.Reason = "a redelivery: the job waited for its next attempt (" + job.Error + ") and runs now"
		}
		if err := s.Store.RecordGitHook(ctx, it.Tenant, it.Name, *h); err != nil {
			return nil, err
		}
	default:
		h.Reason = "a redelivery: the same job, " + job.Status
	}
	s.emit(ctx, it, "git.hook", h)
	return s.inline(ctx, it, h)
}

// inline runs the waiting jobs in the request when Inline is set (tests) and returns the
// hook as recorded afterwards.
func (s *Service) inline(ctx context.Context, it *model.CatalogItem, h *model.GitHook) (*model.GitHook, error) {
	if !s.Inline {
		return h, nil
	}
	for {
		if ran, _ := s.RunOnce(ctx); !ran {
			break
		}
	}
	if g, err := s.Store.GetGitSync(ctx, it.Tenant, it.Name); err == nil && g.Hook != nil && g.Hook.Job == h.Job {
		s.fillHook(ctx, g)
		return g.Hook, nil
	}
	// The record kept another job's summary: this job's outcome comes from the job itself.
	if j, err := s.jobs().GetGitJob(ctx, h.Job); err == nil && (j.Status == model.GitJobDone || j.Status == model.GitJobFailed) {
		h.Outcome, h.Error = j.Outcome, j.Error
	}
	return h, nil
}

// Run claims and runs webhook jobs until ctx ends: the worker every replica runs. A job whose
// replica died is picked up once its lease lapsed.
func (s *Service) Run(ctx context.Context) {
	if s.jobs() == nil {
		return
	}
	for {
		ran, err := s.RunOnce(ctx)
		if err != nil && s.Log != nil && ctx.Err() == nil {
			s.Log.Error("git jobs", "err", err)
		}
		if ran {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.poll()):
		}
	}
}

// RunOnce claims one waiting job and runs it to its outcome; false when none was waiting.
func (s *Service) RunOnce(ctx context.Context) (bool, error) {
	job, err := s.jobs().ClaimGitJob(ctx, s.owner(), s.now(), s.lease())
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s.runJob(ctx, job)
	return true, nil
}

// MaxAttempts bounds how often a job runs: after a replica lost it mid-way (the lease ran
// out) or after an error (the repository or the provider's API unreachable), it runs again,
// up to this many attempts in all; then it fails, and a redelivery queues it anew.
const MaxAttempts = 5

// finishTimeout bounds the writes that end a job (its outcome, the hook record): they get a
// context of their own, made when the work is over, so a job whose lease ran out, or whose
// work took longer than this, still ends.
const finishTimeout = 30 * time.Second

// finishContext is the context for the writes that end a job: bounded, and independent of
// the work's, which may have ended.
func (s *Service) finishContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
}

func (s *Service) runJob(ctx context.Context, job *model.GitJob) {
	work, cancel := context.WithTimeout(ctx, s.lease())
	defer cancel()
	fail := func(msg string) {
		fin, cancel := s.finishContext(ctx)
		defer cancel()
		if err := s.jobs().FinishGitJob(fin, job.ID, s.owner(), job.Attempts, model.GitJobFailed, model.GitSyncError, msg); err != nil && s.Log != nil {
			s.Log.Warn("git job: finish", "job", job.ID, "err", err)
		}
	}
	var d Delivery
	if err := json.Unmarshal(job.Payload, &d); err != nil {
		fail("payload: " + err.Error())
		return
	}
	it, err := s.Repos.Store.GetItem(work, model.KindGitRepository, job.Tenant, job.Name, 0)
	if err != nil {
		fail("repository: " + err.Error())
		return
	}
	sp, err := gitrepo.Decode(it)
	if err != nil {
		fail("spec: " + err.Error())
		return
	}
	// The documents are applied with the repository's authority: the tenant's for a tenant's
	// repository, the admin's for a shared one. The subject names the provider.
	scope := plan.Scope{Tenant: it.Tenant, Admin: it.Tenant == "", Subject: "webhook:" + d.Provider}
	done := model.GitHook{Provider: d.Provider, Event: d.Event, Ref: d.Ref, Commit: d.After, Delivery: d.ID, Job: job.ID, Attempt: job.Attempts, Action: job.Action, At: s.now()}
	if d.PR != nil {
		done.Number, done.Commit = d.PR.Number, d.PR.HeadSHA
	}
	if job.Attempts > MaxAttempts {
		// Claimed once more after its last attempt died unfinished: nothing runs again.
		done.Outcome = model.GitSyncError
		done.Error = fmt.Sprintf("gave up after %d attempts; the last one did not finish", MaxAttempts)
		s.conclude(ctx, it, job, &done, model.GitJobFailed, time.Time{})
		return
	}
	var outcome string
	var runErr error
	switch job.Action {
	case model.HookActionSync:
		outcome, done.Commit, done.Reason, runErr = s.syncHead(work, it, sp, scope, d.After)
	case model.HookActionPlan:
		outcome, done.Reason, runErr = s.preview(work, it, sp, scope, *d.PR)
	default:
		outcome, runErr = model.GitSyncError, fmt.Errorf("unknown action %q", job.Action)
	}
	done.Outcome = outcome
	if runErr != nil {
		done.Error = runErr.Error()
	}
	// Unfinished work is retried: an error (the repository or the provider unreachable, a
	// credential not available) and a stopped apply (the store went away mid-way, a conflict)
	// alike, the latter continuing the same applies under the same keys. An invalid bundle is
	// an outcome, not unfinished work.
	unfinished := runErr != nil && (outcome == model.GitSyncError || outcome == model.GitSyncStopped)
	switch {
	case work.Err() != nil && runErr != nil && job.Attempts < MaxAttempts:
		// Cut short (the lease ran out, the process is stopping): the job stays running under
		// its lease, so another replica (or this one, later) takes it over.
		return
	case work.Err() != nil && runErr != nil:
		done.Error = fmt.Sprintf("attempt %d of %d did not finish within its lease: %v", job.Attempts, MaxAttempts, runErr)
		s.conclude(ctx, it, job, &done, model.GitJobFailed, time.Time{})
	case unfinished && job.Attempts < MaxAttempts:
		at := s.now().Add(s.backoff(job.Attempts))
		done.Reason = fmt.Sprintf("attempt %d of %d ended with %s; the job runs again at %s", job.Attempts, MaxAttempts, outcome, at.UTC().Format(time.RFC3339))
		s.conclude(ctx, it, job, &done, model.GitJobPending, at)
	case unfinished:
		done.Error = fmt.Sprintf("gave up after %d attempts: %v", MaxAttempts, runErr)
		s.conclude(ctx, it, job, &done, model.GitJobFailed, time.Time{})
	default:
		s.conclude(ctx, it, job, &done, model.GitJobDone, time.Time{})
	}
}

// conclude moves the job on (done or failed, or pending again at retryAt) and records how the
// attempt went in the hook half of the record, under a context of its own. The job first: it
// checks owner and attempt, so a late attempt another replica took over writes nothing, not
// even the record. The record then, only while it still carries this job and no later attempt
// of it has written: a delivery accepted meanwhile, or a later attempt's outcome, keeps its
// summary (the condition is the store's, in one statement), and a job that ended without
// reaching the record still shows its outcome (Status completes the hook from the job).
func (s *Service) conclude(ctx context.Context, it *model.CatalogItem, job *model.GitJob, done *model.GitHook, status string, retryAt time.Time) {
	fin, cancel := s.finishContext(ctx)
	defer cancel()
	if err := s.move(fin, job, status, done, retryAt); err != nil {
		if s.Log != nil {
			s.Log.Warn("git job: finish", "job", job.ID, "status", status, "err", err)
		}
		if errors.Is(err, store.ErrConflict) {
			return // the holder's outcome counts
		}
	}
	if _, err := s.Store.RecordGitHookIf(fin, it.Tenant, it.Name, *done, job.ID, job.Attempts); err != nil && s.Log != nil {
		s.Log.Error("git hook: record outcome", "tenant", it.Tenant, "repository", it.Name, "err", err)
	}
	s.emit(fin, it, "git.hook", done)
}

func (s *Service) move(ctx context.Context, job *model.GitJob, status string, done *model.GitHook, retryAt time.Time) error {
	if status == model.GitJobPending {
		return s.jobs().RetryGitJob(ctx, job.ID, s.owner(), job.Attempts, retryAt, done.Error)
	}
	return s.jobs().FinishGitJob(ctx, job.ID, s.owner(), job.Attempts, status, done.Outcome, done.Error)
}

// backoff is the wait before the attempt after the given one.
func (s *Service) backoff(attempt int) time.Duration {
	base := s.Retry
	if base <= 0 {
		base = 30 * time.Second
	}
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 10 {
		attempt = 10
	}
	return base << (attempt - 1)
}

// syncHead syncs the ref's current head for a push delivery, under the tenant's lock: the ref
// as it is now, not as the delivery saw it. A delivery that arrives after a later push (or
// after a sync of a newer head) is superseded: the newest state is already what the ref holds,
// and an older commit is never written over it. Returns the outcome, the commit synced and a
// note for the hook record.
func (s *Service) syncHead(ctx context.Context, it *model.CatalogItem, sp gitrepo.Spec, scope plan.Scope, after string) (outcome, commit, note string, err error) {
	err = s.locked(ctx, it.Tenant, func(ctx context.Context) error {
		r, rerr := s.remote(ctx, it, sp)
		if rerr != nil {
			outcome, commit = model.GitSyncError, after
			return rerr
		}
		head, rerr := s.Fetch.Resolve(ctx, r)
		if rerr != nil {
			outcome, commit = model.GitSyncError, after
			return fmt.Errorf("%w: %v", ErrRead, rerr)
		}
		commit = head
		if head != after {
			note = fmt.Sprintf("the delivery named %s; the ref's head is %s and that is what was synced", after, head)
		}
		if g, _ := s.Store.GetGitSync(ctx, it.Tenant, it.Name); g != nil && g.Sync != nil && g.Sync.Commit == head && g.Sync.Status == model.GitSyncDone && head != after {
			// The newer head is already applied: this delivery has nothing left to do.
			outcome = model.HookSuperseded
			return nil
		}
		g, serr := s.sync(ctx, it, sp, scope, head)
		switch {
		case g != nil && g.Sync != nil:
			outcome = g.Sync.Status
		default:
			outcome = model.GitSyncError
		}
		return serr
	})
	return outcome, commit, note, err
}

// jobs is the job store: Jobs when wired, else the status store when it keeps jobs too (every
// store does; a Service built from a store alone works).
func (s *Service) jobs() store.GitJobs {
	if s.Jobs != nil {
		return s.Jobs
	}
	j, _ := s.Store.(store.GitJobs)
	return j
}

func (s *Service) owner() string {
	if s.Replica != "" {
		return s.Replica
	}
	return "replica"
}

func (s *Service) lease() time.Duration {
	if s.Lease > 0 {
		return s.Lease
	}
	return 10 * time.Minute
}

func (s *Service) poll() time.Duration {
	if s.Lease > 0 && s.Lease < 20*time.Second {
		return s.Lease / 10
	}
	return 2 * time.Second
}

func newJobID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "gitjob_" + hex.EncodeToString(b[:])
}

// planActions are the pull request actions that get a plan: a new or updated head.
var planActions = map[string]map[string]bool{
	ProviderGitHub: {"opened": true, "synchronize": true, "reopened": true, "ready_for_review": true},
	ProviderGitLab: {"open": true, "update": true, "reopen": true},
}

// emit publishes an event about the repository when an emitter is wired: git.hook with the
// hook record, git.sync with the sync result, git.plan with the plan outcome.
func (s *Service) emit(ctx context.Context, it *model.CatalogItem, typ string, data any) {
	if s.Emit == nil {
		return
	}
	b, _ := json.Marshal(data)
	s.Emit(ctx, model.Event{SandboxID: "git:" + it.Name, Tenant: it.Tenant, Type: typ, Data: string(b), At: s.now()})
}

// preview plans the bundles at a pull request's head with the repository's authority and
// reports the result on the pull request: one comment (updated per push, found by the marker)
// and one commit status, each posted whether or not the other could be. It runs under the
// tenant's lock, like a sync, so two jobs for one pull request never publish at once, and it
// publishes only for the request's current head: a delivery whose head the request has moved
// past is superseded, so an older plan never lands over a newer one, whatever order the
// deliveries ran in. The files are planned as a sync applies them (parseBundles), one section
// per file. Nothing is written to the catalogue. Returns the outcome and a note for the record.
func (s *Service) preview(ctx context.Context, it *model.CatalogItem, sp gitrepo.Spec, scope plan.Scope, pr PullRequest) (outcome, note string, err error) {
	if s.Reporter == nil {
		return model.GitSyncError, "", errors.New("no pull request reporter is configured")
	}
	outcome = model.GitSyncError
	err = s.locked(ctx, it.Tenant, func(ctx context.Context) error {
		r, err := s.remote(ctx, it, sp)
		if err != nil {
			return err
		}
		target, err := TargetOf(r, pr)
		if err != nil {
			return err
		}
		r.Ref = pr.HeadRef
		var body bytes.Buffer
		changes := 0
		files, ferr := s.Fetch.Files(ctx, r, pr.HeadSHA, sp.Paths)
		// The request as it is now, read after the files (the closest to publishing): a head
		// the request has moved past (a push, a force push that took the commit off the ref)
		// is superseded, and nothing of it is published.
		head, err := s.Fetch.Resolve(ctx, r)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrRead, err)
		}
		if head != pr.HeadSHA {
			outcome = model.HookSuperseded
			note = fmt.Sprintf("the pull request's head is now %s; the plan of %s is not published", head, pr.HeadSHA)
			return nil
		}
		if ferr != nil {
			err = fmt.Errorf("%w: %v", ErrRead, ferr)
			render.Failure(&body, "Plan", "", err)
			outcome = model.GitSyncError
		} else {
			outcome, changes = s.planFiles(ctx, &body, files, scope)
		}
		s.emit(ctx, it, "git.plan", map[string]any{"number": pr.Number, "commit": pr.HeadSHA, "outcome": outcome, "changes": changes})
		state, description := StatusSuccess, fmt.Sprintf("plan: %d to apply on merge", changes)
		switch outcome {
		case model.GitSyncInvalid:
			state, description = StatusFailure, "plan: a bundle is not valid; see the comment"
		case model.GitSyncError:
			state, description = StatusError, "plan: the repository could not be read; see the comment"
		}
		var report []error
		if cerr := s.Reporter.UpsertComment(ctx, target, body.String()); cerr != nil {
			report = append(report, fmt.Errorf("comment on %s #%d: %w", target.Repo, pr.Number, cerr))
		}
		if serr := s.Reporter.SetStatus(ctx, target, state, description); serr != nil {
			report = append(report, fmt.Errorf("status on %s@%s: %w", target.Repo, pr.HeadSHA, serr))
		}
		if len(report) > 0 {
			outcome = model.GitSyncError
			return errors.Join(append(report, err)...)
		}
		return err
	})
	return outcome, note, err
}

// planFiles plans the files as a sync applies them: in path order, each over the state the
// files before it leave behind (plan.Deps.Virtual), stopping at the first that is not valid
// (a sync stops there too), with one section per file. Returns the outcome and the creates and
// updates a merge would apply.
func (s *Service) planFiles(ctx context.Context, body *bytes.Buffer, files map[string][]byte, scope plan.Scope) (string, int) {
	bundles, path, perr := parseBundles(files, scope.Tenant)
	if perr != nil {
		render.Failure(body, "Plan", path, perr)
		return model.GitSyncInvalid, 0
	}
	changes := 0
	var virtual []*model.CatalogItem
	for i, bf := range bundles {
		pl, items, err := s.Applier.Planner.Virtual(virtual).PlanItems(ctx, bf.Docs, scope)
		if err != nil {
			render.Failure(body, "Plan", bf.Path, err)
			return model.GitSyncError, changes
		}
		render.Plan(body, *pl, bf.Path)
		body.WriteString("\n")
		if !pl.Valid {
			if rest := len(bundles) - i - 1; rest > 0 {
				fmt.Fprintf(body, "_%d more file(s) not planned: a sync stops at the first bundle that is not valid._\n\n", rest)
			}
			return model.GitSyncInvalid, changes
		}
		changes += pl.Summary.Create + pl.Summary.Update
		for j, c := range pl.Changes {
			if j < len(items) && items[j] != nil {
				written := *items[j]
				written.Revision = c.NextRevision
				virtual = append(virtual, &written)
			}
		}
	}
	return model.GitSyncDone, changes
}
