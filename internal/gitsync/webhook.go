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
	"sort"
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
		job = existing
		h.Reason = "a redelivery: the same job"
	}
	h.Job = job.ID
	if err := s.Store.RecordGitHook(ctx, it.Tenant, it.Name, *h); err != nil {
		return nil, err
	}
	s.emit(ctx, it, "git.hook", h)
	if s.Inline {
		for {
			if ran, _ := s.RunOnce(ctx); !ran {
				break
			}
		}
		if g, err := s.Store.GetGitSync(ctx, it.Tenant, it.Name); err == nil && g.Hook != nil {
			return g.Hook, nil
		}
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

// MaxAttempts bounds how often a job is retried after a replica lost it mid-way.
const MaxAttempts = 5

func (s *Service) runJob(ctx context.Context, job *model.GitJob) {
	ctx, cancel := context.WithTimeout(ctx, s.lease())
	defer cancel()
	var d Delivery
	if err := json.Unmarshal(job.Payload, &d); err != nil {
		_ = s.jobs().FinishGitJob(ctx, job.ID, s.owner(), model.GitJobFailed, model.GitSyncError, "payload: "+err.Error())
		return
	}
	it, err := s.Repos.Store.GetItem(ctx, model.KindGitRepository, job.Tenant, job.Name, 0)
	if err != nil {
		_ = s.jobs().FinishGitJob(ctx, job.ID, s.owner(), model.GitJobFailed, model.GitSyncError, "repository: "+err.Error())
		return
	}
	sp, err := gitrepo.Decode(it)
	if err != nil {
		_ = s.jobs().FinishGitJob(ctx, job.ID, s.owner(), model.GitJobFailed, model.GitSyncError, "spec: "+err.Error())
		return
	}
	// The documents are applied with the repository's authority: the tenant's for a tenant's
	// repository, the admin's for a shared one. The subject names the provider.
	scope := plan.Scope{Tenant: it.Tenant, Admin: it.Tenant == "", Subject: "webhook:" + d.Provider}
	done := model.GitHook{Provider: d.Provider, Event: d.Event, Ref: d.Ref, Commit: d.After, Delivery: d.ID, Job: job.ID, Action: job.Action, At: s.now()}
	if d.PR != nil {
		done.Number, done.Commit = d.PR.Number, d.PR.HeadSHA
	}
	var outcome string
	var runErr error
	switch job.Action {
	case model.HookActionSync:
		outcome, done.Commit, done.Reason, runErr = s.syncHead(ctx, it, sp, scope, d.After)
	case model.HookActionPlan:
		outcome, runErr = s.preview(ctx, it, sp, scope, *d.PR)
	default:
		outcome, runErr = model.GitSyncError, fmt.Errorf("unknown action %q", job.Action)
	}
	done.Outcome = outcome
	if runErr != nil {
		done.Error = runErr.Error()
	}
	status := model.GitJobDone
	if ctx.Err() != nil && job.Attempts < MaxAttempts {
		// Cut short (the lease ran out, the process is stopping): leave the job running under
		// its lease, so another replica (or this one, later) takes it over.
		return
	}
	if outcome == model.GitSyncError && runErr != nil {
		status = model.GitJobFailed
	}
	if err := s.jobs().FinishGitJob(ctx, job.ID, s.owner(), status, outcome, done.Error); err != nil {
		if s.Log != nil {
			s.Log.Warn("git job: finish", "job", job.ID, "err", err)
		}
		if errors.Is(err, store.ErrConflict) {
			return // another replica took the job over: its outcome counts
		}
	}
	if err := s.Store.RecordGitHook(ctx, it.Tenant, it.Name, done); err != nil && s.Log != nil {
		s.Log.Error("git hook: record outcome", "tenant", it.Tenant, "repository", it.Name, "err", err)
	}
	s.emit(ctx, it, "git.hook", &done)
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
// and one commit status, each posted whether or not the other could be. The files are planned
// as one bundle in path order, as a sync applies them in sequence, so a document in a later
// file may name what an earlier file introduces; the comment still shows one section per file.
// Nothing is written to the catalogue.
func (s *Service) preview(ctx context.Context, it *model.CatalogItem, sp gitrepo.Spec, scope plan.Scope, pr PullRequest) (string, error) {
	if s.Reporter == nil {
		return model.GitSyncError, errors.New("no pull request reporter is configured")
	}
	r, err := s.remote(ctx, it, sp)
	if err != nil {
		return model.GitSyncError, err
	}
	target, err := TargetOf(r, pr)
	if err != nil {
		return model.GitSyncError, err
	}
	var body bytes.Buffer
	outcome := model.GitSyncDone
	changes := 0
	r.Ref = pr.HeadRef
	files, err := s.Fetch.Files(ctx, r, pr.HeadSHA, sp.Paths)
	if err != nil {
		err = fmt.Errorf("%w: %v", ErrRead, err)
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
		return model.GitSyncError, errors.Join(append(report, err)...)
	}
	return outcome, err
}

// planFiles plans the files as one bundle and renders one section per file (bundle-level
// errors, such as two files describing one item, go with the first section).
func (s *Service) planFiles(ctx context.Context, body *bytes.Buffer, files map[string][]byte, scope plan.Scope) (string, int) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	outcome := model.GitSyncDone
	var all []*res.Document
	owner := map[string]string{} // kind|tenant|name → file
	var parsed []string
	for _, p := range paths {
		docs, perr := res.ParseYAMLAll(files[p])
		if perr != nil {
			render.Failure(body, "Plan", p, perr)
			outcome = model.GitSyncInvalid
			continue
		}
		for _, d := range docs {
			tenant := scope.Tenant
			if d.Tenant != nil {
				tenant = *d.Tenant
			}
			k := d.Kind + "|" + tenant + "|" + d.Name
			if _, dup := owner[k]; !dup {
				owner[k] = p
			}
		}
		all = append(all, docs...)
		parsed = append(parsed, p)
	}
	if len(all) == 0 {
		return outcome, 0
	}
	joint, err := s.Applier.Planner.Plan(ctx, all, scope)
	if err != nil {
		render.Failure(body, "Plan", "", err)
		return model.GitSyncError, 0
	}
	if !joint.Valid {
		outcome = model.GitSyncInvalid
	}
	for i, p := range parsed {
		part := plan.Plan{Valid: true, Bundle: joint.Bundle, Fingerprint: joint.Fingerprint}
		if i == 0 {
			part.Errors = joint.Errors
			part.Valid = len(joint.Errors) == 0
		}
		for _, c := range joint.Changes {
			if owner[c.Kind+"|"+c.Tenant+"|"+c.Name] != p {
				continue
			}
			part.Changes = append(part.Changes, c)
			switch {
			case len(c.Errors) > 0 || c.Action == plan.ActionInvalid:
				part.Summary.Invalid++
				part.Valid = false
			case c.Action == plan.ActionCreate:
				part.Summary.Create++
			case c.Action == plan.ActionUpdate:
				part.Summary.Update++
			default:
				part.Summary.Noop++
			}
		}
		render.Plan(body, part, p)
		body.WriteString("\n")
	}
	return outcome, joint.Summary.Create + joint.Summary.Update
}
