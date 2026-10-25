package gitsync

import (
	"bytes"
	"context"
	"crypto/hmac"
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
	"sync"
	"time"

	"agent-sandbox/internal/gitrepo"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/render"
	res "agent-sandbox/internal/resource"
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
// decides what to do, records the decision in the hook half of the record and runs the action
// (in the background unless Inline is set), recording the outcome and emitting an event when
// it is done. The returned record is the decision; the outcome follows in the status.
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
	if err := s.Store.RecordGitHook(ctx, it.Tenant, it.Name, *h); err != nil {
		return nil, err
	}
	// The documents are applied with the repository's authority: the tenant's for a tenant's
	// repository, the admin's for a shared one. The subject names the provider.
	scope := plan.Scope{Tenant: it.Tenant, Admin: it.Tenant == "", Subject: "webhook:" + d.Provider}
	run := func(ctx context.Context) {
		s.repoLock(it.Tenant, it.Name).Lock()
		defer s.repoLock(it.Tenant, it.Name).Unlock()
		done := *h
		switch h.Action {
		case model.HookActionSync:
			g, err := s.Sync(ctx, scope, it.Name, d.After)
			switch {
			case g != nil && g.Sync != nil:
				done.Outcome = g.Sync.Status
				done.Error = g.Sync.Error
			default:
				done.Outcome = model.GitSyncError
				if err != nil {
					done.Error = err.Error()
				}
			}
		case model.HookActionPlan:
			outcome, err := s.preview(ctx, it, sp, scope, *d.PR)
			done.Outcome = outcome
			if err != nil {
				done.Error = err.Error()
			}
		}
		done.Reason = ""
		if rerr := s.Store.RecordGitHook(ctx, it.Tenant, it.Name, done); rerr != nil && s.Log != nil {
			s.Log.Error("git hook: record outcome", "tenant", it.Tenant, "repository", it.Name, "err", rerr)
		}
		s.emit(ctx, it, "git.hook", &done)
	}
	if s.Inline {
		run(ctx)
		if g, err := s.Store.GetGitSync(ctx, it.Tenant, it.Name); err == nil && g.Hook != nil {
			return g.Hook, nil
		}
		return h, nil
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), s.hookTimeout())
		defer cancel()
		run(ctx)
	}()
	return h, nil
}

// planActions are the pull request actions that get a plan: a new or updated head.
var planActions = map[string]map[string]bool{
	ProviderGitHub: {"opened": true, "synchronize": true, "reopened": true, "ready_for_review": true},
	ProviderGitLab: {"open": true, "update": true, "reopen": true},
}

func (s *Service) hookTimeout() time.Duration {
	if s.HookTimeout > 0 {
		return s.HookTimeout
	}
	return 10 * time.Minute
}

func (s *Service) repoLock(tenant, name string) *sync.Mutex {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	if s.locks == nil {
		s.locks = map[string]*sync.Mutex{}
	}
	key := tenant + "|" + name
	if s.locks[key] == nil {
		s.locks[key] = &sync.Mutex{}
	}
	return s.locks[key]
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
// and one commit status. Nothing is written to the catalogue.
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
		paths := make([]string, 0, len(files))
		for p := range files {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			docs, perr := res.ParseYAMLAll(files[p])
			if perr != nil {
				render.Failure(&body, "Plan", p, perr)
				outcome = model.GitSyncInvalid
				continue
			}
			pl, perr := s.Applier.Planner.Plan(ctx, docs, scope)
			if perr != nil {
				render.Failure(&body, "Plan", p, perr)
				outcome = model.GitSyncError
				continue
			}
			render.Plan(&body, *pl, p)
			body.WriteString("\n")
			changes += pl.Summary.Create + pl.Summary.Update
			if !pl.Valid && outcome == model.GitSyncDone {
				outcome = model.GitSyncInvalid
			}
		}
	}
	s.emit(ctx, it, "git.plan", map[string]any{"number": pr.Number, "commit": pr.HeadSHA, "outcome": outcome, "changes": changes})
	if cerr := s.Reporter.UpsertComment(ctx, target, body.String()); cerr != nil {
		return model.GitSyncError, fmt.Errorf("comment on %s #%d: %w", target.Repo, pr.Number, cerr)
	}
	state, description := StatusSuccess, fmt.Sprintf("plan: %d to apply on merge", changes)
	switch outcome {
	case model.GitSyncInvalid:
		state, description = StatusFailure, "plan: a bundle is not valid; see the comment"
	case model.GitSyncError:
		state, description = StatusError, "plan: the repository could not be read; see the comment"
	}
	if serr := s.Reporter.SetStatus(ctx, target, state, description); serr != nil {
		return model.GitSyncError, fmt.Errorf("status on %s@%s: %w", target.Repo, pr.HeadSHA, serr)
	}
	if err != nil {
		return outcome, err
	}
	return outcome, nil
}
