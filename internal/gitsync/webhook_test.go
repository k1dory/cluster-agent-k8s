package gitsync

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"agent-sandbox/internal/gitsync/gittest"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/render"
	"agent-sandbox/internal/secrets"
)

func signGitHub(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func githubHeaders(event, secret string, body []byte) http.Header {
	h := http.Header{}
	h.Set("X-GitHub-Event", event)
	h.Set("X-GitHub-Delivery", "d-1")
	h.Set("X-Hub-Signature-256", signGitHub(secret, body))
	return h
}

func gitlabHeaders(event, secret string) http.Header {
	h := http.Header{}
	h.Set("X-Gitlab-Event", event)
	h.Set("X-Gitlab-Event-UUID", "u-1")
	h.Set("X-Gitlab-Token", secret)
	return h
}

func TestParseDeliveryAndVerify(t *testing.T) {
	push := []byte(`{"ref":"refs/heads/main","after":"` + sha1 + `","repository":{"clone_url":"https://git.example.com/acme/config.git","html_url":"https://git.example.com/acme/config"}}`)
	d, err := ParseDelivery(githubHeaders("push", "s", push), push)
	if err != nil || d.Provider != ProviderGitHub || d.Event != EventPush || d.Ref != "refs/heads/main" || d.After != sha1 || d.ID != "d-1" {
		t.Fatalf("github push: %v %+v", err, d)
	}
	deleted := []byte(`{"ref":"refs/heads/main","after":"0000000000000000000000000000000000000000","deleted":true,"repository":{"clone_url":"https://git.example.com/acme/config.git"}}`)
	if d, _ := ParseDelivery(githubHeaders("push", "s", deleted), deleted); d.After != "" {
		t.Fatalf("a deleted ref has no head: %+v", d)
	}
	pr := []byte(`{"action":"synchronize","number":7,"pull_request":{"number":7,"head":{"sha":"` + sha1 + `","ref":"feature"}},"repository":{"clone_url":"https://git.example.com/acme/config.git"}}`)
	d, err = ParseDelivery(githubHeaders("pull_request", "s", pr), pr)
	if err != nil || d.Event != EventPullRequest || d.PR == nil || d.PR.Number != 7 || d.PR.HeadSHA != sha1 || d.PR.HeadRef != "refs/pull/7/head" || d.PR.Action != "synchronize" {
		t.Fatalf("github pull_request: %v %+v", err, d)
	}
	if d, err := ParseDelivery(githubHeaders("issues", "s", []byte(`{}`)), []byte(`{}`)); err != nil || d.Event != "issues" {
		t.Fatalf("an event the platform ignores still parses: %v %+v", err, d)
	}
	glPush := []byte(`{"object_kind":"push","ref":"refs/heads/main","after":"` + sha1 + `","project":{"web_url":"https://gitlab.example/acme/config","http_url":"https://gitlab.example/acme/config.git"}}`)
	d, err = ParseDelivery(gitlabHeaders("Push Hook", "s"), glPush)
	if err != nil || d.Provider != ProviderGitLab || d.Event != EventPush || d.After != sha1 || d.ID != "u-1" {
		t.Fatalf("gitlab push: %v %+v", err, d)
	}
	mr := []byte(`{"object_kind":"merge_request","object_attributes":{"iid":3,"action":"update","last_commit":{"id":"` + sha1 + `"}},"project":{"web_url":"https://gitlab.example/acme/config"}}`)
	d, err = ParseDelivery(gitlabHeaders("Merge Request Hook", "s"), mr)
	if err != nil || d.Event != EventMergeRequest || d.PR == nil || d.PR.Number != 3 || d.PR.HeadRef != "refs/merge-requests/3/head" || d.PR.Action != "update" {
		t.Fatalf("gitlab merge request: %v %+v", err, d)
	}
	if _, err := ParseDelivery(http.Header{}, push); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("no provider header: %v", err)
	}
	if _, err := ParseDelivery(githubHeaders("push", "s", []byte("{")), []byte("{")); err == nil {
		t.Fatal("garbage parsed")
	}

	// Signatures: the right secret passes, a wrong one, a missing header and an empty secret fail.
	if err := Verify(ProviderGitHub, githubHeaders("push", "s3cret", push), push, "s3cret"); err != nil {
		t.Fatalf("github signature: %v", err)
	}
	if err := Verify(ProviderGitHub, githubHeaders("push", "other", push), push, "s3cret"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong github secret: %v", err)
	}
	if err := Verify(ProviderGitHub, http.Header{}, push, "s3cret"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("unsigned github delivery: %v", err)
	}
	if err := Verify(ProviderGitLab, gitlabHeaders("Push Hook", "tok"), glPush, "tok"); err != nil {
		t.Fatalf("gitlab token: %v", err)
	}
	if err := Verify(ProviderGitLab, gitlabHeaders("Push Hook", "nope"), glPush, "tok"); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong gitlab token: %v", err)
	}
	if err := Verify(ProviderGitHub, githubHeaders("push", "", push), push, ""); !errors.Is(err, ErrNoWebhook) {
		t.Fatalf("empty secret must never verify: %v", err)
	}

	// Repository identity: host and path, .git and a slash aside; another repository is not it.
	if !SameRepository("https://git.example.com/acme/config.git", []string{"https://GIT.example.com/acme/config", "x"}) {
		t.Fatal("the same repository was not recognised")
	}
	if SameRepository("https://git.example.com/acme/config.git", []string{"https://git.example.com/acme/other.git", "https://evil.example/acme/config.git"}) {
		t.Fatal("another repository was taken for the registered one")
	}
	// Targets are derived from the registered URL, never from the delivery.
	tg, err := TargetOf(Remote{URL: "https://github.com/acme/config.git", Auth: "u:tok"}, PullRequest{Number: 7, HeadSHA: sha1, HeadRef: "refs/pull/7/head"})
	if err != nil || tg.Provider != ProviderGitHub || tg.APIBase != "https://api.github.com" || tg.Repo != "acme/config" || tg.Token != "tok" {
		t.Fatalf("github.com target: %v %+v", err, tg)
	}
	tg, err = TargetOf(Remote{URL: "https://ghe.example/acme/config", Auth: "tok"}, PullRequest{Number: 7, HeadRef: "refs/pull/7/head"})
	if err != nil || tg.APIBase != "https://ghe.example/api/v3" || tg.Token != "tok" {
		t.Fatalf("enterprise target: %v %+v", err, tg)
	}
	tg, err = TargetOf(Remote{URL: "https://gitlab.example/group/sub/config.git"}, PullRequest{Number: 3, HeadRef: "refs/merge-requests/3/head"})
	if err != nil || tg.Provider != ProviderGitLab || tg.APIBase != "https://gitlab.example/api/v4" || tg.Repo != "group/sub/config" {
		t.Fatalf("gitlab target: %v %+v", err, tg)
	}
	if _, err := TargetOf(Remote{URL: "https://gitlab.example/config"}, PullRequest{HeadRef: "refs/merge-requests/3/head"}); err == nil {
		t.Fatal("a URL without owner/name made a target")
	}
}

// fakeReporter records what the platform would post.
type fakeReporter struct {
	mu       sync.Mutex
	comments map[string][]string // target key → bodies in order
	statuses map[string][]string // target key → "state: description"
}

func (f *fakeReporter) key(t Target) string {
	return fmt.Sprintf("%s %s #%d", t.Provider, t.Repo, t.Number)
}

func (f *fakeReporter) UpsertComment(_ context.Context, t Target, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.comments == nil {
		f.comments = map[string][]string{}
	}
	f.comments[f.key(t)] = append(f.comments[f.key(t)], body)
	return nil
}

func (f *fakeReporter) SetStatus(_ context.Context, t Target, state, description string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statuses == nil {
		f.statuses = map[string][]string{}
	}
	f.statuses[f.key(t)] = append(f.statuses[f.key(t)], state+": "+description)
	return nil
}

// refFetcher serves several refs: the branch and pull request heads.
type refFetcher struct {
	auth  string
	heads map[string]string            // full or short ref → head
	files map[string]map[string][]byte // commit → files
	seen  []string
}

func (f *refFetcher) Resolve(_ context.Context, r Remote) (string, error) {
	if r.Auth != f.auth {
		return "", errors.New("the server refused the credential (HTTP 401)")
	}
	f.seen = append(f.seen, "resolve "+r.Ref)
	if h, ok := f.heads[r.Ref]; ok {
		return h, nil
	}
	return "", fmt.Errorf("%w: %s", ErrNoRef, r.Ref)
}

func (f *refFetcher) Files(_ context.Context, r Remote, commit string, patterns []string) (map[string][]byte, error) {
	if r.Auth != f.auth {
		return nil, errors.New("the server refused the credential (HTTP 401)")
	}
	f.seen = append(f.seen, "files "+r.Ref+"@"+commit)
	if h, ok := f.heads[r.Ref]; !ok || h != commit {
		return nil, fmt.Errorf("%w: %s", ErrNotOnRef, commit)
	}
	out := map[string][]byte{}
	for p, b := range f.files[commit] {
		if Matches(p, patterns) {
			out[p] = b
		}
	}
	if len(out) == 0 {
		return nil, ErrNoMatch
	}
	return out, nil
}

const sha2 = "2222222222222222222222222222222222222222"

func TestHookSyncsOnPushPlansOnPullRequestAndIgnoresTheRest(t *testing.T) {
	ctx := context.Background()
	env := "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"
	fetch := &refFetcher{auth: "tok", heads: map[string]string{"main": sha1, "refs/pull/7/head": sha2, "refs/merge-requests/3/head": sha2},
		files: map[string]map[string][]byte{sha1: {"bundles/a.yaml": []byte(env)}, sha2: {"bundles/a.yaml": []byte(env + "---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n")}}}
	s, st := newService(t, fetch)
	s.Secrets = secrets.Static{"acme/repo-token": "tok", "acme/hook-secret": "s3cret"}
	s.Repos.Secrets = s.Secrets
	rep := &fakeReporter{}
	s.Reporter, s.Inline = rep, true
	var events []model.Event
	s.Emit = func(_ context.Context, e model.Event) { events = append(events, e) }
	register(t, s, "acme", "config", "kind: GitRepository\nname: config\nspec: {url: https://git.example.com/acme/config.git, ref: main, paths: ['bundles/*.yaml'], credential: repo-token, webhook_secret: hook-secret}\n")

	// A pull request opened: the plan of its head goes to the request as a comment and a status;
	// nothing is written.
	pr := []byte(`{"action":"opened","number":7,"pull_request":{"number":7,"head":{"sha":"` + sha2 + `"}},"repository":{"clone_url":"https://git.example.com/acme/config.git"}}`)
	h, err := s.Hook(ctx, "acme", "config", githubHeaders("pull_request", "s3cret", pr), pr)
	if err != nil || h.Action != model.HookActionPlan || h.Outcome != model.GitSyncDone || h.Number != 7 || h.Commit != sha2 {
		t.Fatalf("pull request hook: %v %+v", err, h)
	}
	key := "github acme/config #7"
	if len(rep.comments[key]) != 1 || !strings.HasPrefix(rep.comments[key][0], render.Marker) || !strings.Contains(rep.comments[key][0], "2 to create") || !strings.Contains(rep.comments[key][0], "`bundles/a.yaml`") {
		t.Fatalf("plan comment: %q", rep.comments[key])
	}
	if len(rep.statuses[key]) != 1 || !strings.HasPrefix(rep.statuses[key][0], "success: plan: 2 to apply") {
		t.Fatalf("plan status: %q", rep.statuses[key])
	}
	if n := revs(t, st, model.KindEnvironment, "acme", "py"); n != 0 {
		t.Fatal("a plan wrote")
	}
	// A push to the followed ref: the head is synced with the repository's authority.
	push := []byte(`{"ref":"refs/heads/main","after":"` + sha1 + `","repository":{"clone_url":"https://git.example.com/acme/config.git"}}`)
	h, err = s.Hook(ctx, "acme", "config", githubHeaders("push", "s3cret", push), push)
	if err != nil || h.Action != model.HookActionSync || h.Outcome != model.GitSyncDone || h.Commit != sha1 {
		t.Fatalf("push hook: %v %+v", err, h)
	}
	g, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config")
	if g.Sync == nil || g.Sync.Commit != sha1 || g.Sync.Status != model.GitSyncDone || g.Hook == nil || g.Hook.Action != model.HookActionSync {
		t.Fatalf("status after the push: %+v", g)
	}
	a, err := st.GetApplyByKey(ctx, "acme", Key("config", sha1, "bundles/a.yaml"))
	if err != nil || a.Subject != "webhook:github" || a.Admin {
		t.Fatalf("the apply of a webhook sync: %v %+v", err, a)
	}
	// Events: git.hook per delivery, git.plan for the plan, git.sync for the sync.
	types := map[string]int{}
	for _, e := range events {
		types[e.Type]++
		if e.Tenant != "acme" || e.SandboxID != "git:config" {
			t.Fatalf("event scope: %+v", e)
		}
	}
	if types["git.hook"] != 2 || types["git.plan"] != 1 || types["git.sync"] != 1 {
		t.Fatalf("events: %v", types)
	}
	// Ignored deliveries: another branch, a deleted ref, a closed pull request, another
	// repository, an event the platform does not act on. Each is recorded and nothing runs.
	seen := len(fetch.seen)
	for name, tc := range map[string]struct {
		event string
		body  string
	}{
		"other_branch":     {"push", `{"ref":"refs/heads/feature","after":"` + sha2 + `","repository":{"clone_url":"https://git.example.com/acme/config.git"}}`},
		"deleted_ref":      {"push", `{"ref":"refs/heads/main","after":"0000000000000000000000000000000000000000","deleted":true,"repository":{"clone_url":"https://git.example.com/acme/config.git"}}`},
		"closed_pr":        {"pull_request", `{"action":"closed","number":7,"pull_request":{"number":7,"head":{"sha":"` + sha2 + `"}},"repository":{"clone_url":"https://git.example.com/acme/config.git"}}`},
		"other_repository": {"push", `{"ref":"refs/heads/main","after":"` + sha1 + `","repository":{"clone_url":"https://git.example.com/acme/other.git"}}`},
		"issue_comment":    {"issue_comment", `{"action":"created","repository":{"clone_url":"https://git.example.com/acme/config.git"}}`},
	} {
		body := []byte(tc.body)
		h, err := s.Hook(ctx, "acme", "config", githubHeaders(tc.event, "s3cret", body), body)
		if err != nil || h.Action != model.HookActionIgnored || h.Outcome != model.HookIgnored || h.Reason == "" {
			t.Errorf("%s: %v %+v", name, err, h)
		}
	}
	if len(fetch.seen) != seen {
		t.Fatalf("an ignored delivery reached Git: %v", fetch.seen[seen:])
	}
	// A wrong signature, an unsigned delivery: refused before anything, nothing recorded.
	before, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config")
	if _, err := s.Hook(ctx, "acme", "config", githubHeaders("push", "wrong", push), push); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong secret: %v", err)
	}
	unsigned := http.Header{}
	unsigned.Set("X-GitHub-Event", "push")
	if _, err := s.Hook(ctx, "acme", "config", unsigned, push); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("unsigned: %v", err)
	}
	after, _ := s.Status(ctx, plan.Scope{Tenant: "acme"}, "config")
	if after.Hook.Delivery != before.Hook.Delivery || after.Hook.At != before.Hook.At {
		t.Fatal("a refused delivery was recorded")
	}
	// A GitLab merge request on the same registration (the provider comes from the delivery):
	// the comment goes to the GitLab target derived from the registered URL.
	mr := []byte(`{"object_kind":"merge_request","object_attributes":{"iid":3,"action":"open","last_commit":{"id":"` + sha2 + `"}},"project":{"web_url":"https://git.example.com/acme/config","http_url":"https://git.example.com/acme/config.git"}}`)
	h, err = s.Hook(ctx, "acme", "config", gitlabHeaders("Merge Request Hook", "s3cret"), mr)
	if err != nil || h.Action != model.HookActionPlan || h.Outcome != model.GitSyncDone || h.Provider != ProviderGitLab {
		t.Fatalf("merge request hook: %v %+v", err, h)
	}
	if len(rep.comments["gitlab acme/config #3"]) != 1 {
		t.Fatalf("gitlab comment: %v", rep.comments)
	}
	// An invalid bundle on a pull request: the comment says so, the status is a failure, the
	// outcome invalid; nothing is written.
	fetch.heads["refs/pull/8/head"] = "3333333333333333333333333333333333333333"
	fetch.files["3333333333333333333333333333333333333333"] = map[string][]byte{"bundles/a.yaml": []byte("kind: PolicyBinding\nname: backend-dev\nspec: {}\n")}
	pr8 := []byte(`{"action":"opened","number":8,"pull_request":{"number":8,"head":{"sha":"3333333333333333333333333333333333333333"}},"repository":{"clone_url":"https://git.example.com/acme/config.git"}}`)
	h, err = s.Hook(ctx, "acme", "config", githubHeaders("pull_request", "s3cret", pr8), pr8)
	if err != nil || h.Outcome != model.GitSyncInvalid {
		t.Fatalf("invalid pull request: %v %+v", err, h)
	}
	if c := rep.comments["github acme/config #8"]; len(c) != 1 || !strings.Contains(c[0], "❌ invalid") || !strings.Contains(c[0], "admin only") {
		t.Fatalf("invalid plan comment: %q", c)
	}
	if st := rep.statuses["github acme/config #8"]; len(st) != 1 || !strings.HasPrefix(st[0], "failure:") {
		t.Fatalf("invalid plan status: %q", st)
	}
	// No webhook secret in the spec: deliveries are refused as not found, whatever they carry.
	register(t, s, "acme", "plain", "kind: GitRepository\nname: plain\nspec: {url: https://git.example.com/acme/plain.git, ref: main, paths: ['bundles/*.yaml']}\n")
	if _, err := s.Hook(ctx, "acme", "plain", githubHeaders("push", "s3cret", push), push); err == nil || !strings.Contains(err.Error(), "accepts no webhooks") {
		t.Fatalf("repository without a webhook secret: %v", err)
	}
	// A second push of the same head: the same apply, nothing written twice.
	h, err = s.Hook(ctx, "acme", "config", githubHeaders("push", "s3cret", push), push)
	if err != nil || h.Outcome != model.GitSyncDone {
		t.Fatalf("second push: %v %+v", err, h)
	}
	if n := revs(t, st, model.KindEnvironment, "acme", "py"); n != 1 {
		t.Fatalf("a repeated push wrote: %d revisions", n)
	}
}

// The REST reporters against stand-ins for the providers' APIs: the comment is created once and
// then updated in place (found by the marker), the status carries the platform's context; the
// token goes in the provider's header and nowhere else.
func TestRESTReporterUpsertsCommentsAndSetsStatuses(t *testing.T) {
	type call struct{ method, path, auth, body string }
	var mu sync.Mutex
	var calls []call
	comments := map[int64]string{}
	var nextID int64 = 100
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var buf strings.Builder
		if r.Body != nil {
			b := make([]byte, 1<<16)
			n, _ := r.Body.Read(b)
			buf.Write(b[:n])
		}
		auth := r.Header.Get("Authorization") + r.Header.Get("PRIVATE-TOKEN")
		calls = append(calls, call{r.Method, r.URL.String(), auth, buf.String()})
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == "GET" && (strings.HasSuffix(r.URL.Path, "/comments") || strings.HasSuffix(r.URL.Path, "/notes")):
			var list []map[string]any
			list = append(list, map[string]any{"id": 1, "body": "a human's comment"})
			for id, body := range comments {
				list = append(list, map[string]any{"id": id, "body": body})
			}
			_ = json.NewEncoder(w).Encode(list)
		case r.Method == "POST" && (strings.HasSuffix(r.URL.Path, "/comments") || strings.HasSuffix(r.URL.Path, "/notes")):
			var in struct{ Body string }
			_ = json.Unmarshal([]byte(buf.String()), &in)
			nextID++
			comments[nextID] = in.Body
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"id":%d}`, nextID)
		case r.Method == "PATCH" || r.Method == "PUT":
			var in struct{ Body string }
			_ = json.Unmarshal([]byte(buf.String()), &in)
			for id := range comments {
				if strings.HasSuffix(r.URL.Path, fmt.Sprint(id)) {
					comments[id] = in.Body
				}
			}
			fmt.Fprint(w, `{}`)
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/statuses/"):
			w.WriteHeader(201)
			fmt.Fprint(w, `{}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	rep := RESTReporter{Client: srv.Client()}
	gh := Target{Provider: ProviderGitHub, APIBase: srv.URL, Repo: "acme/config", Number: 7, SHA: sha1, Token: "gh-token"}
	if err := rep.UpsertComment(ctx, gh, render.Marker+"\nfirst"); err != nil {
		t.Fatal(err)
	}
	if err := rep.UpsertComment(ctx, gh, render.Marker+"\nsecond"); err != nil {
		t.Fatal(err)
	}
	if err := rep.SetStatus(ctx, gh, StatusFailure, "plan: invalid"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if len(comments) != 1 {
		t.Fatalf("the comment was not updated in place: %v", comments)
	}
	for _, c := range comments {
		if c != render.Marker+"\nsecond" {
			t.Fatalf("comment body: %q", c)
		}
	}
	var created, patched, statused int
	for _, c := range calls {
		if c.auth != "Bearer gh-token" {
			t.Fatalf("github auth header: %q", c.auth)
		}
		switch {
		case c.method == "POST" && strings.HasSuffix(c.path, "/repos/acme/config/issues/7/comments"):
			created++
		case c.method == "PATCH" && strings.Contains(c.path, "/repos/acme/config/issues/comments/"):
			patched++
		case c.method == "POST" && strings.HasSuffix(c.path, "/repos/acme/config/statuses/"+sha1):
			statused++
			if !strings.Contains(c.body, `"context":"agent-sandbox/plan"`) || !strings.Contains(c.body, `"state":"failure"`) {
				t.Fatalf("github status body: %s", c.body)
			}
		}
	}
	if created != 1 || patched != 1 || statused != 1 {
		t.Fatalf("github calls: created %d patched %d statused %d: %+v", created, patched, statused, calls)
	}
	calls, comments = nil, map[int64]string{}
	mu.Unlock()
	gl := Target{Provider: ProviderGitLab, APIBase: srv.URL, Repo: "group/config", Number: 3, SHA: sha1, Token: "gl-token"}
	if err := rep.UpsertComment(ctx, gl, render.Marker+"\nfirst"); err != nil {
		t.Fatal(err)
	}
	if err := rep.UpsertComment(ctx, gl, render.Marker+"\nsecond"); err != nil {
		t.Fatal(err)
	}
	if err := rep.SetStatus(ctx, gl, StatusSuccess, "plan: 1 to apply on merge"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(comments) != 1 {
		t.Fatalf("the note was not updated in place: %v", comments)
	}
	var noted, put, glStatus int
	for _, c := range calls {
		if c.auth != "gl-token" {
			t.Fatalf("gitlab auth header: %q", c.auth)
		}
		switch {
		case c.method == "POST" && strings.HasSuffix(c.path, "/projects/group%2Fconfig/merge_requests/3/notes"):
			noted++
		case c.method == "PUT" && strings.Contains(c.path, "/projects/group%2Fconfig/merge_requests/3/notes/"):
			put++
		case c.method == "POST" && strings.HasSuffix(c.path, "/projects/group%2Fconfig/statuses/"+sha1):
			glStatus++
			if !strings.Contains(c.body, `"name":"agent-sandbox/plan"`) || !strings.Contains(c.body, `"state":"success"`) {
				t.Fatalf("gitlab status body: %s", c.body)
			}
		}
	}
	if noted != 1 || put != 1 || glStatus != 1 {
		t.Fatalf("gitlab calls: noted %d put %d status %d: %+v", noted, put, glStatus, calls)
	}
}

// A pull request head on a real server: the branch is fetched by its full ref
// (refs/pull/N/head, which no branch name reaches), the plan is posted, nothing is written.
func TestHookPlansAPullRequestHeadFromARealServer(t *testing.T) {
	srv := gittest.New(t, "x-access-token", "tok-real")
	base := srv.Commit(t, map[string]string{"bundles/a.yaml": "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"}, "base")
	// The pull request's head: a commit on a branch pushed as refs/pull/1/head only.
	gittest.Git(t, srv.Work, "checkout", "-q", "-b", "feature")
	head := srv.CommitOn(t, "feature", map[string]string{"bundles/a.yaml": "kind: EnvironmentProfile\nname: py\nspec: {image: stable, env: {LOG: debug}}\n"}, "feature", "refs/pull/1/head")
	s, st := newService(t, CLI{})
	s.Secrets = secrets.Static{"acme/repo-token": "tok-real", "acme/hook-secret": "s3cret"}
	s.Repos.Secrets = s.Secrets
	rep := &fakeReporter{}
	s.Reporter, s.Inline = rep, true
	register(t, s, "acme", "config", "kind: GitRepository\nname: config\nspec: {url: "+srv.URL+", ref: main, paths: ['bundles/*.yaml'], credential: repo-token, webhook_secret: hook-secret}\n")
	ctx := context.Background()
	pr := []byte(`{"action":"opened","number":1,"pull_request":{"number":1,"head":{"sha":"` + head + `"}},"repository":{"clone_url":"` + srv.URL + `"}}`)
	h, err := s.Hook(ctx, "acme", "config", githubHeaders("pull_request", "s3cret", pr), pr)
	if err != nil || h.Action != model.HookActionPlan || h.Outcome != model.GitSyncDone {
		t.Fatalf("pull request on a real server: %v %+v", err, h)
	}
	// TargetOf derives GitHub from the ref; the fake reporter takes any target.
	var body string
	for _, c := range rep.comments {
		body = c[0]
	}
	if !strings.Contains(body, "1 to create") || !strings.Contains(body, "LOG=debug") {
		t.Fatalf("the plan of the pull request head: %q", body)
	}
	if n := revs(t, st, model.KindEnvironment, "acme", "py"); n != 0 {
		t.Fatal("a plan wrote")
	}
	// The base is what a push syncs: the merged head, not the pull request's.
	push := []byte(`{"ref":"refs/heads/main","after":"` + base + `","repository":{"clone_url":"` + srv.URL + `"}}`)
	if h, err := s.Hook(ctx, "acme", "config", githubHeaders("push", "s3cret", push), push); err != nil || h.Outcome != model.GitSyncDone {
		t.Fatalf("push on a real server: %v %+v", err, h)
	}
	it, err := st.GetItem(ctx, model.KindEnvironment, "acme", "py", 0)
	if err != nil || it.Source == nil || it.Source.Commit != base || strings.Contains(string(it.Spec), "debug") {
		t.Fatalf("synced item: %v %+v", err, it)
	}
}
