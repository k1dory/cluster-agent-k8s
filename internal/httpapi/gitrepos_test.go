package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"agent-sandbox/internal/app"
	"agent-sandbox/internal/credentials"
	"agent-sandbox/internal/gitsync"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
)

// fakeGit is a Fetcher with one repository per URL: a head per ref, files per commit, and
// the credential each URL expects. It records the credentials it was handed.
type fakeGit struct {
	mu    sync.Mutex
	repos map[string]*fakeRepo
	seen  []string
}

type fakeRepo struct {
	auth    string
	heads   map[string]string
	files   map[string]map[string][]byte // commit → path → content
	history map[string][]string          // ref → commits, oldest first
	down    bool
}

func (f *fakeGit) open(r gitsync.Remote) (*fakeRepo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Auth)
	repo, ok := f.repos[r.URL]
	if !ok || repo.down {
		return nil, fmt.Errorf("git ls-remote: unable to access '%s': Could not connect to server", r.URL)
	}
	if repo.auth != r.Auth {
		return nil, errors.New("git ls-remote: the server refused the credential (HTTP 401)")
	}
	return repo, nil
}

func (f *fakeGit) Resolve(_ context.Context, r gitsync.Remote) (string, error) {
	repo, err := f.open(r)
	if err != nil {
		return "", err
	}
	head, ok := repo.heads[r.Ref]
	if !ok {
		return "", fmt.Errorf("%w: %s", gitsync.ErrNoRef, r.Ref)
	}
	return head, nil
}

func (f *fakeGit) Files(_ context.Context, r gitsync.Remote, commit string, patterns []string) (map[string][]byte, error) {
	repo, err := f.open(r)
	if err != nil {
		return nil, err
	}
	onRef := false
	for _, c := range repo.history[r.Ref] {
		onRef = onRef || c == commit
	}
	if !onRef {
		return nil, fmt.Errorf("%w: %s", gitsync.ErrNotOnRef, commit)
	}
	out := map[string][]byte{}
	for p, b := range repo.files[commit] {
		if gitsync.Matches(p, patterns) {
			out[p] = b
		}
	}
	if len(out) == 0 {
		return nil, gitsync.ErrNoMatch
	}
	return out, nil
}

const (
	shaA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shaX = "cccccccccccccccccccccccccccccccccccccccc"
)

// gitStack is the platform with credentials (BYOK) and the fake Git; alice and bob are
// tenants, the admin token t0k.
func gitStack(t *testing.T) (*stack, *fakeGit, *credentials.Service) {
	t.Helper()
	s := newStack(t)
	pols := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Tenants: []string{"alice", "bob"}, Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}})
	pols.Strict = true
	s.p.Policies = pols
	s.orch.Cfg.Versions = map[string]string{"stable": "reg/agent:1.0"}
	key, _ := credentials.ParseKey(strings.Repeat("ab", 32))
	creds, err := credentials.New(s.orch.Store, key)
	if err != nil {
		t.Fatal(err)
	}
	git := &fakeGit{repos: map[string]*fakeRepo{}}
	services, err := app.Wire(context.Background(), app.Deps{Store: s.orch.Store, Policies: pols,
		Secrets: secrets.Chain{credentials.Resolver{Service: creds}, secrets.Static{"shared-token": "op-secret", "/shared-token": "op-secret"}}, Orch: s.orch, Fetch: git})
	if err != nil {
		t.Fatal(err)
	}
	services.Install(s.p)
	s.p.Credentials = creds
	return s, git, creds
}

func syncOf(t *testing.T, body []byte) model.GitSync {
	t.Helper()
	var g model.GitSync
	if err := json.Unmarshal(body, &g); err == nil && g.Name != "" {
		return g
	}
	var wrapped struct {
		Sync model.GitSync `json:"sync"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		t.Fatalf("not a sync record: %s", body)
	}
	return wrapped.Sync
}

func TestGitRepositoryRegisterCheckSyncAndRepeat(t *testing.T) {
	s, git, _ := gitStack(t)
	api := s.platform.URL
	v1 := []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n")
	v2 := []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable, env: {LOG: debug}}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n")
	git.repos["https://git.example.com/alice/config.git"] = &fakeRepo{auth: "tok-alice", heads: map[string]string{"main": shaA},
		files:   map[string]map[string][]byte{shaA: {"bundles/acme.yaml": v1, "README.md": []byte("x")}, shaB: {"bundles/acme.yaml": v2}},
		history: map[string][]string{"main": {shaA}}}

	// The credential first (BYOK), then the registration, which must resolve it.
	if resp, body := call(t, "PUT", api+"/v1/credentials/config-token", "alice-tok", map[string]string{"value": "tok-alice"}, nil); resp.StatusCode != 201 {
		t.Fatalf("credential: %d %s", resp.StatusCode, body)
	}
	repo := `{"spec":{"url":"https://git.example.com/alice/config.git","ref":"main","paths":["bundles/*.yaml"],"credential":"config-token"}}`
	if code, _ := putDoc(t, api, "alice-tok", "gitrepos", "config", strings.Replace(repo, "config-token", "missing", 1)); code != 422 {
		t.Fatalf("a repository naming a missing credential: %d", code)
	}
	for _, bad := range []string{
		`{"spec":{"url":"https://user:pw@git.example.com/a.git","ref":"main","paths":["b.yaml"]}}`,
		`{"spec":{"url":"http://git.example.com/a.git","ref":"main","paths":["b.yaml"]}}`,
		`{"spec":{"url":"https://git.example.com/a.git","ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","paths":["b.yaml"]}}`,
		`{"spec":{"url":"https://git.example.com/a.git","ref":"main","paths":["../b.yaml"]}}`,
		`{"spec":{"url":"https://git.example.com/a.git","ref":"main","paths":[]}}`,
		`{"spec":{"url":"https://git.example.com/a.git","ref":"main","paths":["b.yaml"],"credential":"ghp_averyrealtoken:with:colons"}}`,
		`{"spec":{"url":"https://git.example.com/a.git","ref":"main","paths":["b.yaml"],"webhook_secret":"missing"}}`,
		`{"spec":{"url":"https://git.example.com/a.git","ref":"main","paths":["b.yaml"],"webhook_secret":"a value with spaces"}}`,
	} {
		if code, _ := putDoc(t, api, "alice-tok", "gitrepos", "bad", bad); code != 422 {
			t.Errorf("accepted %s: %d", bad, code)
		}
	}
	code, it := putDoc(t, api, "alice-tok", "gitrepos", "config", repo)
	if code != 201 || it.Kind != model.KindGitRepository || it.Tenant != "alice" {
		t.Fatalf("register: %d %+v", code, it)
	}
	// Status before any check: nothing yet.
	if resp, _ := call(t, "GET", api+"/v1/gitrepos/config/status", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("status before a check: %d", resp.StatusCode)
	}
	// Check: the head, with the tenant's credential handed to Git.
	resp, body := call(t, "POST", api+"/v1/gitrepos/config/check", "alice-tok", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 200 || g.Check.Head != shaA || g.Check.At.IsZero() || g.Check.Error != "" {
		t.Fatalf("check: %d %s", resp.StatusCode, body)
	}
	if git.seen[len(git.seen)-1] != "tok-alice" {
		t.Fatalf("the credential handed to git: %q", git.seen[len(git.seen)-1])
	}
	// Sync the head: one apply for the one bundle, the commit on every revision.
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", nil, nil)
	g := syncOf(t, body)
	if resp.StatusCode != 200 || g.Sync.Status != model.GitSyncDone || g.Sync.Commit != shaA || len(g.Sync.Bundles) != 1 || g.Sync.Bundles[0].Path != "bundles/acme.yaml" || g.Sync.Bundles[0].Status != model.ApplyDone || g.Sync.Bundles[0].Changes != 2 {
		t.Fatalf("sync: %d %s", resp.StatusCode, body)
	}
	first := g.Sync.Bundles[0].Apply
	var env model.CatalogItem
	if resp, body := call(t, "GET", api+"/v1/environments/py", "alice-tok", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("environment: %d %s", resp.StatusCode, body)
	} else {
		_ = json.Unmarshal(body, &env)
	}
	if env.Source == nil || env.Source.Commit != shaA || env.Source.Repo != "https://git.example.com/alice/config.git" || env.Source.Ref != "main" || env.Source.Path != "bundles/acme.yaml" || env.Source.Apply != first {
		t.Fatalf("environment source: %+v", env.Source)
	}
	var a model.Apply
	_, body = call(t, "GET", api+"/v1/applies/"+first, "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &a)
	if a.Key != gitsync.Key("config", shaA, "bundles/acme.yaml") || a.Admin || a.Tenant != "alice" {
		t.Fatalf("apply record: %+v", a)
	}
	// The same commit again (explicitly): the same apply, no new revision.
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", map[string]string{"commit": shaA}, nil)
	if g := syncOf(t, body); resp.StatusCode != 200 || g.Sync.Bundles[0].Apply != first {
		t.Fatalf("repeat: %d %s", resp.StatusCode, body)
	}
	var revs []model.CatalogItem
	_, body = call(t, "GET", api+"/v1/environments/py/revisions", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &revs)
	if len(revs) != 1 {
		t.Fatalf("a repeated sync wrote: %d revisions", len(revs))
	}
	_, body = call(t, "GET", api+"/v1/applies", "alice-tok", nil, nil)
	var applies []model.Apply
	_ = json.Unmarshal(body, &applies)
	if len(applies) != 1 {
		t.Fatalf("a repeated sync created an apply: %d", len(applies))
	}
	// The ref moves: the next sync applies the new head under a new key; the old commit stays
	// syncable (reachable from the ref) and still writes nothing.
	git.repos["https://git.example.com/alice/config.git"].heads["main"] = shaB
	git.repos["https://git.example.com/alice/config.git"].history["main"] = []string{shaA, shaB}
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", nil, nil)
	g = syncOf(t, body)
	if resp.StatusCode != 200 || g.Sync.Commit != shaB || g.Sync.Bundles[0].Apply == first || g.Sync.Bundles[0].Changes != 1 {
		t.Fatalf("sync of the new head: %d %s", resp.StatusCode, body)
	}
	_, body = call(t, "GET", api+"/v1/environments/py", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &env)
	if env.Revision != 2 || env.Source.Commit != shaB {
		t.Fatalf("environment after the second sync: rev %d %+v", env.Revision, env.Source)
	}
	if resp, body := call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", map[string]string{"commit": shaA}, nil); resp.StatusCode != 200 || syncOf(t, body).Sync.Bundles[0].Apply != first {
		t.Fatalf("the old commit again: %d %s", resp.StatusCode, body)
	}
	_, body = call(t, "GET", api+"/v1/environments/py/revisions", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &revs)
	if len(revs) != 2 {
		t.Fatalf("revisions after re-syncing the old commit: %d", len(revs))
	}
	// A commit that is not on the ref, a non-SHA, an unknown field in the body.
	if resp, body := call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", map[string]string{"commit": shaX}, nil); resp.StatusCode != 502 || !strings.Contains(string(body), "not reachable") {
		t.Fatalf("commit off the ref: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", map[string]string{"commit": "deadbeef"}, nil); resp.StatusCode != 422 {
		t.Fatalf("non-SHA: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", map[string]string{"sha": shaA}, nil); resp.StatusCode != 400 {
		t.Fatalf("unknown body field: %d", resp.StatusCode)
	}
	// The whole body is checked before Git is asked: trailing data, a second document, a
	// truncated document and an oversized body are refused, and nothing is fetched or applied.
	seen := len(git.seen)
	for body, want := range map[string]int{
		`{"commit":"` + shaA + `"} trailing`:      400,
		`{"commit":"` + shaA + `"}{"commit":"x"}`: 400,
		`{"commit":"` + shaA + `"`:                400,
		`[]`:                                      400,
		`null`:                                    400,
		`{"commit":null}`:                         400,
		`{"commit":123}`:                          400,
		`{"commit":["` + shaA + `"]}`:             400,
		`"` + shaA + `"`:                          400,
		`{"commit":"` + strings.Repeat("a", 5000) + `"}`: 413,
	} {
		if resp, got := call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", body, map[string]string{"Content-Type": "application/json"}); resp.StatusCode != want {
			t.Errorf("body %.40q: %d %s, want %d", body, resp.StatusCode, got, want)
		}
	}
	if len(git.seen) != seen {
		t.Fatalf("a refused body reached Git: %d calls", len(git.seen)-seen)
	}
	// Status: the last check and the last sync attempt, the failed one included (its commit
	// and error), so the operator sees what was tried last.
	resp, body = call(t, "GET", api+"/v1/gitrepos/config/status", "alice-tok", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 200 || g.Check.Head != shaB || g.Sync.Commit != shaX || g.Sync.Status != model.GitSyncError || !strings.Contains(g.Sync.Error, "not reachable") {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
	// An empty body (whitespace too) means the head.
	if resp, body := call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", "  \n", map[string]string{"Content-Type": "application/json"}); resp.StatusCode != 200 || syncOf(t, body).Sync.Commit != shaB {
		t.Fatalf("sync of the head after a failed attempt (whitespace body): %d %s", resp.StatusCode, body)
	}
	// The repository is a versioned item: drift and revisions apply to it like to any other.
	_, body = call(t, "GET", api+"/v1/gitrepos/config/revisions", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &revs)
	if len(revs) != 1 || revs[0].Kind != model.KindGitRepository {
		t.Fatalf("repository revisions: %s", body)
	}
}

func TestGitRepositoryIsolationCredentialRevocationAndUnreachable(t *testing.T) {
	s, git, _ := gitStack(t)
	api := s.platform.URL
	v1 := []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n")
	git.repos["https://git.example.com/alice/config.git"] = &fakeRepo{auth: "tok-alice", heads: map[string]string{"main": shaA},
		files: map[string]map[string][]byte{shaA: {"bundles/acme.yaml": v1}}, history: map[string][]string{"main": {shaA}}}
	call(t, "PUT", api+"/v1/credentials/config-token", "alice-tok", map[string]string{"value": "tok-alice"}, nil)
	repo := `{"spec":{"url":"https://git.example.com/alice/config.git","ref":"main","paths":["bundles/*.yaml"],"credential":"config-token"}}`
	if code, _ := putDoc(t, api, "alice-tok", "gitrepos", "config", repo); code != 201 {
		t.Fatalf("register: %d", code)
	}
	// Isolation: bob sees nothing of alice's repository, cannot check, sync or read its status;
	// the admin acts on it with ?tenant=alice, and the apply stays alice's (not admin).
	for _, path := range []string{"/v1/gitrepos/config", "/v1/gitrepos/config/status"} {
		if resp, _ := call(t, "GET", api+path, "bob-tok", nil, nil); resp.StatusCode != 404 {
			t.Fatalf("bob GET %s: %d", path, resp.StatusCode)
		}
	}
	for _, path := range []string{"/v1/gitrepos/config/check", "/v1/gitrepos/config/sync"} {
		if resp, _ := call(t, "POST", api+path, "bob-tok", nil, nil); resp.StatusCode != 404 {
			t.Fatalf("bob POST %s: %d", path, resp.StatusCode)
		}
	}
	if resp, body := call(t, "GET", api+"/v1/gitrepos", "bob-tok", nil, nil); resp.StatusCode != 200 || strings.Contains(string(body), "alice/config") {
		t.Fatalf("bob's list: %d %s", resp.StatusCode, body)
	}
	resp, body := call(t, "POST", api+"/v1/gitrepos/config/sync?tenant=alice", "t0k", nil, nil)
	g := syncOf(t, body)
	if resp.StatusCode != 200 || g.Sync.Status != model.GitSyncDone {
		t.Fatalf("admin sync of alice's repository: %d %s", resp.StatusCode, body)
	}
	var a model.Apply
	_, body = call(t, "GET", api+"/v1/applies/"+g.Sync.Bundles[0].Apply+"?tenant=alice", "t0k", nil, nil)
	_ = json.Unmarshal(body, &a)
	if a.Tenant != "alice" || a.Admin {
		t.Fatalf("an admin-triggered sync must apply with the tenant's authority: %+v", a)
	}
	// A tenant's bundle cannot grant itself: a PolicyBinding in alice's repository is refused.
	git.repos["https://git.example.com/alice/config.git"].heads["main"] = shaB
	git.repos["https://git.example.com/alice/config.git"].history["main"] = []string{shaA, shaB}
	git.repos["https://git.example.com/alice/config.git"].files[shaB] = map[string][]byte{"bundles/acme.yaml": []byte("kind: PolicyBinding\nname: backend-dev\nspec: {}\n")}
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/sync?tenant=alice", "t0k", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 422 || g.Sync.Status != model.GitSyncInvalid || !strings.Contains(strings.Join(g.Sync.Bundles[0].Errors, " "), "admin only") {
		t.Fatalf("a grant in a tenant's repository: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/bindings/backend-dev", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatal("the refused bundle wrote")
	}
	// A shared repository is the admin's: alice sees it in her list but may not sync it.
	git.repos["https://git.example.com/platform/config.git"] = &fakeRepo{auth: "op-secret", heads: map[string]string{"main": shaA},
		files: map[string]map[string][]byte{shaA: {"bundles/alice.yaml": []byte("kind: PolicyBinding\ntenant: alice\nname: backend-dev\nspec: {}\n")}}, history: map[string][]string{"main": {shaA}}}
	if code, _ := putDoc(t, api, "t0k", "gitrepos", "platform", `{"spec":{"url":"https://git.example.com/platform/config.git","ref":"main","paths":["bundles/*.yaml"],"credential":"shared-token"}}`); code != 201 {
		t.Fatalf("shared repository: %d", code)
	}
	if resp, _ := call(t, "POST", api+"/v1/gitrepos/platform/sync", "alice-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("alice syncing the shared repository: %d", resp.StatusCode)
	}
	resp, body = call(t, "POST", api+"/v1/gitrepos/platform/sync", "t0k", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 200 || g.Sync.Status != model.GitSyncDone {
		t.Fatalf("admin sync of the shared repository: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/bindings/backend-dev", "alice-tok", nil, nil); resp.StatusCode != 200 {
		t.Fatal("the admin's repository did not grant")
	}

	// Revocation: the credential is deleted; check and sync fail with a clear error, name no
	// value, write nothing, and the status records it. Restoring it restores the sync.
	git.repos["https://git.example.com/alice/config.git"].files[shaB] = map[string][]byte{"bundles/acme.yaml": []byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable, env: {A: b}}\n")}
	if resp, _ := call(t, "DELETE", api+"/v1/credentials/config-token", "alice-tok", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete credential: %d", resp.StatusCode)
	}
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/check", "alice-tok", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 422 || g.Check.Error == "" || !strings.Contains(g.Check.Error, `"config-token"`) || strings.Contains(string(body), "tok-alice") {
		t.Fatalf("check without the credential: %d %s", resp.StatusCode, body)
	}
	seen := len(git.seen)
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 422 || g.Sync.Status != model.GitSyncError || !strings.Contains(g.Sync.Error, "not available") || len(git.seen) != seen {
		t.Fatalf("sync without the credential: %d %s", resp.StatusCode, body)
	}
	var revs []model.CatalogItem
	_, body = call(t, "GET", api+"/v1/environments/py/revisions", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &revs)
	if len(revs) != 1 {
		t.Fatalf("a sync without a credential wrote: %d revisions", len(revs))
	}
	// A wrong credential is the server's refusal: 502, the token never in the message.
	call(t, "PUT", api+"/v1/credentials/config-token", "alice-tok", map[string]string{"value": "tok-wrong"}, nil)
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 502 || g.Sync.Status != model.GitSyncError || !strings.Contains(g.Sync.Error, "401") || strings.Contains(string(body), "tok-wrong") {
		t.Fatalf("sync with a refused credential: %d %s", resp.StatusCode, body)
	}
	call(t, "PUT", api+"/v1/credentials/config-token", "alice-tok", map[string]string{"value": "tok-alice"}, nil)
	if resp, body := call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", nil, nil); resp.StatusCode != 200 || syncOf(t, body).Sync.Status != model.GitSyncDone {
		t.Fatalf("sync after restoring the credential: %d %s", resp.StatusCode, body)
	}
	// Unreachable: 502 on check and sync, recorded, nothing written; back online, it works.
	git.repos["https://git.example.com/alice/config.git"].down = true
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/check", "alice-tok", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 502 || !strings.Contains(g.Check.Error, "Could not connect") || g.Check.Head != "" {
		t.Fatalf("check while down: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", map[string]string{"commit": shaB}, nil)
	if g := syncOf(t, body); resp.StatusCode != 502 || g.Sync.Status != model.GitSyncError {
		t.Fatalf("sync while down: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/gitrepos/config/status", "alice-tok", nil, nil)
	if g := syncOf(t, body); resp.StatusCode != 200 || g.Sync.Status != model.GitSyncError || g.Check.Error == "" {
		t.Fatalf("status while down: %d %s", resp.StatusCode, body)
	}
	git.repos["https://git.example.com/alice/config.git"].down = false
	if resp, body := call(t, "POST", api+"/v1/gitrepos/config/check", "alice-tok", nil, nil); resp.StatusCode != 200 || syncOf(t, body).Check.Head != shaB {
		t.Fatalf("check back online: %d %s", resp.StatusCode, body)
	}
	// Deleting the registration ends the routes for it; the revisions it wrote stay.
	if resp, _ := call(t, "DELETE", api+"/v1/gitrepos/config", "alice-tok", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/gitrepos/config/sync", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("sync after delete: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/environments/py", "alice-tok", nil, nil); resp.StatusCode != 200 {
		t.Fatal("the synced environment vanished with the registration")
	}
}
