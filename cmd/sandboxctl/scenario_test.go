package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/app"
	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/events"
	"agent-sandbox/internal/httpapi"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/registrar"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// breakingStore fails the apply step of one named item while armed: the database going away
// in the middle of a merge's apply.
type breakingStore struct {
	store.Store
	mu   sync.Mutex
	item string
}

func (s *breakingStore) arm(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.item = name
}

func (s *breakingStore) ApplyStep(ctx context.Context, a *model.Apply, step int, it *model.CatalogItem, expected int) error {
	s.mu.Lock()
	item := s.item
	s.mu.Unlock()
	if it != nil && it.Name == item {
		return fmt.Errorf("database went away while writing %s", it.Name)
	}
	return s.Store.ApplyStep(ctx, a, step, it, expected)
}

// realPlatform is the control plane as sandboxd wires it (configuration services included),
// on a memory store wrapped so one step can be made to fail.
func realPlatform(t *testing.T) (*httptest.Server, *breakingStore) {
	t.Helper()
	st := &breakingStore{Store: store.NewMemory()}
	c, err := ca.Generate("test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reg := &registrar.Registrar{CA: c, Store: st, Resolver: registrar.StaticResolver{}, TTL: time.Hour, GatewayCA: []byte("GWROOT")}
	hub := events.New()
	orch := orchestrator.New(st, orchestrator.NewFakeRuntime(), reg, hub, orchestrator.Config{PreviewDomain: "preview.test", Versions: map[string]string{"stable": "reg/agent:1.0"}}, nil)
	pols := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Tenants: []string{"acme"}, Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}})
	pols.Strict = true
	p := &httpapi.Platform{Orch: orch, Hub: hub, Policies: pols, Token: "admin-tok", Tenants: map[string]string{"acme-tok": "acme"}}
	services, err := app.Wire(context.Background(), app.Deps{Store: st, Policies: pols, Secrets: secrets.Static{}, Orch: orch})
	if err != nil {
		t.Fatal(err)
	}
	services.Install(p)
	srv := httptest.NewServer(p.Routes())
	t.Cleanup(srv.Close)
	return srv, st
}

func apiGet(t *testing.T, base, token, path string, out any) int {
	t.Helper()
	req, _ := http.NewRequest("GET", base+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 {
		if err := json.Unmarshal(body, out); err != nil {
			t.Fatalf("GET %s: %v: %s", path, err, body)
		}
	}
	return resp.StatusCode
}

func apiPut(t *testing.T, base, token, path, body string) int {
	t.Helper()
	req, _ := http.NewRequest("PUT", base+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Logf("PUT %s: %d %s", path, resp.StatusCode, raw)
	}
	return resp.StatusCode
}

var applyID = regexp.MustCompile("### Apply [^·]+· `([^`]+)`")

// The Git adapters' scenario, end to end on the real control plane, with the CLI calls the
// templates make: the plan on the pull request, the apply on the merge with the commit's SHA
// recorded under a key stable for the bundle at that commit, drift after a hand edit, and a
// merge whose apply stops half-way: re-running the job (same key, same bundle) continues the
// same apply where it stopped rather than starting another one.
func TestScenarioPullRequestMergeDriftAndResumeUnderAStableKey(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	srv, st := realPlatform(t)
	api, tok := srv.URL, "acme-tok"

	repo := t.TempDir()
	run(t, repo, "init", "-q", "-b", "main")
	run(t, repo, "remote", "add", "origin", "https://x-access-token:ghp_secret@github.com/acme/config.git")
	if err := os.MkdirAll(filepath.Join(repo, "bundles"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(repo, "bundles", "acme.yaml")
	commit := func(content, msg string) string {
		if err := os.WriteFile(bundle, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		run(t, repo, "add", ".")
		run(t, repo, "commit", "-q", "-m", msg)
		return run(t, repo, "rev-parse", "HEAD")
	}
	v1 := "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"
	sha1 := commit(v1, "add the backend agent")
	// The templates' apply call: the branch named, the repository named, the key the bundle at
	// this commit, the SHA required.
	applyArgs := func(sha string) []string {
		return []string{"apply", "-f", "bundles/acme.yaml", "-ref", "main", "-key", "bundles/acme.yaml@" + sha, "-require-commit", "-markdown"}
	}

	// 1. The pull request: the plan is the comment, nothing is written.
	out, errOut, code := ctlChild(t, repo, api, tok, nil, "plan", "-f", "bundles/acme.yaml", "-markdown")
	if code != 0 || !strings.HasPrefix(out, Marker+"\n### Plan ✅ valid · `bundles/acme.yaml`") || !strings.Contains(out, "2 to create, 0 to update") {
		t.Fatalf("plan on the pull request: exit %d\n%s%s", code, out, errOut)
	}
	if apiGet(t, api, tok, "/v1/environments/py", nil) != 404 {
		t.Fatal("the plan wrote")
	}

	// 2. The merge: the apply records the commit on every revision, and the remote's credential
	// never leaves the runner.
	out, errOut, code = ctlChild(t, repo, api, tok, nil, applyArgs(sha1)...)
	if code != 0 || !strings.Contains(out, "### Apply ✅ done") || !strings.Contains(out, "Source: `"+sha1+"` in https://github.com/acme/config.git (`bundles/acme.yaml`)") {
		t.Fatalf("apply on merge: exit %d\n%s%s", code, out, errOut)
	}
	first := applyID.FindStringSubmatch(out)
	if first == nil {
		t.Fatalf("no apply id in\n%s", out)
	}
	var env model.CatalogItem
	if apiGet(t, api, tok, "/v1/environments/py", &env) != 200 || env.Source == nil || env.Source.Commit != sha1 || env.Source.Apply != first[1] || env.Source.Ref != "main" || env.Source.Path != "bundles/acme.yaml" {
		t.Fatalf("environment source: %+v", env.Source)
	}
	if env.Source.Repo != "https://github.com/acme/config.git" || strings.Contains(out, "ghp_") {
		t.Fatalf("credential leaked into the record or the summary: %+v", env.Source)
	}
	var agent model.CatalogItem
	if apiGet(t, api, tok, "/v1/agents/backend", &agent) != 200 || agent.Source == nil || agent.Source.Commit != sha1 {
		t.Fatalf("agent source: %+v", agent.Source)
	}
	// Re-running the merge job (same key, same bundle) returns the same apply and writes nothing.
	out, _, code = ctlChild(t, repo, api, tok, nil, applyArgs(sha1)...)
	if code != 0 || applyID.FindStringSubmatch(out)[1] != first[1] {
		t.Fatalf("re-run of a done apply: exit %d\n%s", code, out)
	}
	var revs []model.CatalogItem
	if apiGet(t, api, tok, "/v1/environments/py/revisions", &revs) != 200 || len(revs) != 1 {
		t.Fatalf("a re-run wrote: %d revisions", len(revs))
	}

	// 3. Nothing drifted yet; then a hand edit through the API is drift, with the author.
	if out, _, code = ctlChild(t, repo, api, tok, nil, "drift", "-markdown"); code != 0 || !strings.Contains(out, "### Drift ✅ none · 2 managed items") {
		t.Fatalf("drift after apply: exit %d\n%s", code, out)
	}
	if apiPut(t, api, tok, "/v1/environments/py", `{"spec":{"image":"stable","runtime_class":"gvisor"}}`) != 200 {
		t.Fatal("hand edit")
	}
	out, _, code = ctlChild(t, repo, api, tok, nil, "drift", "-markdown")
	if code != 3 || !strings.Contains(out, "### Drift ⚠️ 1 of 2 managed items") || !strings.Contains(out, "| changed | EnvironmentProfile | acme | `py` | 1 (`"+first[1]+"` @ `"+shortSHA(sha1)+"`) | 2 |") || !strings.Contains(out, "runtime_class") {
		t.Fatalf("drift after a hand edit: exit %d\n%s", code, out)
	}
	// The pull request that declares the intended state shows the way back.
	if out, _, code = ctlChild(t, repo, api, tok, nil, "drift", "-f", "bundles/acme.yaml", "-markdown"); code != 3 || !strings.Contains(out, "| ✏️ update | EnvironmentProfile | acme | `py` | 2 → 3 |") {
		t.Fatalf("drift against the bundle: exit %d\n%s", code, out)
	}

	// 4. The next merge: the environment and the agent change; the agent's step fails.
	v2 := "kind: EnvironmentProfile\nname: py\nspec: {image: stable, env: {LOG: debug}}\n---\nkind: AgentDefinition\nname: backend\ndescription: with logs\nspec: {policy: backend-dev, environment: py}\n"
	sha2 := commit(v2, "debug logging")
	var before struct{ Plan string }
	if out, _, code = ctlChild(t, repo, api, tok, nil, "plan", "-f", "bundles/acme.yaml", "-json"); code != 0 {
		t.Fatalf("plan v2: exit %d\n%s", code, out)
	}
	_ = json.Unmarshal([]byte(out), &before)
	st.arm("backend")
	out, errOut, code = ctlChild(t, repo, api, tok, nil, applyArgs(sha2)...)
	if code != 3 || !strings.Contains(out, "### Apply ❌ failed") || !strings.Contains(out, "| 1 | EnvironmentProfile | acme | `py` | ✏️ update | done | 3 | - |") || !strings.Contains(out, "| 2 | AgentDefinition | acme | `backend` | ✏️ update | failed | - | database went away") {
		t.Fatalf("partial apply: exit %d\n%s%s", code, out, errOut)
	}
	second := applyID.FindStringSubmatch(out)[1]
	if second == first[1] {
		t.Fatal("a new commit is a new apply")
	}
	// Half applied: the environment moved, the agent did not; the fingerprint of the same bundle
	// is now another one (it is bound to the state), which is why the key must not be it.
	var after struct{ Plan string }
	if out, _, code = ctlChild(t, repo, api, tok, nil, "plan", "-f", "bundles/acme.yaml", "-json"); code != 0 {
		t.Fatalf("plan after the partial apply: exit %d\n%s", code, out)
	}
	_ = json.Unmarshal([]byte(out), &after)
	if before.Plan == "" || before.Plan == after.Plan {
		t.Fatalf("the plan fingerprint should move with the state: %q then %q", before.Plan, after.Plan)
	}
	if apiGet(t, api, tok, "/v1/environments/py", &env) != 200 || env.Revision != 3 || env.Source == nil || env.Source.Commit != sha2 || env.Source.Apply != second {
		t.Fatalf("environment after the partial apply: rev %d %+v", env.Revision, env.Source)
	}
	if apiGet(t, api, tok, "/v1/agents/backend", &agent) != 200 || agent.Revision != 1 {
		t.Fatalf("the agent should be untouched: rev %d", agent.Revision)
	}

	// 5. The cause is fixed and the job is re-run: the same command (same key, same bundle)
	// continues the same apply from the failed step. One revision per step, no duplicate.
	st.arm("")
	out, errOut, code = ctlChild(t, repo, api, tok, nil, applyArgs(sha2)...)
	if code != 0 || !strings.Contains(out, "### Apply ✅ done · `"+second+"`") || !strings.Contains(out, "| 1 | EnvironmentProfile | acme | `py` | ✏️ update | done | 3 | - |") || !strings.Contains(out, "| 2 | AgentDefinition | acme | `backend` | ✏️ update | done | 2 | - |") {
		t.Fatalf("re-run after the partial apply: exit %d\n%s%s", code, out, errOut)
	}
	if apiGet(t, api, tok, "/v1/environments/py/revisions", &revs) != 200 || len(revs) != 3 {
		t.Fatalf("the re-run re-applied the done step: %d revisions", len(revs))
	}
	if apiGet(t, api, tok, "/v1/agents/backend", &agent) != 200 || agent.Revision != 2 || agent.Source == nil || agent.Source.Commit != sha2 || agent.Source.Apply != second {
		t.Fatalf("agent after the re-run: rev %d %+v", agent.Revision, agent.Source)
	}
	var a model.Apply
	if apiGet(t, api, tok, "/v1/applies/"+second, &a) != 200 || a.Status != model.ApplyDone || a.Key != "bundles/acme.yaml@"+sha2 || a.Attempt != 2 {
		t.Fatalf("the apply record: %+v", a)
	}
	// Everything the platform holds is what the merge declared: no drift.
	if out, _, code = ctlChild(t, repo, api, tok, nil, "drift", "-markdown"); code != 0 || !strings.Contains(out, "### Drift ✅ none · 2 managed items") {
		t.Fatalf("drift after the completed apply: exit %d\n%s", code, out)
	}
	// Without a stable key the re-run would be a new apply: the default key is the fingerprint,
	// and the bundle's fingerprint has moved. The templates therefore pass -key path@commit.
	if a2, err := st.GetApplyByKey(context.Background(), "acme", after.Plan); err == nil {
		t.Fatalf("an apply under the moved fingerprint exists: %s", a2.ID)
	}
}

// A bundle with expected_revision re-plans as invalid against the state its own first attempt
// wrote (0 for "must not exist" once step 1 created the item; 1 once it was updated). The
// re-run of the merge job must still continue that apply: the decision is the controller's,
// which knows the apply and adjusts the expectation of the steps it already did. Four cases:
// a partial and a finished apply, with expected_revision 0 and 1.
func TestScenarioRerunWithExpectedRevisionReachesTheController(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	srv, st := realPlatform(t)
	api, tok := srv.URL, "acme-tok"
	repo := t.TempDir()
	run(t, repo, "init", "-q", "-b", "main")
	if err := os.MkdirAll(filepath.Join(repo, "bundles"), 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(repo, "bundles", "acme.yaml")
	commit := func(content, msg string) string {
		if err := os.WriteFile(bundle, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		run(t, repo, "add", ".")
		run(t, repo, "commit", "-q", "-m", msg)
		return run(t, repo, "rev-parse", "HEAD")
	}
	applyArgs := func(sha string, extra ...string) []string {
		return append([]string{"apply", "-f", "bundles/acme.yaml", "-ref", "main", "-key", "bundles/acme.yaml@" + sha, "-require-commit", "-markdown"}, extra...)
	}
	// v1: both documents must not exist yet (expected_revision 0); the agent's step fails.
	v1 := "kind: EnvironmentProfile\nname: py\nexpected_revision: 0\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nexpected_revision: 0\nspec: {policy: backend-dev, environment: py}\n"
	sha1 := commit(v1, "create, guarded")
	st.arm("backend")
	out, errOut, code := ctlChild(t, repo, api, tok, nil, applyArgs(sha1)...)
	if code != 3 || !strings.Contains(out, "### Apply ❌ failed") {
		t.Fatalf("partial apply: exit %d\n%s%s", code, out, errOut)
	}
	id := applyID.FindStringSubmatch(out)[1]
	// The plan of the same bundle is now invalid (py exists, expected 0): the pull request
	// check would say so, and so would the previous CLI, which never reached the controller.
	if out, _, code := ctlChild(t, repo, api, tok, nil, "plan", "-f", "bundles/acme.yaml"); code != 2 {
		t.Fatalf("precondition: the re-plan should be invalid now: exit %d\n%s", code, out)
	}
	st.arm("")
	out, errOut, code = ctlChild(t, repo, api, tok, nil, applyArgs(sha1)...)
	if code != 0 || !strings.Contains(out, "### Apply ✅ done · `"+id+"`") || !strings.Contains(out, "| 2 | AgentDefinition | acme | `backend` | ➕ create | done | 1 | - |") {
		t.Fatalf("re-run of the partial apply with expected_revision 0: exit %d\n%s%s", code, out, errOut)
	}
	// Finished apply, same key, same bundle: the same apply again, nothing written, exit 0.
	out, errOut, code = ctlChild(t, repo, api, tok, nil, applyArgs(sha1)...)
	if code != 0 || !strings.Contains(out, "### Apply ✅ done · `"+id+"`") {
		t.Fatalf("re-run of the finished apply with expected_revision 0: exit %d\n%s%s", code, out, errOut)
	}
	var revs []model.CatalogItem
	if apiGet(t, api, tok, "/v1/environments/py/revisions", &revs) != 200 || len(revs) != 1 {
		t.Fatalf("re-runs wrote: %d revisions", len(revs))
	}
	// v2: both at revision 1 (expected_revision 1); the agent's step fails again.
	v2 := "kind: EnvironmentProfile\nname: py\nexpected_revision: 1\nspec: {image: stable, env: {LOG: debug}}\n---\nkind: AgentDefinition\nname: backend\nexpected_revision: 1\ndescription: with logs\nspec: {policy: backend-dev, environment: py}\n"
	sha2 := commit(v2, "update, guarded")
	st.arm("backend")
	out, errOut, code = ctlChild(t, repo, api, tok, nil, applyArgs(sha2)...)
	if code != 3 || !strings.Contains(out, "| 1 | EnvironmentProfile | acme | `py` | ✏️ update | done | 2 | - |") {
		t.Fatalf("partial update: exit %d\n%s%s", code, out, errOut)
	}
	id2 := applyID.FindStringSubmatch(out)[1]
	st.arm("")
	for i := 0; i < 2; i++ { // the continuation, then the finished apply again
		out, errOut, code = ctlChild(t, repo, api, tok, nil, applyArgs(sha2)...)
		if code != 0 || !strings.Contains(out, "### Apply ✅ done · `"+id2+"`") || !strings.Contains(out, "| 2 | AgentDefinition | acme | `backend` | ✏️ update | done | 2 | - |") {
			t.Fatalf("re-run %d with expected_revision 1: exit %d\n%s%s", i+1, code, out, errOut)
		}
	}
	if apiGet(t, api, tok, "/v1/environments/py/revisions", &revs) != 200 || len(revs) != 2 {
		t.Fatalf("re-runs wrote: %d revisions", len(revs))
	}
	// The controller's checks still hold on a continuation: the same key with another bundle
	// is a conflict, and an outside change to a done step's item stops it.
	if out, errOut, code := ctlChild(t, repo, api, tok, nil, "apply", "-f", "bundles/acme.yaml", "-no-git", "-key", "bundles/acme.yaml@"+sha1); code != 1 || !strings.Contains(errOut, "different bundle") {
		t.Fatalf("another bundle under a used key: exit %d\n%s%s", code, out, errOut)
	}
	// A genuinely new, invalid bundle under a new key is refused by the controller with its
	// plan, rendered here as the plan (exit 2), never applied.
	v3 := "kind: EnvironmentProfile\nname: py\nexpected_revision: 0\nspec: {image: stable}\n"
	sha3 := commit(v3, "stale guard")
	out, errOut, code = ctlChild(t, repo, api, tok, nil, applyArgs(sha3)...)
	if code != 2 || !strings.HasPrefix(out, Marker+"\n### Plan ❌ invalid · `bundles/acme.yaml`") || !strings.Contains(out, "expected") {
		t.Fatalf("new invalid bundle under a new key: exit %d\n%s%s", code, out, errOut)
	}
	if apiGet(t, api, tok, "/v1/environments/py/revisions", &revs) != 200 || len(revs) != 2 {
		t.Fatalf("a refused apply wrote: %d revisions", len(revs))
	}
}
