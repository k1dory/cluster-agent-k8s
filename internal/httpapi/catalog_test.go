package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/policy"
)

// catalogStack is newStack plus the catalogue, a version catalogue and tenant-owned policies.
func catalogStack(t *testing.T) *stack {
	t.Helper()
	s := newStack(t)
	pols := policy.FromPolicies(
		&policy.Policy{Slug: "backend-dev", Tenants: []string{"alice"}, Allow: []policy.Rule{{Host: "api.anthropic.com", Paths: []string{"/v1/**"}}}},
		&policy.Policy{Slug: "netops", Tenants: []string{"*"}, Allow: []policy.Rule{{Host: "netbox.example.com", Paths: []string{"/api/**"}}}},
	)
	s.orch.Policies, s.p.Policies = pols, pols
	s.orch.Cfg.DefaultAgentVersion = "reg/agent:1.0"
	s.orch.Cfg.Versions = map[string]string{"stable": "reg/agent:1.0", "py": "reg/agent-py:2.0"}
	s.orch.Cfg.EnvVersion = func(sb *model.Sandbox) string {
		if sb.Launch == nil {
			return "bare"
		}
		b, _ := json.Marshal(sb.Launch)
		return "launch-" + string(b[len(b)-8:])
	}
	s.p.Catalog = &catalog.Service{Store: s.orch.Store, Images: s.orch.Cfg, Policies: pols}
	return s
}

func putDoc(t *testing.T, api, token, kind, name, body string) (int, model.CatalogItem) {
	t.Helper()
	resp, raw := call(t, "PUT", api+"/v1/"+kind+"/"+name, token, body, nil)
	var it model.CatalogItem
	_ = json.Unmarshal(raw, &it)
	if resp.StatusCode >= 300 {
		t.Logf("PUT %s/%s: %d %s", kind, name, resp.StatusCode, raw)
	}
	return resp.StatusCode, it
}

func waitRunning(t *testing.T, api, token, id string) model.Sandbox {
	t.Helper()
	var sb model.Sandbox
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, body := call(t, "GET", api+"/v1/sandboxes/"+id, token, nil, nil)
		_ = json.Unmarshal(body, &sb)
		if sb.Status == model.StatusRunning {
			return sb
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("sandbox %s not running: %+v", id, sb)
	return sb
}

func TestCatalogAcceptance(t *testing.T) {
	s := catalogStack(t)
	api := s.platform.URL

	// --- two environments, two agents, really different launch parameters -------------------
	code, env1 := putDoc(t, api, "alice-tok", "environments", "py", `{"spec":{"image":"py","harness":{"command":"codex exec \"$SANDBOX_TASK\" --json"},
		"model":{"name":"claude-opus-5-5"},"resources":{"cpu_limit":"3","memory_limit":"6Gi","volume_size":"20Gi"},"lifecycle":{"idle_timeout":120,"ttl":3600},
		"env":{"PIP_INDEX_URL":"https://pypi.example.com"}}}`)
	if code != 201 || env1.Revision != 1 || env1.Tenant != "alice" {
		t.Fatalf("environment: %d %+v", code, env1)
	}
	if code, _ := putDoc(t, api, "alice-tok", "environments", "lean", `{"spec":{"image":"stable","resources":{"cpu_limit":"1"}}}`); code != 201 {
		t.Fatalf("second environment: %d", code)
	}
	if code, _ := putDoc(t, api, "alice-tok", "agents", "backend", `{"spec":{"policy":"backend-dev","environment":"py","repo":"https://git.example.com/org/shop.git","instructions":"Be brief."}}`); code != 201 {
		t.Fatalf("agent: %d", code)
	}
	if code, _ := putDoc(t, api, "alice-tok", "agents", "lean", `{"spec":{"policy":"backend-dev","environment":"lean"}}`); code != 201 {
		t.Fatalf("agent 2: %d", code)
	}
	// Same document shape as the YAML files: kind must match the endpoint, unknown fields refused.
	if code, _ := putDoc(t, api, "alice-tok", "agents", "x", `{"kind":"EnvironmentProfile","spec":{"policy":"backend-dev","environment":"py"}}`); code != 422 {
		t.Fatalf("kind mismatch: %d", code)
	}
	if code, _ := putDoc(t, api, "alice-tok", "environments", "x", `{"spec":{"image":"stable","imag":"typo"}}`); code != 422 {
		t.Fatalf("typo must be refused: %d", code)
	}
	if code, _ := putDoc(t, api, "alice-tok", "environments", "x", `{"spec":{"image":"reg/evil:1"}}`); code != 422 {
		t.Fatalf("tenant naming an image reference: %d", code)
	}

	resp, body := call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "shop", "owner": "alice", "agent_ref": "backend"}, nil)
	var sb1 model.Sandbox
	_ = json.Unmarshal(body, &sb1)
	if resp.StatusCode != 201 || sb1.Slug != "backend-dev" || sb1.Repo != "https://git.example.com/org/shop.git" || sb1.IdleTimeout != 120 || sb1.ExpiresAt == nil ||
		sb1.AgentRef != "backend" || sb1.AgentRevision != 1 || sb1.EnvironmentRef != "py" || sb1.EnvironmentRevision != 1 ||
		sb1.AgentVersion != "reg/agent-py:2.0" || sb1.Launch == nil || sb1.Launch.CPULimit != "3" || sb1.Launch.Instructions != "Be brief." {
		t.Fatalf("sandbox from agent_ref: %d %+v", resp.StatusCode, sb1)
	}
	resp, body = call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "lean", "owner": "alice", "agent_ref": "lean", "idle_timeout": 5}, nil)
	var sb2 model.Sandbox
	_ = json.Unmarshal(body, &sb2)
	if resp.StatusCode != 201 || sb2.AgentVersion != "reg/agent:1.0" || sb2.Launch.CPULimit != "1" || sb2.IdleTimeout != 5 || sb2.Launch.Model != "" {
		t.Fatalf("second agent runs with its own settings: %d %+v", resp.StatusCode, sb2)
	}
	sb1, sb2 = waitRunning(t, api, "alice-tok", sb1.ID), waitRunning(t, api, "alice-tok", sb2.ID)
	l1, l2 := s.rt.LaunchOf(sb1.ID), s.rt.LaunchOf(sb2.ID)
	if l1 == nil || l2 == nil || l1.HarnessCommand == l2.HarnessCommand || l1.Image == l2.Image || sb1.EnvVersion == sb2.EnvVersion {
		t.Fatalf("pods must start with their environment's parameters: %+v / %+v", l1, l2)
	}
	if resp, _ := call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "bad", "owner": "alice", "agent_ref": "backend", "slug": "netops"}, nil); resp.StatusCode != 422 {
		t.Fatalf("slug conflicting with the agent's policy: %d", resp.StatusCode)
	}

	// --- a run records the revisions; changing the definition afterwards changes nothing ------
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb1.ID+"/runs", "alice-tok", map[string]string{"task": "add tests"}, nil)
	var run model.Run
	_ = json.Unmarshal(body, &run)
	if resp.StatusCode != 202 {
		t.Fatalf("run: %d %s", resp.StatusCode, body)
	}
	claimed, err := s.orch.NextRun(t.Context(), sb1.ID, time.Second)
	if err != nil || claimed.AgentRef != "backend" || claimed.AgentRevision != 1 || claimed.EnvironmentRef != "py" || claimed.EnvironmentRevision != 1 || claimed.AgentVersion != "reg/agent-py:2.0" {
		t.Fatalf("claimed run must carry the revisions: %v %+v", err, claimed)
	}
	if code, env2 := putDoc(t, api, "alice-tok", "environments", "py", `{"spec":{"image":"stable","resources":{"cpu_limit":"8"}}}`); code != 200 || env2.Revision != 2 {
		t.Fatalf("environment update: %d %+v", code, env2)
	}
	if code, a2 := putDoc(t, api, "alice-tok", "agents", "backend", `{"spec":{"policy":"backend-dev","environment":"py","instructions":"Be verbose."}}`); code != 200 || a2.Revision != 2 {
		t.Fatalf("agent update: %d %+v", code, a2)
	}
	_, body = call(t, "GET", api+"/v1/sandboxes/"+sb1.ID+"/runs/"+run.ID, "alice-tok", nil, nil)
	var again model.Run
	_ = json.Unmarshal(body, &again)
	if again.AgentRevision != 1 || again.EnvironmentRevision != 1 || again.AgentVersion != "reg/agent-py:2.0" {
		t.Fatalf("a run in progress must not follow catalogue changes: %+v", again)
	}
	_, body = call(t, "GET", api+"/v1/sandboxes/"+sb1.ID, "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &sb1)
	if sb1.AgentRevision != 1 || sb1.EnvironmentRevision != 1 || sb1.Launch.CPULimit != "3" || sb1.Launch.Instructions != "Be brief." {
		t.Fatalf("the sandbox keeps the revisions it was built from: %+v", sb1)
	}
	// A new sandbox from the same reference gets the new revisions.
	resp, body = call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "shop2", "owner": "alice", "agent_ref": "backend"}, nil)
	var sb3 model.Sandbox
	_ = json.Unmarshal(body, &sb3)
	if resp.StatusCode != 201 || sb3.AgentRevision != 2 || sb3.EnvironmentRevision != 2 || sb3.Launch.CPULimit != "8" || sb3.AgentVersion != "reg/agent:1.0" {
		t.Fatalf("new sandbox follows the latest revisions: %+v", sb3)
	}
	// Pinned reference.
	resp, body = call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "shop1", "owner": "alice", "agent_ref": "backend@1"}, nil)
	var sb4 model.Sandbox
	_ = json.Unmarshal(body, &sb4)
	if resp.StatusCode != 201 || sb4.AgentRevision != 1 || sb4.EnvironmentRevision != 2 {
		t.Fatalf("agent@1 with the environment's latest revision: %+v", sb4)
	}

	// --- conflicting updates: optimistic concurrency ----------------------------------------
	if code, _ := putDoc(t, api, "alice-tok", "environments", "lean", `{"expected_revision":1,"spec":{"image":"stable","resources":{"cpu_limit":"2"}}}`); code != 200 {
		t.Fatalf("first writer: %d", code)
	}
	code, _ = putDoc(t, api, "alice-tok", "environments", "lean", `{"expected_revision":1,"spec":{"image":"stable","resources":{"cpu_limit":"4"}}}`)
	if code != 409 {
		t.Fatalf("second writer from a stale revision must get 409, got %d", code)
	}
	if code, _ := putDoc(t, api, "alice-tok", "environments", "brand-new", `{"expected_revision":0,"spec":{"image":"stable"}}`); code != 201 {
		t.Fatalf("create-only: %d", code)
	}
	if code, _ := putDoc(t, api, "alice-tok", "environments", "brand-new", `{"expected_revision":0,"spec":{"image":"stable"}}`); code != 409 {
		t.Fatalf("create-only on an existing item: %d", code)
	}
	resp, body = call(t, "GET", api+"/v1/environments/lean/revisions", "alice-tok", nil, nil)
	var revs []model.CatalogItem
	_ = json.Unmarshal(body, &revs)
	if resp.StatusCode != 200 || len(revs) != 2 {
		t.Fatalf("revisions: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "GET", api+"/v1/environments/lean?revision=1", "alice-tok", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), `"cpu_limit":"1"`) {
		t.Fatalf("old revision: %d %s", resp.StatusCode, body)
	}

	// --- tenant isolation --------------------------------------------------------------------
	for _, path := range []string{"/v1/agents/backend", "/v1/environments/py", "/v1/agents/backend/revisions"} {
		if resp, _ := call(t, "GET", api+path, "bob-tok", nil, nil); resp.StatusCode != 404 {
			t.Fatalf("bob reading alice's %s: %d", path, resp.StatusCode)
		}
	}
	if resp, _ := call(t, "POST", api+"/v1/sandboxes", "bob-tok", map[string]any{"name": "steal", "owner": "bob", "agent_ref": "backend"}, nil); resp.StatusCode != 404 {
		t.Fatalf("bob creating from alice's agent: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/agents?tenant=alice", "bob-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob listing alice's scope: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "PUT", api+"/v1/environments/mine", "bob-tok", `{"tenant":"alice","spec":{"image":"stable"}}`, nil); resp.StatusCode != 403 {
		t.Fatalf("bob writing into alice's scope: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "DELETE", api+"/v1/environments/py", "bob-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("bob deleting alice's environment: %d", resp.StatusCode)
	}
	// bob may not define an agent on alice's policy; netops is open to everyone.
	if code, _ := putDoc(t, api, "bob-tok", "environments", "py", `{"spec":{"image":"stable"}}`); code != 201 {
		t.Fatalf("bob's own environment named like alice's: %d", code)
	}
	if code, _ := putDoc(t, api, "bob-tok", "agents", "sneaky", `{"spec":{"policy":"backend-dev","environment":"py"}}`); code != 403 {
		t.Fatalf("bob on alice's policy: %d", code)
	}
	if code, _ := putDoc(t, api, "bob-tok", "agents", "net", `{"spec":{"policy":"netops","environment":"py"}}`); code != 201 {
		t.Fatalf("bob on an open policy: %d", code)
	}
	// Shared items (admin, tenant "") are visible to every tenant and usable by their agents.
	if code, _ := putDoc(t, api, "t0k", "environments", "base", `{"spec":{"image":"reg/custom:7","harness":{"command":"claude -p \"$SANDBOX_TASK\""}}}`); code != 201 {
		t.Fatalf("admin shared environment: %d", code)
	}
	if code, _ := putDoc(t, api, "t0k", "agents", "generic", `{"spec":{"policy":"netops","environment":"base"}}`); code != 201 {
		t.Fatalf("admin shared agent: %d", code)
	}
	resp, body = call(t, "GET", api+"/v1/environments", "bob-tok", nil, nil)
	var list []model.CatalogItem
	_ = json.Unmarshal(body, &list)
	if resp.StatusCode != 200 || len(list) != 2 { // bob's py + shared base
		t.Fatalf("bob's view: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "POST", api+"/v1/sandboxes", "bob-tok", map[string]any{"name": "gen", "owner": "bob", "agent_ref": "generic"}, nil)
	var sb5 model.Sandbox
	_ = json.Unmarshal(body, &sb5)
	if resp.StatusCode != 201 || sb5.AgentVersion != "reg/custom:7" || sb5.Slug != "netops" {
		t.Fatalf("shared agent for a tenant: %d %+v", resp.StatusCode, sb5)
	}
	// The admin works in a tenant's scope with ?tenant=.
	if resp, _ := call(t, "GET", api+"/v1/agents/backend?tenant=alice", "t0k", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("admin in alice's scope: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/agents/backend", "t0k", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("admin default scope is shared: %d", resp.StatusCode)
	}

	// --- persistence: a fresh control plane over the same store sees everything ----------------
	p2 := &Platform{Orch: orchestrator.New(s.orch.Store, s.rt, nil, s.orch.Hub, s.orch.Cfg, nil), Hub: s.orch.Hub, Policies: s.p.Policies,
		Catalog: &catalog.Service{Store: s.orch.Store, Images: s.orch.Cfg, Policies: s.p.Policies}, Token: "t0k", Tenants: map[string]string{"alice-tok": "alice"}}
	p2.Orch.Policies = s.orch.Policies
	srv2 := httptest.NewServer(p2.Routes())
	defer srv2.Close()
	resp, body = call(t, "GET", srv2.URL+"/v1/agents/backend", "alice-tok", nil, nil)
	var it model.CatalogItem
	_ = json.Unmarshal(body, &it)
	if resp.StatusCode != 200 || it.Revision != 2 {
		t.Fatalf("after restart: %d %s", resp.StatusCode, body)
	}
	_, body = call(t, "GET", srv2.URL+"/v1/sandboxes/"+sb1.ID, "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &sb1)
	if sb1.Launch == nil || sb1.Launch.CPULimit != "3" || sb1.AgentRevision != 1 {
		t.Fatalf("sandbox launch after restart: %+v", sb1)
	}
	resp, body = call(t, "POST", srv2.URL+"/v1/sandboxes", "alice-tok", map[string]any{"name": "after", "owner": "alice", "agent_ref": "backend"}, nil)
	if resp.StatusCode != 201 || !strings.Contains(string(body), `"agent_revision":2`) {
		t.Fatalf("create after restart: %d %s", resp.StatusCode, body)
	}
	_ = http.StatusOK
}
