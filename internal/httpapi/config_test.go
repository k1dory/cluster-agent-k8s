package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/bindings"
	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/connections"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/tenants"
)

const leaked = "ghp_SECRET_VALUE_42"

type limits struct {
	tenants  *tenants.Service
	bindings *bindings.Service
}

func (l limits) QuotaFor(tenant string) orchestrator.Quota {
	q := l.tenants.QuotaFor(tenant)
	return orchestrator.Quota{MaxSandboxes: q.MaxSandboxes, MaxAwake: q.MaxAwake}
}

func (l limits) SlugQuota(slug, tenant string) orchestrator.Quota {
	if b, ok := l.bindings.Active(slug, tenant); ok {
		return orchestrator.Quota{MaxSandboxes: b.MaxSandboxes, MaxAwake: b.MaxAwake}
	}
	return orchestrator.Quota{}
}

// configStack wires the step 2.2 services the way sandboxd does: guard over policies and
// bindings, quotas from tenant settings and bindings, connections over the secrets provider.
func configStack(t *testing.T) (*stack, *bindings.Guard) {
	t.Helper()
	s := newStack(t)
	ctx := context.Background()
	pols := policy.FromPolicies(
		&policy.Policy{Slug: "backend-dev", Tenants: []string{"alice"}, Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}},
	)
	pols.Strict = true
	st := s.orch.Store
	bind := bindings.New(st, pols)
	tset := tenants.New(st, func(tenant string) tenants.Quota {
		q := s.orch.Cfg.QuotaFor(tenant)
		return tenants.Quota{MaxSandboxes: q.MaxSandboxes, MaxAwake: q.MaxAwake}
	})
	if err := bind.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tset.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	guard := &bindings.Guard{Set: pols, Bindings: bind}
	s.orch.Policies, s.orch.Quotas, s.p.Policies = guard, limits{tset, bind}, pols
	s.orch.Cfg.Versions = map[string]string{"stable": "reg/agent:1.0"}
	conns := &connections.Service{Store: st, Secrets: secrets.Static{"alice/github": leaked, "bob/github": "bob-" + leaked}}
	s.p.Catalog = &catalog.Service{Store: st, Images: s.orch.Cfg, Policies: guard, Connections: conns, Tenants: tset}
	s.p.Connections, s.p.Bindings, s.p.TenantSettings = conns, bind, tset
	return s, guard
}

func TestConnectionsIsolationAndNoSecretLeak(t *testing.T) {
	s, _ := configStack(t)
	api := s.platform.URL
	conn := `{"spec":{"type":"http","host":"api.github.com","headers":{"Authorization":"Bearer secret:github","X-GitHub-Api-Version":"2022-11-28"}}}`
	if code, _ := putDoc(t, api, "alice-tok", "connections", "github", conn); code != 201 {
		t.Fatalf("alice connection: %d", code)
	}
	// A literal credential is refused and never echoed.
	resp, body := call(t, "PUT", api+"/v1/connections/leaky", "alice-tok", `{"spec":{"type":"http","host":"api.github.com","headers":{"Authorization":"Bearer `+leaked+`"}}}`, nil)
	if resp.StatusCode != 422 || strings.Contains(string(body), leaked) {
		t.Fatalf("literal credential: %d %s", resp.StatusCode, body)
	}
	// A reference the tenant cannot resolve is refused: carol has no github secret.
	s.p.Tenants["carol-tok"] = "carol"
	if code, _ := putDoc(t, api, "carol-tok", "connections", "github", conn); code != 422 {
		t.Fatalf("unresolvable reference: %d", code)
	}
	// Isolation: bob sees neither alice's connection nor her scope.
	if resp, _ := call(t, "GET", api+"/v1/connections/github", "bob-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("bob reading alice's connection: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/connections?tenant=alice", "bob-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob listing alice's scope: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "PUT", api+"/v1/connections/github", "bob-tok", `{"tenant":"alice","spec":{"type":"http","host":"api.github.com"}}`, nil); resp.StatusCode != 403 {
		t.Fatalf("bob writing into alice's scope: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "DELETE", api+"/v1/connections/github", "bob-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("bob deleting alice's connection: %d", resp.StatusCode)
	}
	// An agent names the connection; the stored reference is canonical and the sandbox, the
	// run and the trace carry no secret value anywhere.
	if code, _ := putDoc(t, api, "alice-tok", "environments", "py", `{"spec":{"image":"stable"}}`); code != 201 {
		t.Fatalf("environment: %d", code)
	}
	code, agent := putDoc(t, api, "alice-tok", "agents", "backend", `{"spec":{"policy":"backend-dev","environment":"py","connections":["github"]}}`)
	if code != 201 || !strings.Contains(string(agent.Spec), `"connections":["github"]`) {
		t.Fatalf("agent with connection: %d %s", code, agent.Spec)
	}
	if code, _ := putDoc(t, api, "alice-tok", "agents", "bad", `{"spec":{"policy":"backend-dev","environment":"py","connections":["missing"]}}`); code != 422 {
		t.Fatalf("unknown connection must be refused: %d", code)
	}
	resp, body = call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "shop", "owner": "alice", "agent_ref": "backend"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("sandbox: %d %s", resp.StatusCode, body)
	}
	var sb model.Sandbox
	_ = json.Unmarshal(body, &sb)
	for _, path := range []string{"/v1/connections", "/v1/connections/github", "/v1/connections/github/revisions", "/v1/agents/backend",
		"/v1/sandboxes/" + sb.ID, "/v1/sandboxes/" + sb.ID + "/runs", "/v1/trace", "/v1/trace?sandbox=" + sb.ID + "&type=all"} {
		resp, body := call(t, "GET", api+path, "alice-tok", nil, nil)
		if resp.StatusCode != 200 || strings.Contains(string(body), leaked) {
			t.Fatalf("GET %s: %d, leaked=%v", path, resp.StatusCode, strings.Contains(string(body), leaked))
		}
	}
	// Deleting the connection keeps its history (without values) and stops agents naming it.
	if resp, _ := call(t, "DELETE", api+"/v1/connections/github", "alice-tok", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	resp, body = call(t, "GET", api+"/v1/connections/github/revisions", "alice-tok", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "deleted_at") || strings.Contains(string(body), leaked) {
		t.Fatalf("history after delete: %d %s", resp.StatusCode, body)
	}
	if code, _ := putDoc(t, api, "alice-tok", "agents", "backend", `{"spec":{"policy":"backend-dev","environment":"py","connections":["github"]}}`); code != 422 {
		t.Fatalf("agent on a deleted connection: %d", code)
	}
}

func TestBindingsGrantRevokeRunningAgent(t *testing.T) {
	s, guard := configStack(t)
	api := s.platform.URL
	ctx := context.Background()
	// bob is not in the policy's tenants list: refused, and may not grant himself.
	resp, _ := call(t, "POST", api+"/v1/sandboxes", "bob-tok", map[string]any{"name": "b1", "owner": "bob", "slug": "backend-dev"}, nil)
	if resp.StatusCode != 403 {
		t.Fatalf("unbound tenant: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "PUT", api+"/v1/bindings/backend-dev", "bob-tok", `{"spec":{}}`, nil); resp.StatusCode != 403 {
		t.Fatalf("tenant writing a binding: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "PUT", api+"/v1/bindings/backend-dev", "t0k", `{"spec":{}}`, nil); resp.StatusCode != 422 {
		t.Fatalf("binding without a tenant: %d", resp.StatusCode)
	}
	// The admin binds the slug to bob with a per-slug limit.
	resp, body := call(t, "PUT", api+"/v1/bindings/backend-dev?tenant=bob", "t0k", `{"spec":{"max_sandboxes":1}}`, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("binding: %d %s", resp.StatusCode, body)
	}
	// bob reads his own bindings, nobody else's.
	if resp, body := call(t, "GET", api+"/v1/bindings", "bob-tok", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), `"backend-dev"`) {
		t.Fatalf("bob's bindings: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/bindings?tenant=bob", "alice-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("alice reading bob's bindings: %d", resp.StatusCode)
	}
	resp, body = call(t, "POST", api+"/v1/sandboxes", "bob-tok", map[string]any{"name": "b1", "owner": "bob", "slug": "backend-dev"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("bound tenant: %d %s", resp.StatusCode, body)
	}
	var sb model.Sandbox
	_ = json.Unmarshal(body, &sb)
	if resp, body := call(t, "POST", api+"/v1/sandboxes", "bob-tok", map[string]any{"name": "b2", "owner": "bob", "slug": "backend-dev"}, nil); resp.StatusCode != 429 {
		t.Fatalf("per-slug limit from the binding: %d %s", resp.StatusCode, body)
	}
	waitFor(t, func() bool { cur, _ := s.orch.Get(ctx, sb.ID); return cur.Status == model.StatusRunning })
	// The gateway decides with the same guard: allowed while the binding lives.
	az := &authz.Handler{Policies: guard, Secrets: secrets.Static{}}
	decide := func() int {
		r := httptest.NewRequest("GET", "/authz", nil)
		r.Header.Set(identity.HeaderSANs, "spiffe://sandbox/agent/backend-dev/1,spiffe://sandbox/tenant/bob,spiffe://sandbox/sandbox/"+sb.ID)
		r.Header.Set("X-Forwarded-Host", "api.github.com")
		r.Header.Set("X-Forwarded-Method", "GET")
		r.Header.Set("X-Forwarded-Uri", "/repos")
		w := httptest.NewRecorder()
		az.ServeHTTP(w, r)
		return w.Code
	}
	if decide() != 200 {
		t.Fatal("bound agent must pass the gateway")
	}
	// Revocation: the binding goes; the gateway refuses at once, the reconciler stops the pod,
	// new sandboxes are refused, the history keeps the grant.
	if resp, _ := call(t, "DELETE", api+"/v1/bindings/backend-dev?tenant=bob", "t0k", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete binding: %d", resp.StatusCode)
	}
	if decide() != 403 {
		t.Fatal("running agent must lose the gateway after revocation")
	}
	s.orch.Reconcile(ctx)
	if cur, _ := s.orch.Get(ctx, sb.ID); cur.Status != model.StatusSleeping {
		t.Fatalf("revoked agent must be stopped: %s", cur.Status)
	}
	if resp, _ := call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/wake", "bob-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("wake after revocation: %d", resp.StatusCode)
	}
	resp, body = call(t, "GET", api+"/v1/bindings/backend-dev/revisions?tenant=bob", "t0k", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "deleted_at") {
		t.Fatalf("binding history: %d %s", resp.StatusCode, body)
	}
	// An expiring binding revokes by itself.
	exp := time.Now().Add(150 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	if resp, body := call(t, "PUT", api+"/v1/bindings/backend-dev?tenant=bob", "t0k", `{"spec":{"expires_at":"`+exp+`"}}`, nil); resp.StatusCode != 200 {
		t.Fatalf("rebind: %d %s", resp.StatusCode, body)
	}
	if decide() != 200 {
		t.Fatal("rebound agent must pass")
	}
	time.Sleep(200 * time.Millisecond)
	if decide() != 403 {
		t.Fatal("expired binding must not grant")
	}
}

func TestTenantSettingsQuotaAndEnvironments(t *testing.T) {
	s, _ := configStack(t)
	api := s.platform.URL
	// Only the admin writes; a tenant reads its own and nobody else's.
	if resp, _ := call(t, "PUT", api+"/v1/tenants/bob/settings", "bob-tok", `{"spec":{"quota":{"max_sandboxes":100}}}`, nil); resp.StatusCode != 403 {
		t.Fatalf("tenant raising its own quota: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/tenants/alice/settings", "bob-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob reading alice's settings: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/tenants/bob/settings", "bob-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("defaults: %d", resp.StatusCode)
	}
	// bob's configured quota is 1; settings raise it to 2.
	if resp, body := call(t, "PUT", api+"/v1/tenants/bob/settings", "t0k", `{"spec":{"quota":{"max_sandboxes":2}}}`, nil); resp.StatusCode != 201 {
		t.Fatalf("settings: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "PUT", api+"/v1/tenants/bob/settings", "t0k", `{"tenant":"alice","spec":{}}`, nil); resp.StatusCode != 400 {
		t.Fatalf("body tenant must match the path: %d", resp.StatusCode)
	}
	if resp, body := call(t, "PUT", api+"/v1/bindings/backend-dev?tenant=bob", "t0k", `{"spec":{}}`, nil); resp.StatusCode != 201 {
		t.Fatalf("binding: %d %s", resp.StatusCode, body)
	}
	for i, want := range []int{201, 201, 429} {
		resp, body := call(t, "POST", api+"/v1/sandboxes", "bob-tok", map[string]any{"name": "q" + string(rune('a'+i)), "owner": "bob", "slug": "backend-dev"}, nil)
		if resp.StatusCode != want {
			t.Fatalf("sandbox %d: %d %s", i, resp.StatusCode, body)
		}
	}
	if resp, body := call(t, "GET", api+"/v1/tenants/bob/settings", "bob-tok", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), `"max_sandboxes":2`) {
		t.Fatalf("bob reads his settings: %d %s", resp.StatusCode, body)
	}
	// Allowed environments: alice's agents may only use the shared base.
	if code, _ := putDoc(t, api, "t0k", "environments", "base", `{"spec":{"image":"stable"}}`); code != 201 {
		t.Fatal("shared environment")
	}
	if code, _ := putDoc(t, api, "alice-tok", "environments", "py", `{"spec":{"image":"stable"}}`); code != 201 {
		t.Fatal("alice environment")
	}
	if code, _ := putDoc(t, api, "alice-tok", "agents", "free", `{"spec":{"policy":"backend-dev","environment":"py"}}`); code != 201 {
		t.Fatal("agent before the restriction")
	}
	if resp, body := call(t, "PUT", api+"/v1/tenants/alice/settings", "t0k", `{"spec":{"environments":["shared/base"]}}`, nil); resp.StatusCode != 201 {
		t.Fatalf("alice settings: %d %s", resp.StatusCode, body)
	}
	if code, _ := putDoc(t, api, "alice-tok", "agents", "own", `{"spec":{"policy":"backend-dev","environment":"py"}}`); code != 403 {
		t.Fatalf("agent on a disallowed environment: %d", code)
	}
	if code, _ := putDoc(t, api, "alice-tok", "agents", "ok", `{"spec":{"policy":"backend-dev","environment":"base"}}`); code != 201 {
		t.Fatalf("agent on the allowed shared environment: %d", code)
	}
	// An agent written before the restriction does not keep the environment it lost.
	if resp, body := call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "f", "owner": "alice", "agent_ref": "free"}, nil); resp.StatusCode != 403 {
		t.Fatalf("creation on a disallowed environment: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "o", "owner": "alice", "agent_ref": "ok"}, nil); resp.StatusCode != 201 {
		t.Fatalf("creation on the allowed environment: %d %s", resp.StatusCode, body)
	}
	// Reset: defaults again, history kept.
	if resp, _ := call(t, "DELETE", api+"/v1/tenants/alice/settings", "t0k", nil, nil); resp.StatusCode != 204 {
		t.Fatal("reset")
	}
	if code, _ := putDoc(t, api, "alice-tok", "agents", "own", `{"spec":{"policy":"backend-dev","environment":"py"}}`); code != 201 {
		t.Fatalf("after reset: %d", code)
	}
	if resp, body := call(t, "GET", api+"/v1/tenants/alice/settings/revisions", "alice-tok", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), "deleted_at") {
		t.Fatalf("settings history: %d %s", resp.StatusCode, body)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
