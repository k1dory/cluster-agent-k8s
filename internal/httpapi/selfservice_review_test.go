package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
)

func TestReviewHostDelegationRevokesExistingConnection(t *testing.T) {
	s, guard := configStack(t)
	api := s.platform.URL
	const host = "tools.review.example.com"
	if resp, _ := call(t, "PUT", api+"/v1/tenants/alice/settings", "t0k", `{"spec":{"hosts":["tools.review.example.com"]}}`, nil); resp.StatusCode != 201 {
		t.Fatal("host delegation fixture")
	}
	if resp, _ := call(t, "PUT", api+"/v1/connections/review", "alice-tok", `{"spec":{"type":"mcp","host":"tools.review.example.com","paths":["/mcp"],"mcp":{"read_only":true}}}`, nil); resp.StatusCode != 201 {
		t.Fatal("connection fixture")
	}
	sb := &model.Sandbox{ID: "sb_review_hosts", Name: "review", Tenant: "alice", Slug: "backend-dev", Status: model.StatusRunning, Connections: []string{"review"}}
	if err := s.orch.Store.CreateSandbox(t.Context(), sb); err != nil {
		t.Fatal(err)
	}
	az := &authz.Handler{Policies: guard, Secrets: s.p.Connections.Secrets}
	decide := func() bool {
		r := httptest.NewRequest(http.MethodGet, "/authz", nil)
		r.Header.Set(identity.HeaderSANs, "spiffe://sandbox/agent/backend-dev/1,spiffe://sandbox/tenant/alice,spiffe://sandbox/sandbox/"+sb.ID)
		return az.Decide(t.Context(), r, host, http.MethodPost, "/mcp").Allowed()
	}
	if !decide() {
		t.Fatal("delegated connection must initially be usable")
	}
	if resp, _ := call(t, "PUT", api+"/v1/tenants/alice/settings", "t0k", `{"spec":{"hosts":[]}}`, nil); resp.StatusCode != 200 {
		t.Fatal("withdraw host delegation")
	}
	if s.p.TenantSettings.HostAllowed("alice", host) {
		t.Fatal("settings snapshot did not update")
	}
	if decide() {
		t.Error("withdrawing host delegation must deny the existing sandbox's next decision")
	}
	if _, present := guard.HostInfo(host); present {
		t.Error("a host with no remaining delegation must leave the gateway host set")
	}
}

func TestReviewConnectionPlanUsesSameHostPolicyAsPut(t *testing.T) {
	for _, tc := range []struct {
		name, spec string
		putCode    int
		planValid  bool
	}{
		{"allowed_mcp", `{"type":"mcp","host":"tools.review.example.com","upstream":"https://tools.review.example.com","paths":["/mcp"],"mcp":{"read_only":true}}`, 201, true},
		{"undelegated_host", `{"type":"http","host":"other.review.example.com"}`, 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := configStack(t)
			api := s.platform.URL
			if resp, _ := call(t, "PUT", api+"/v1/tenants/alice/settings", "t0k", `{"spec":{"hosts":["tools.review.example.com"]}}`, nil); resp.StatusCode != 201 {
				t.Fatal("host delegation fixture")
			}
			doc := map[string]any{"kind": model.KindConnection, "name": "review", "spec": json.RawMessage(tc.spec)}
			if resp, _ := call(t, "PUT", api+"/v1/connections/review", "alice-tok", doc, nil); resp.StatusCode != tc.putCode {
				t.Fatalf("direct write: got HTTP %d, want %d", resp.StatusCode, tc.putCode)
			}
			resp, body := call(t, "POST", api+"/v1/plan", "alice-tok", map[string]any{"documents": []any{doc}}, nil)
			var p plan.Plan
			if resp.StatusCode != 200 || json.Unmarshal(body, &p) != nil {
				t.Fatalf("plan request failed: HTTP %d", resp.StatusCode)
			}
			if p.Valid != tc.planValid {
				t.Errorf("plan must use the same host policy as direct PUT: valid=%v want=%v", p.Valid, tc.planValid)
			}
		})
	}
}
