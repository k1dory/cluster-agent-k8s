package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
)

func TestReviewConnectionHeadersReachGatewayDecision(t *testing.T) {
	s, guard := configStack(t)
	api := s.platform.URL
	for _, doc := range []struct{ kind, name, body string }{
		{"connections", "review", `{"spec":{"type":"http","host":"api.github.com","headers":{"X-Review-Connection":"fixture"}}}`},
		{"environments", "review", `{"spec":{"image":"stable"}}`},
		{"agents", "review", `{"spec":{"policy":"backend-dev","environment":"review","connections":["review"]}}`},
	} {
		if code, _ := putDoc(t, api, "alice-tok", doc.kind, doc.name, doc.body); code != http.StatusCreated {
			t.Fatalf("create %s: HTTP %d", doc.kind, code)
		}
	}
	resp, body := call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "review", "owner": "alice", "agent_ref": "review"}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("sandbox: HTTP %d", resp.StatusCode)
	}
	var sb model.Sandbox
	if err := json.Unmarshal(body, &sb); err != nil {
		t.Fatal(err)
	}
	// Match sandboxd's decision wiring. The request is evaluated locally: no upstream call.
	az := &authz.Handler{Policies: guard, Secrets: s.p.Connections.Secrets, Toucher: s.orch, Recorder: s.orch}
	r := httptest.NewRequest(http.MethodGet, "/authz", nil)
	r.Header.Set(identity.HeaderSANs, "spiffe://sandbox/agent/backend-dev/1,spiffe://sandbox/tenant/alice,spiffe://sandbox/sandbox/"+sb.ID)
	d := az.Decide(t.Context(), r, "api.github.com", http.MethodGet, "/repos")
	if !d.Allowed() {
		t.Fatalf("fixture: policy must permit the request: %s", d.Reason)
	}
	if d.Headers["X-Review-Connection"] != "fixture" {
		t.Fatal("the agent's configured Connection does not contribute its header to the gateway decision")
	}
}

func TestReviewEnvironmentRestrictionCoversLegacyCreate(t *testing.T) {
	s, _ := configStack(t)
	api := s.platform.URL
	if code, _ := putDoc(t, api, "t0k", "environments", "approved", `{"spec":{"image":"stable"}}`); code != http.StatusCreated {
		t.Fatal("shared environment fixture")
	}
	resp, _ := call(t, "PUT", api+"/v1/tenants/alice/settings", "t0k", `{"spec":{"environments":["shared/approved"]}}`, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("settings: HTTP %d", resp.StatusCode)
	}
	resp, _ = call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "legacy", "owner": "alice", "slug": "backend-dev"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a restricted tenant must not launch an unlisted default environment through legacy creation: HTTP %d", resp.StatusCode)
	}
}
