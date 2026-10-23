package authz

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
)

func req(san, host, method, uri string) *http.Request {
	r := httptest.NewRequest("GET", "/authz", nil)
	r.Header.Set(identity.HeaderSANs, san)
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Method", method)
	r.Header.Set("X-Forwarded-Uri", uri)
	return r
}

func TestAuthz(t *testing.T) {
	h := &Handler{
		Policies: policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Allow: []policy.Rule{
			{Host: "api.anthropic.com", Paths: []string{"/v1/**"}, Inject: map[string]string{"X-Api-Key": "secret:anthropic"}},
			{Host: "git.example.com", Paths: []string{"/*/*/info/refs", "/*/*/git-upload-pack"}, Inject: map[string]string{"Authorization": "Bearer secret:forgejo"}},
			{Host: "mcp.example.com", Paths: []string{"/mcp"}, MCP: &policy.MCPRule{ReadOnly: true}},
		}}),
		Secrets: secrets.Static{"u1/anthropic": "sk-ant-TENANT", "shared/forgejo": "forgejo-shared"},
	}
	san := "spiffe://sandbox/agent/backend-dev/5,spiffe://sandbox/tenant/u1,spiffe://sandbox/sandbox/sb1"

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(san, "api.anthropic.com", "POST", "/v1/messages"))
	if w.Code != 200 || w.Header().Get("X-Api-Key") != "sk-ant-TENANT" {
		t.Fatalf("anthropic: code %d key %q", w.Code, w.Header().Get("X-Api-Key"))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req(san, "git.example.com", "GET", "/org/repo.git/info/refs?service=git-upload-pack"))
	if w.Code != 200 || w.Header().Get("Authorization") != "Bearer forgejo-shared" {
		t.Fatalf("git: code %d auth %q", w.Code, w.Header().Get("Authorization"))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req(san, "git.example.com", "POST", "/org/repo.git/git-receive-pack"))
	if w.Code != 403 {
		t.Fatalf("push must be denied, got %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req(san, "mcp.example.com", "POST", "/mcp"))
	if w.Code != 200 || w.Header().Get(HeaderAccess) != "read-only" {
		t.Fatalf("mcp: code %d access %q", w.Code, w.Header().Get(HeaderAccess))
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req("", "api.anthropic.com", "POST", "/v1/messages"))
	if w.Code != 403 {
		t.Fatalf("no identity must be denied, got %d", w.Code)
	}
}
