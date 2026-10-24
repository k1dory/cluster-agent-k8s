package authz

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestPartialSecretsLeakNothing: a rule injecting two secrets of which the second is missing
// must answer 502 without the first one on the response.
func TestPartialSecretsLeakNothing(t *testing.T) {
	h := &Handler{
		Policies: policy.FromPolicies(&policy.Policy{Slug: "s", Allow: []policy.Rule{
			{Host: "two.example.com", Paths: []string{"/**"}, Inject: map[string]string{"Authorization": "Bearer secret:present", "X-Second": "secret:missing"}},
		}}),
		Secrets: secrets.Static{"shared/present": "LEAK-IF-SEEN"},
	}
	san := "spiffe://sandbox/agent/s/1,spiffe://sandbox/tenant/u1,spiffe://sandbox/sandbox/sb1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(san, "two.example.com", "GET", "/"))
	if w.Code != 502 {
		t.Fatalf("missing secret must be 502, got %d", w.Code)
	}
	for name := range w.Header() {
		if name == "Authorization" || name == "X-Second" || name == HeaderSlug {
			t.Fatalf("denied response must carry no verdict headers, got %v", w.Header())
		}
	}
}

// TestOwnershipRevoked: once a policy's tenants list excludes the tenant, a running agent is
// refused on the next request even though its certificate and the host rule are fine.
func TestOwnershipRevoked(t *testing.T) {
	h := &Handler{Policies: policy.FromPolicies(&policy.Policy{Slug: "s", Tenants: []string{"other"}, Allow: []policy.Rule{
		{Host: "git.example.com", Paths: []string{"/**"}},
	}})}
	san := "spiffe://sandbox/agent/s/1,spiffe://sandbox/tenant/u1,spiffe://sandbox/sandbox/sb1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(san, "git.example.com", "GET", "/x"))
	if w.Code != 403 || !strings.Contains(w.Body.String(), "no longer owns") {
		t.Fatalf("revoked ownership must be denied: %d %s", w.Code, w.Body.String())
	}
}
