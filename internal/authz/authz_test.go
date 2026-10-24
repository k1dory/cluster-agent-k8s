package authz

import (
	"context"
	"errors"
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

// withConnections is a policy set whose connections answer for hosts the repository lacks.
type withConnections struct {
	*policy.Set
	rules map[string]*policy.Rule // sandbox|host → rule
}

func (w withConnections) RuleFor(_ context.Context, sandboxID, _, host, _, reqPath string) (*policy.Rule, bool, error) {
	if sandboxID == "fail" {
		return nil, false, errors.New("store down")
	}
	r, ok := w.rules[sandboxID+"|"+host]
	if ok && !policy.PathMatch(r.Paths[0], reqPath) {
		return nil, false, nil
	}
	return r, ok, nil
}

func TestConnectionRuleWhenTheRepositoryHasNone(t *testing.T) {
	pols := policy.FromPolicies(&policy.Policy{Slug: "s", Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}, Inject: map[string]string{"X-Policy": "p"}}}})
	h := &Handler{Policies: withConnections{Set: pols, rules: map[string]*policy.Rule{
		"sb1|tools.example.com": {Host: "tools.example.com", Paths: []string{"/mcp/**"}, MCP: &policy.MCPRule{ReadOnly: true}},
		"sb1|api.github.com":    {Host: "api.github.com", Paths: []string{"/**"}}, // never consulted: the repository has it
	}}, Secrets: secrets.Static{}}
	decide := func(sandbox, host, p string) *Decision {
		san := "spiffe://sandbox/agent/s/1,spiffe://sandbox/tenant/acme,spiffe://sandbox/sandbox/" + sandbox
		return h.Decide(context.Background(), req(san, host, "POST", p), host, "POST", p)
	}
	if d := decide("sb1", "tools.example.com", "/mcp"); !d.Allowed() || d.Headers[HeaderAccess] != "read-only" || d.Rule.MCP == nil {
		t.Fatalf("connection host: %+v", d)
	}
	if d := decide("sb1", "tools.example.com", "/admin"); d.Allowed() || d.Code != 403 {
		t.Fatalf("outside the connection's paths: %+v", d)
	}
	if d := decide("sb2", "tools.example.com", "/mcp"); d.Allowed() || d.Code != 403 || !strings.Contains(d.Reason, "no rule") {
		t.Fatalf("sandbox without the connection: %+v", d)
	}
	if d := decide("sb1", "api.github.com", "/x"); !d.Allowed() || d.Headers["X-Policy"] != "p" {
		t.Fatalf("repository host keeps the repository's rule: %+v", d)
	}
	if d := decide("fail", "tools.example.com", "/mcp"); d.Allowed() || d.Code != 502 {
		t.Fatalf("a failing lookup is 502, never an allow: %+v", d)
	}
}
