package authz

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/credentials"
	"agent-sandbox/internal/gateway"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// A Claude subscription through the gateway, as the shipped example policy sets it up: the
// tenant's own credential (a `claude setup-token` token) becomes the Authorization header of
// the decision, nothing else is injected, and the rendered gateway strips the agent's
// Authorization (the placeholder Claude Code sends) while it leaves anthropic-beta (the
// oauth-2025-04-20 beta Claude Code sends with an OAuth token) alone.
func TestClaudeSubscriptionTokenReplacesThePlaceholder(t *testing.T) {
	pols, err := policy.Load("../../examples/policies")
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewMemory()
	creds, err := credentials.New(st, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	const token = "sk-ant-oat01-REAL-SUBSCRIPTION-TOKEN"
	if _, _, err := creds.Put(context.Background(), "acme", "claude-oauth", token, "alice"); err != nil {
		t.Fatal(err)
	}
	h := &Handler{Policies: pols, Secrets: secrets.Chain{credentials.Resolver{Service: creds}}}
	san := "spiffe://sandbox/agent/llm-subscriptions/1,spiffe://sandbox/tenant/acme,spiffe://sandbox/sandbox/sb1"

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req(san, "api.anthropic.com", "POST", "/v1/messages?beta=true"))
	if w.Code != 200 || w.Header().Get("Authorization") != "Bearer "+token {
		t.Fatalf("decision: %d Authorization=%q", w.Code, w.Header().Get("Authorization"))
	}
	for _, name := range []string{"X-Api-Key", "Anthropic-Beta"} {
		if v := w.Header().Get(name); v != "" {
			t.Fatalf("%s must not be injected (the agent's own is kept): %q", name, v)
		}
	}
	// Another tenant has no such credential: refused at the gateway, nothing sent.
	other := strings.Replace(san, "tenant/acme", "tenant/other", 1)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req(other, "api.anthropic.com", "POST", "/v1/messages"))
	if w.Code != 502 || w.Header().Get("Authorization") != "" {
		t.Fatalf("a tenant without the credential: %d %q", w.Code, w.Header().Get("Authorization"))
	}

	// The gateway side of the swap: the agent's Authorization is stripped and the decision's
	// copied; anthropic-beta is neither, so the agent's value travels as it was sent.
	c, _ := ca.Generate("t", time.Hour)
	cf, err := gateway.Render(gateway.Config{IP: "10.77.77.1", SandboxdAddr: "127.0.0.1:8081"}, pols.Hosts(), c.PEM())
	if err != nil {
		t.Fatal(err)
	}
	site := cf[strings.Index(cf, "api.anthropic.com {"):]
	site = site[:strings.Index(site, "reverse_proxy")]
	if !strings.Contains(site, "request_header -Authorization") || !strings.Contains(site, "copy_headers") || !strings.Contains(site[strings.Index(site, "copy_headers"):], "Authorization") {
		t.Fatalf("the site must strip and copy Authorization:\n%s", site)
	}
	if strings.Contains(strings.ToLower(site), "anthropic-beta") {
		t.Fatalf("the site must leave anthropic-beta to the agent:\n%s", site)
	}
}
