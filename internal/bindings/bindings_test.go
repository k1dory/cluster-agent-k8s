package bindings

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

func TestBindingsGrantAndRevoke(t *testing.T) {
	ctx := context.Background()
	pols := policy.FromPolicies(
		&policy.Policy{Slug: "backend-dev", Tenants: []string{"alice"}, Allow: []policy.Rule{{Host: "h.example.com", Paths: []string{"/"}}}},
		&policy.Policy{Slug: "locked", Allow: []policy.Rule{{Host: "h.example.com", Paths: []string{"/"}}}},
	)
	pols.Strict = true
	now := time.Now()
	s := New(store.NewMemory(), pols)
	s.Now = func() time.Time { return now }
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	g := &Guard{Set: pols, Bindings: s}
	if g.AllowedFor("backend-dev", "bob") || !g.AllowedFor("backend-dev", "alice") || g.AllowedFor("locked", "alice") {
		t.Fatal("without bindings the repository decides")
	}
	// Validation: a tenant, a known slug, sane limits, a future expiry.
	for _, tc := range []struct{ tenant, slug, spec string }{
		{"", "backend-dev", `{}`},
		{"bob", "nope", `{}`},
		{"bob", "backend-dev", `{"max_sandboxes":-1}`},
		{"bob", "backend-dev", `{"expires_at":"2000-01-01T00:00:00Z"}`},
		{"bob", "backend-dev", `{"extra":1}`},
	} {
		if _, err := s.Put(ctx, tc.tenant, &res.Document{Name: tc.slug, Spec: json.RawMessage(tc.spec)}, true, "admin"); !errors.Is(err, res.ErrInvalid) {
			t.Errorf("%+v must be invalid: %v", tc, err)
		}
	}
	exp := now.Add(time.Hour)
	spec, _ := json.Marshal(Spec{ExpiresAt: &exp, MaxSandboxes: 2})
	if _, err := s.Put(ctx, "bob", &res.Document{Name: "backend-dev", Spec: spec}, true, "admin"); err != nil {
		t.Fatal(err)
	}
	if !g.AllowedFor("backend-dev", "bob") || g.Revoked("backend-dev", "bob", false) {
		t.Fatal("a binding grants the slug")
	}
	if b, ok := s.Active("backend-dev", "bob"); !ok || b.MaxSandboxes != 2 {
		t.Fatalf("active binding: %+v %v", b, ok)
	}
	// A binding on a locked (admin-only) slug grants it; one on a slug without a policy cannot.
	if _, err := s.Put(ctx, "bob", &res.Document{Name: "locked", Spec: json.RawMessage(`{}`)}, true, "admin"); err != nil {
		t.Fatal(err)
	}
	if !g.AllowedFor("locked", "bob") {
		t.Fatal("binding on an admin-only slug")
	}
	s.Policies = nil
	if _, err := s.Put(ctx, "bob", &res.Document{Name: "ghost", Spec: json.RawMessage(`{}`)}, true, "admin"); err != nil {
		t.Fatal(err)
	}
	if g.AllowedFor("ghost", "bob") || !g.Revoked("ghost", "bob", false) {
		t.Fatal("a binding cannot grant a slug that has no policy")
	}
	// Expiry revokes without a write; deletion revokes at once and keeps the history.
	now = exp.Add(time.Second)
	if g.AllowedFor("backend-dev", "bob") || !g.Revoked("backend-dev", "bob", false) {
		t.Fatal("expired binding must not grant")
	}
	now = exp.Add(-time.Minute)
	if err := s.Delete(ctx, "bob", "backend-dev"); err != nil {
		t.Fatal(err)
	}
	if g.AllowedFor("backend-dev", "bob") || !g.Revoked("backend-dev", "bob", false) {
		t.Fatal("deleted binding must not grant")
	}
	if revs, err := s.Revisions(ctx, "bob", "backend-dev"); err != nil || len(revs) != 1 || revs[0].DeletedAt == nil {
		t.Fatalf("history after revocation: %v %+v", err, revs)
	}
	// The repository's own grant and the admin grant are untouched by bindings.
	if !g.AllowedFor("backend-dev", "alice") || g.Revoked("backend-dev", "bob", true) {
		t.Fatal("repository and admin grants")
	}
	// Another replica sees the change on its next refresh.
	other := New(s.Store, pols)
	other.Now = s.Now
	g2 := &Guard{Set: pols, Bindings: other}
	if g2.AllowedFor("locked", "bob") {
		t.Fatal("nothing granted before the first refresh")
	}
	if err := other.Refresh(ctx); err != nil || !g2.AllowedFor("locked", "bob") || g2.AllowedFor("backend-dev", "bob") {
		t.Fatalf("replica after refresh: %v", err)
	}
}

// ownHosts stands in for the connections service's self-service hosts.
type ownHosts struct {
	hosts []policy.Host
	fp    string
}

func (o ownHosts) OwnHosts() ([]policy.Host, string) { return o.hosts, o.fp }
func (o ownHosts) HeadersFor(context.Context, string, string, string) (map[string]string, error) {
	return nil, nil
}
func (o ownHosts) RuleFor(_ context.Context, sandboxID, _, host, _, _ string) (*policy.Rule, bool, error) {
	if sandboxID == "sb" && host == "tools.example.com" {
		return &policy.Rule{Host: host, Paths: []string{"/**"}}, true, nil
	}
	return nil, false, nil
}

func TestGuardMergesConnectionHosts(t *testing.T) {
	pols := policy.FromPolicies(&policy.Policy{Slug: "dev", Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}})
	g := &Guard{Set: pols, Bindings: New(store.NewMemory(), pols)}
	// Without a host source the guard is the repository.
	if hs := g.Hosts(); len(hs) != 1 || g.Fingerprint() != pols.Fingerprint() {
		t.Fatalf("plain guard: %+v", hs)
	}
	g.Headers = ownHosts{hosts: []policy.Host{
		{Name: "tools.example.com", Upstream: "https://10.0.0.5", MCP: true, Injected: []string{"Authorization"}},
		{Name: "api.github.com", Upstream: "https://evil", Injected: []string{"X-Shadow"}}, // a repository host stays the repository's
	}, fp: "c1"}
	hs := g.Hosts()
	if len(hs) != 2 || hs[0].Name != "api.github.com" || hs[0].Upstream != "https://api.github.com" || hs[1].Name != "tools.example.com" || !hs[1].MCP {
		t.Fatalf("merged hosts: %+v", hs)
	}
	if info, ok := g.HostInfo("tools.example.com"); !ok || info.Upstream != "https://10.0.0.5" {
		t.Fatalf("host info: %v %+v", ok, info)
	}
	if _, ok := g.HostInfo("nope.example.com"); ok {
		t.Fatal("unknown host")
	}
	if fp := g.Fingerprint(); fp != pols.Fingerprint()+"+c1" {
		t.Fatalf("fingerprint: %s", fp)
	}
	if r, ok, _ := g.RuleFor(context.Background(), "sb", "acme", "tools.example.com", "POST", "/mcp"); !ok || r.Host != "tools.example.com" {
		t.Fatal("rule through the guard")
	}
}
