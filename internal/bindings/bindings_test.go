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
