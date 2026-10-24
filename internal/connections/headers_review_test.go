package connections

import (
	"context"
	"testing"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// A connection whose secret is missing must not block requests to other hosts: only the
// connections for the requested host are resolved.
func TestMissingSecretAffectsOnlyItsHost(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	provider := secrets.Static{"acme/github": "ghp_x", "acme/jira": "jira-x"}
	s := New(st, provider, sandboxes{"sb": {ID: "sb", Tenant: "acme", Connections: []string{"github", "jira"}}})
	for _, d := range []struct{ name, spec string }{
		{"github", `{"type":"http","host":"api.github.com","headers":{"Authorization":"Bearer secret:github"}}`},
		{"jira", `{"type":"http","host":"jira.example.com","headers":{"Authorization":"Bearer secret:jira"}}`},
	} {
		if _, err := s.Put(ctx, "acme", doc(d.name, d.spec), false, "x"); err != nil {
			t.Fatal(err)
		}
	}
	delete(provider, "acme/jira") // rotated away after the connection was written
	if h, err := s.HeadersFor(ctx, "sb", "acme", "api.sandbox.internal"); err != nil || h != nil {
		t.Fatalf("the control plane's own host must be unaffected: %v %v", err, h)
	}
	if h, err := s.HeadersFor(ctx, "sb", "acme", "api.github.com"); err != nil || h["Authorization"] != "Bearer ghp_x" {
		t.Fatalf("the healthy connection must work: %v %v", err, h)
	}
	if _, err := s.HeadersFor(ctx, "sb", "acme", "jira.example.com"); err == nil {
		t.Fatal("the broken connection fails only its own host")
	}
	_ = model.FSList
}
