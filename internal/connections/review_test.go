package connections

import (
	"testing"

	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

func TestReviewUnavailableCredentialOnlyAffectsItsHost(t *testing.T) {
	s := New(store.NewMemory(), secrets.Static{"acme/service": "test-fixture"}, sandboxes{
		"review": {ID: "review", Tenant: "acme", Connections: []string{"service"}},
	})
	if _, err := s.Put(t.Context(), "acme", doc("service", `{"type":"http","host":"service.example.com","headers":{"Authorization":"Bearer secret:service"}}`), false, "alice"); err != nil {
		t.Fatal(err)
	}
	// Simulate a credential being unavailable after the connection was configured.
	s.Secrets = secrets.Static{}
	if _, err := s.HeadersFor(t.Context(), "review", "acme", "service.example.com"); err == nil {
		t.Fatal("the affected service must still reject an unresolved credential")
	}
	if _, err := s.HeadersFor(t.Context(), "review", "acme", "api.sandbox.internal"); err != nil {
		t.Fatal("an unrelated service credential blocked the sandbox control-plane API")
	}
}
