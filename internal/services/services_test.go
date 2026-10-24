package services

import (
	"context"
	"encoding/json"
	"testing"

	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// The assembly is one piece: the connections decide delegation with the tenant settings read
// from the same store, and the guard carries the connections as its header and host source.
func TestAssembleWiresOneSetOverOneStore(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	pols := policy.FromPolicies(&policy.Policy{Slug: "dev", Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}})
	s := Assemble(st, Options{Policies: pols})
	if s.Guard.Headers == nil || s.Connections.Hosts == nil || s.Catalog.Connections == nil || s.Catalog.Tenants == nil {
		t.Fatalf("assembly incomplete: %+v", s)
	}
	for _, r := range []interface{ Refresh(context.Context) error }{s.Tenants, s.Bindings, s.Connections} {
		if err := r.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, repo := s.Connections.Hosts.HostInfo("api.github.com"); !repo {
		t.Fatal("the host policy must see the repository's hosts")
	}
	if s.Connections.Hosts.HostAllowed("acme", "mcp.tools.example.com") {
		t.Fatal("nothing delegated yet")
	}
	// Settings written through the set's own tenants service are what its connections consult.
	if _, err := s.Tenants.Put(ctx, "acme", &res.Document{Spec: json.RawMessage(`{"hosts":["mcp.tools.example.com"]}`)}, "admin"); err != nil {
		t.Fatal(err)
	}
	if !s.Connections.Hosts.HostAllowed("acme", "mcp.tools.example.com") {
		t.Fatal("delegation must be read from the same store")
	}
	if _, err := s.Connections.Put(ctx, "acme", &res.Document{Name: "tools", Spec: json.RawMessage(`{"type":"mcp","host":"mcp.tools.example.com"}`)}, false, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Guard.HostInfo("mcp.tools.example.com"); !ok {
		t.Fatal("the guard must serve the connection's host")
	}
}
