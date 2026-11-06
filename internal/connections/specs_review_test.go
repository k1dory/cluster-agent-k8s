package connections

import (
	"encoding/json"
	"testing"

	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// OwnHosts runs on every DNS query; a connection's spec is decoded once per revision.
func TestReviewSpecIsDecodedOncePerRevision(t *testing.T) {
	s := New(store.NewMemory(), secrets.Static{}, nil)
	raw, _ := json.Marshal(Spec{Type: TypeHTTP, Host: "a.example.com"})
	it := &model.CatalogItem{Tenant: "acme", Name: "a", Revision: 1, Spec: raw}
	first, err := s.specOf(it)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := s.specOf(it); again != first {
		t.Fatal("the same revision must come from the cache")
	}
	raw2, _ := json.Marshal(Spec{Type: TypeHTTP, Host: "b.example.com"})
	next, err := s.specOf(&model.CatalogItem{Tenant: "acme", Name: "a", Revision: 2, Spec: raw2})
	if err != nil || next.Host != "b.example.com" {
		t.Fatalf("a new revision must be decoded: %v %+v", err, next)
	}
	// Same revision number, other content (a recreated item): decoded again.
	if other, _ := s.specOf(&model.CatalogItem{Tenant: "acme", Name: "a", Revision: 2, Spec: raw}); other.Host != "a.example.com" {
		t.Fatalf("changed content must be decoded: %+v", other)
	}
}

// The cache kept every name it ever saw: a deleted connection now leaves it at the next sweep.
func TestReviewSpecCacheForgetsDeletedConnections(t *testing.T) {
	ctx := t.Context()
	s := New(store.NewMemory(), secrets.Static{}, nil)
	s.Hosts = repoHosts{allowed: map[string][]string{"acme": {"tools.example.com"}}}
	for i := range 20 {
		name := "c" + string(rune('a'+i))
		raw, _ := json.Marshal(Spec{Type: TypeHTTP, Host: "tools.example.com"})
		if _, err := s.Put(ctx, "acme", &res.Document{Name: name, Spec: raw}, false, "review"); err != nil {
			t.Fatal(err)
		}
		s.OwnHosts()
		if err := s.Delete(ctx, "acme", name); err != nil {
			t.Fatal(err)
		}
	}
	s.OwnHosts()
	s.specMu.Lock()
	n := len(s.specs)
	s.specMu.Unlock()
	if n != 0 {
		t.Fatalf("deleted connections must leave the cache, %d entries left", n)
	}
}
