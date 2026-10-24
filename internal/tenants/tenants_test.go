package tenants

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

func TestTenantSettings(t *testing.T) {
	ctx := context.Background()
	s := New(store.NewMemory(), func(tenant string) Quota {
		if tenant == "bob" {
			return Quota{MaxSandboxes: 1}
		}
		return Quota{MaxSandboxes: 10, MaxAwake: 3}
	})
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if q := s.QuotaFor("bob"); q.MaxSandboxes != 1 {
		t.Fatalf("defaults: %+v", q)
	}
	if !s.EnvironmentAllowed("bob", "anything") {
		t.Fatal("no settings: every environment")
	}
	for _, tc := range []struct{ tenant, name, spec string }{
		{"", "", `{}`},
		{"bob", "other", `{}`},
		{"bob", "", `{"quota":{"max_sandboxes":-1}}`},
		{"bob", "", `{"environments":["base@1"]}`},
		{"bob", "", `{"environments":["Bad Name"]}`},
		{"bob", "", `{"extra":1}`},
	} {
		if _, err := s.Put(ctx, tc.tenant, &res.Document{Name: tc.name, Spec: json.RawMessage(tc.spec)}, "admin"); !errors.Is(err, res.ErrInvalid) {
			t.Errorf("%+v must be invalid: %v", tc, err)
		}
	}
	it, err := s.Put(ctx, "bob", &res.Document{Spec: json.RawMessage(`{"quota":{"max_sandboxes":3},"environments":["shared/base","own"]}`)}, "admin")
	if err != nil || it.Name != Name || it.Revision != 1 {
		t.Fatalf("put: %v %+v", err, it)
	}
	if q := s.QuotaFor("bob"); q.MaxSandboxes != 3 || q.MaxAwake != 0 {
		t.Fatalf("settings replace the defaults as a whole: %+v", q)
	}
	if !s.EnvironmentAllowed("bob", "shared/base") || !s.EnvironmentAllowed("bob", "own") || s.EnvironmentAllowed("bob", "base") || s.EnvironmentAllowed("alice", "zzz") == false {
		t.Fatal("environment allow-list")
	}
	// Settings without a quota keep the defaults; a reset returns everything to them.
	if _, err := s.Put(ctx, "bob", &res.Document{Spec: json.RawMessage(`{"environments":["own"]}`)}, "admin"); err != nil {
		t.Fatal(err)
	}
	if q := s.QuotaFor("bob"); q.MaxSandboxes != 1 {
		t.Fatalf("no quota in settings → defaults: %+v", q)
	}
	if err := s.Delete(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if !s.EnvironmentAllowed("bob", "base") {
		t.Fatal("reset")
	}
	if revs, err := s.Revisions(ctx, "bob"); err != nil || len(revs) != 2 || revs[1].DeletedAt == nil {
		t.Fatalf("history: %v %+v", err, revs)
	}
}
