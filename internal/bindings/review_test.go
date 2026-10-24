package bindings

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// Delay one completed read, as can happen when a background refresh overlaps an API write.
type reviewDelayedCatalog struct {
	store.Catalog
	delay   atomic.Bool
	read    chan struct{}
	release chan struct{}
}

func (s *reviewDelayedCatalog) ListKind(ctx context.Context, kind string) ([]*model.CatalogItem, error) {
	items, err := s.Catalog.ListKind(ctx, kind)
	if err == nil && s.delay.CompareAndSwap(true, false) {
		close(s.read)
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return items, err
}

func TestReviewBindingRevocationSurvivesConcurrentRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	st := &reviewDelayedCatalog{Catalog: store.NewMemory(), read: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(st.release) }) }
	t.Cleanup(release)
	pols := policy.FromPolicies(&policy.Policy{Slug: "review", Tenants: []string{"owner"}})
	pols.Strict = true
	svc := New(st, pols)
	guard := &Guard{Set: pols, Bindings: svc}
	if _, err := svc.Put(ctx, "tenant", &res.Document{Name: "review", Spec: json.RawMessage(`{}`)}, true, "admin"); err != nil {
		t.Fatal(err)
	}
	if !guard.AllowedFor("review", "tenant") {
		t.Fatal("fixture: binding must grant access")
	}
	st.delay.Store(true)
	refreshed := make(chan error, 1)
	go func() { refreshed <- svc.Refresh(ctx) }()
	select {
	case <-st.read:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	deleted := make(chan error, 1)
	go func() { deleted <- svc.Delete(ctx, "tenant", "review") }()
	// Concurrent refreshes may discard stale reads or serialize them. Allow either fix:
	// in the latter case Delete waits until the older read is released.
	deleteFinished := false
	select {
	case err := <-deleted:
		deleteFinished = true
		if err != nil {
			t.Fatal(err)
		}
		if guard.AllowedFor("review", "tenant") {
			t.Fatal("delete must revoke the binding before it returns")
		}
	case <-time.After(100 * time.Millisecond):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	release()
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	if !deleteFinished {
		if err := <-deleted; err != nil {
			t.Fatal(err)
		}
	}
	if guard.AllowedFor("review", "tenant") || !guard.Revoked("review", "tenant", false) {
		t.Fatal("an older refresh restored a successfully revoked binding")
	}
}
