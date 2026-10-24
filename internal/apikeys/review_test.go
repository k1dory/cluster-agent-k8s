package apikeys

import (
	"context"
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/store"
)

type reviewKeyTouchStore struct {
	store.APIKeys
	beforeTouch func()
}

func (s *reviewKeyTouchStore) TouchAPIKey(ctx context.Context, id string, at time.Time) error {
	if s.beforeTouch != nil {
		f := s.beforeTouch
		s.beforeTouch = nil
		f()
	}
	return s.APIKeys.TouchAPIKey(ctx, id, at)
}

func TestReviewKeyUsageCannotUndoRevocation(t *testing.T) {
	ctx := t.Context()
	mem := store.NewMemory()
	st := &reviewKeyTouchStore{APIKeys: mem}
	s := &Service{Store: st}
	admin := &Service{Store: mem}
	k, secret, err := s.Create(ctx, "acme", "review", 0, "operator")
	if err != nil {
		t.Fatal(err)
	}
	// Another request revokes the key after authentication read it, before its usage
	// timestamp is saved. Bookkeeping must leave the completed revocation intact.
	st.beforeTouch = func() {
		if _, err := admin.Revoke(ctx, k.ID); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = s.Authenticate(ctx, secret)
	stored, err := mem.GetAPIKey(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RevokedAt == nil {
		t.Error("saving last_used_at must not clear a completed revocation")
	}
	if _, err := admin.Authenticate(ctx, secret); !errors.Is(err, ErrBadKey) {
		t.Error("the next request must reject a revoked key")
	}
}
