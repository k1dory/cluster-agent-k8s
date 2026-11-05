package apikeys

import (
	"context"
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/store"
)

type failingRetire struct {
	store.APIKeys
	fail bool
}

func (f *failingRetire) RetireAPIKey(ctx context.Context, id, rotatedTo string, at time.Time, grace time.Duration) error {
	if f.fail {
		return errors.New("store unavailable")
	}
	return f.APIKeys.RetireAPIKey(ctx, id, rotatedTo, at, grace)
}

func activeKeys(t *testing.T, s *Service, tenant string, now time.Time) int {
	t.Helper()
	ks, err := s.List(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, k := range ks {
		if k.Active(now) {
			n++
		}
	}
	return n
}

// Create succeeded and retire failed: the successor stayed live (nobody had its secret) and
// the old key never expired. Now the successor is withdrawn and the old key is untouched.
func TestReviewRotateWithAFailedRetireLeavesOnlyTheOldKey(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	st := &failingRetire{APIKeys: store.NewMemory(), fail: true}
	s := &Service{Store: st, Now: func() time.Time { return now }}
	old, _, err := s.Create(ctx, "acme", "ci", 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin"); err == nil {
		t.Fatal("a failed retire must fail the rotation")
	}
	if n := activeKeys(t, s, "acme", now); n != 1 {
		t.Fatalf("only the old key may be live after a failed rotation, got %d", n)
	}
	got, _ := s.Get(ctx, old.ID)
	if got.ExpiresAt != nil || got.RotatedTo != "" {
		t.Fatalf("the old key must be unchanged: %+v", got)
	}
	st.fail = false
	if _, _, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin"); err != nil {
		t.Fatalf("a retry must succeed: %v", err)
	}
}

// A rotate repeated after its response was lost minted a third key and left the second live
// with a secret nobody holds. The unused successor is withdrawn now; the new one keeps the
// old key's original lifetime, not the grace period.
func TestReviewRetriedRotateReplacesTheUnusedSuccessor(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s := &Service{Store: store.NewMemory(), Now: func() time.Time { return now }}
	old, _, err := s.Create(ctx, "acme", "ci", 30*24*time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	lost, _, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	again, secret, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin")
	if err != nil {
		t.Fatalf("a retried rotate must succeed: %v", err)
	}
	if again.ID == lost.ID || secret == "" {
		t.Fatal("a new successor with its secret")
	}
	if l, _ := s.Get(ctx, lost.ID); l.Active(now) {
		t.Fatal("the unused earlier successor must be withdrawn")
	}
	if n := activeKeys(t, s, "acme", now); n != 2 {
		t.Fatalf("old (in grace) and one successor, got %d live", n)
	}
	if again.ExpiresAt == nil || again.ExpiresAt.Sub(now) < 29*24*time.Hour {
		t.Fatalf("the successor keeps the original lifetime: %v", again.ExpiresAt)
	}
	// Once the successor is in use, rotating the old key again is refused.
	if _, err := s.Authenticate(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an in-use successor must not be replaced: %v", err)
	}
}
