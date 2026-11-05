package apikeys

import (
	"context"
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// flakyRotate makes RotateAPIKey fail: before writing (commit false), or after the write
// committed with the acknowledgement lost (commit true), optionally cancelling the request.
type flakyRotate struct {
	Store
	fail, commit bool
	cancel       func()
}

func (f *flakyRotate) RotateAPIKey(ctx context.Context, oldID string, next *model.APIKey, at time.Time, grace time.Duration) error {
	if !f.fail {
		return f.Store.RotateAPIKey(ctx, oldID, next, at, grace)
	}
	if f.commit {
		if err := f.Store.RotateAPIKey(ctx, oldID, next, at, grace); err != nil {
			return err
		}
	}
	if f.cancel != nil {
		f.cancel()
	}
	return errors.New("connection reset")
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

// The rotation committed and the acknowledgement was lost: the old cleanup deleted the
// committed successor (with grace 0 the old key was revoked too, leaving nothing). Now the
// outcome is read back on a context of its own and the committed successor is returned.
func TestReviewRotateWhoseCommitLostItsAckReturnsTheSuccessor(t *testing.T) {
	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := &flakyRotate{Store: store.NewMemory(), fail: true, commit: true, cancel: cancel}
	s := &Service{Store: st, Now: func() time.Time { return now }}
	old, _, err := s.Create(context.Background(), "acme", "ci", 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	next, secret, err := s.Rotate(ctx, old.ID, 0, 0, "admin")
	if err != nil {
		t.Fatalf("a committed rotation must be reported as done: %v", err)
	}
	if _, err := s.Authenticate(context.Background(), secret); err != nil {
		t.Fatalf("the committed successor must work: %v", err)
	}
	if got, _ := s.Get(context.Background(), old.ID); got.RotatedTo != next.ID {
		t.Fatalf("old: %+v", got)
	}
}

// Failing before the commit changes nothing and a retry succeeds.
func TestReviewRotateThatFailsBeforeCommitChangesNothing(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	st := &flakyRotate{Store: store.NewMemory(), fail: true}
	s := &Service{Store: st, Now: func() time.Time { return now }}
	old, _, err := s.Create(ctx, "acme", "ci", 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin"); err == nil {
		t.Fatal("a failed rotation must fail")
	}
	if n := activeKeys(t, s, "acme", now); n != 1 {
		t.Fatalf("only the old key may be live after a failed rotation, got %d", n)
	}
	if got, _ := s.Get(ctx, old.ID); got.ExpiresAt != nil || got.RotatedTo != "" {
		t.Fatalf("the old key must be unchanged: %+v", got)
	}
	st.fail = false
	if _, _, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin"); err != nil {
		t.Fatalf("a retry must succeed: %v", err)
	}
}

// A rotate repeated after its response was lost withdraws the unused successor in the same
// step as the new one is made, keeping the original lifetime; a later write failing keeps
// the earlier successor; an in-use successor is refused.
func TestReviewRetriedRotateReplacesTheUnusedSuccessor(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	st := &flakyRotate{Store: store.NewMemory()}
	s := &Service{Store: st, Now: func() time.Time { return now }}
	old, _, err := s.Create(ctx, "acme", "ci", 30*24*time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	lost, _, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	st.fail = true
	if _, _, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin"); err == nil {
		t.Fatal("the failing retry must fail")
	}
	if l, _ := s.Get(ctx, lost.ID); !l.Active(now) {
		t.Fatal("a failed retry must not withdraw the earlier successor")
	}
	st.fail = false
	again, secret, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin")
	if err != nil {
		t.Fatalf("a retried rotate must succeed: %v", err)
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
	if _, err := s.Authenticate(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an in-use successor must not be replaced: %v", err)
	}
	if a, _ := s.Get(ctx, again.ID); !a.Active(now) {
		t.Fatal("the in-use successor stays live")
	}
}
