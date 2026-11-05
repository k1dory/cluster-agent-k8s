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

func (f *flakyRotate) RotateAPIKey(ctx context.Context, oldID string, next *model.APIKey, at time.Time, opts store.RotateOptions) error {
	if !f.fail {
		return f.Store.RotateAPIKey(ctx, oldID, next, at, opts)
	}
	if f.commit {
		if err := f.Store.RotateAPIKey(ctx, oldID, next, at, opts); err != nil {
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

// lateCommit: the COMMIT's acknowledgement is lost while the transaction is still completing;
// it lands after a plain read would already have seen the old row. LockedAPIKey, like a
// FOR UPDATE, waits for it.
type lateCommit struct {
	Store
	done chan struct{}
}

func (l *lateCommit) RotateAPIKey(ctx context.Context, oldID string, next *model.APIKey, at time.Time, opts store.RotateOptions) error {
	l.done = make(chan struct{})
	go func() {
		defer close(l.done)
		time.Sleep(100 * time.Millisecond)
		_ = l.Store.RotateAPIKey(context.Background(), oldID, next, at, opts)
	}()
	return errors.New("connection reset during COMMIT")
}

func (l *lateCommit) LockedAPIKey(ctx context.Context, id string) (*model.APIKey, error) {
	select {
	case <-l.done:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return l.Store.LockedAPIKey(ctx, id)
}

// The recovery read was a plain SELECT: it saw the old row while the commit was still
// completing, reported "nothing changed", dropped the secret, and the commit then retired the
// old key. It now waits under the row lock and returns the committed successor.
func TestReviewRotateRecoveryWaitsForACommitStillCompleting(t *testing.T) {
	now := time.Now()
	st := &lateCommit{Store: store.NewMemory()}
	s := &Service{Store: st, Now: func() time.Time { return now }}
	ctx := context.Background()
	old, _, err := s.Create(ctx, "acme", "ci", 0, "admin")
	if err != nil {
		t.Fatal(err)
	}
	next, secret, err := s.Rotate(ctx, old.ID, 0, 0, "admin")
	if err != nil {
		t.Fatalf("a rotation that committed late must be reported as done: %v", err)
	}
	if _, err := s.Authenticate(ctx, secret); err != nil || next == nil {
		t.Fatalf("the successor must work: %v", err)
	}
}

// Rotate a long-lived key to a short-lived successor, then retry with the TTL omitted after
// that successor expired: the old key is still in its grace period, and the new key gets the
// old key's original lifetime, not "expires now".
func TestReviewOmittedTTLRetryUsesTheOriginalLifetime(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s := &Service{Store: store.NewMemory(), Now: func() time.Time { return now }}
	old, _, err := s.Create(ctx, "acme", "ci", 30*24*time.Hour, "admin")
	if err != nil {
		t.Fatal(err)
	}
	original := *old.ExpiresAt
	short, _, err := s.Rotate(ctx, old.ID, time.Minute, time.Hour, "admin")
	if err != nil || short.ExpiresAt.Sub(now) != time.Minute {
		t.Fatalf("explicit short successor: %v %+v", err, short)
	}
	now = now.Add(2 * time.Minute)
	again, _, err := s.Rotate(ctx, old.ID, 0, time.Hour, "admin")
	if err != nil {
		t.Fatalf("an omitted-TTL retry within the grace period must succeed: %v", err)
	}
	if again.ExpiresAt == nil || !again.ExpiresAt.Equal(original) {
		t.Fatalf("the new key keeps the original expiry %v, got %v", original, again.ExpiresAt)
	}
	// And the stored row says the same as the returned key.
	if got, _ := s.Get(ctx, again.ID); got.ExpiresAt == nil || !got.ExpiresAt.Equal(original) {
		t.Fatalf("stored: %+v", got)
	}
}
