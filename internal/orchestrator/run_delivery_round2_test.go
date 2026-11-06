package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// eventFailStore fails every separate write of an event of type fail: the write a replica made
// after committing a run's transition, and whose error it ignored.
type eventFailStore struct {
	store.Store
	fail string
}

func (s *eventFailStore) AppendEvent(ctx context.Context, e *model.Event) error {
	if e.Type == s.fail {
		return errors.New("injected event write failure")
	}
	return s.Store.AppendEvent(ctx, e)
}

func round2Events(t *testing.T, o *Orchestrator, sandboxID, runID, typ string) int {
	t.Helper()
	evs, err := o.Store.ListEvents(context.Background(), sandboxID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if e.RunID == runID && e.Type == typ {
			n++
		}
	}
	return n
}

// Wiki item 2: the cancel was committed, then run.cancel failed to write (error ignored), and a
// repeated cancel returned before writing it: the run read cancelled while its harness ran on.
// A cancel is now either not committed or delivered, and a repeated one delivers it.
func TestRound2CancelIsDeliveredWhenTheEventWriteFails(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	o.Store = &eventFailStore{Store: o.Store, fail: model.EventRunCancel}
	ctx := context.Background()
	if _, err := o.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	run, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = o.CancelRun(ctx, sb.ID, run.ID)
	_, _ = o.CancelRun(ctx, sb.ID, run.ID) // the client retries the cancel
	got, err := o.Store.GetRun(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == model.RunCancelled && round2Events(t, o, sb.ID, run.ID, model.EventRunCancel) != 1 {
		t.Fatalf("cancelled with %d run.cancel for the runner", round2Events(t, o, sb.ID, run.ID, model.EventRunCancel))
	}
	if got.Status != model.RunCancelled {
		t.Fatalf("cancel did not take: %+v", got)
	}
}

// Wiki item 2, the same gap for a finish: the result was committed and run.finished was lost,
// so clients watching the run never saw it end.
func TestRound2FinishIsAnnouncedWhenTheEventWriteFails(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	o.Store = &eventFailStore{Store: o.Store, fail: model.EventRunDone}
	ctx := context.Background()
	if _, err := o.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	run, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // the runner retries a finish that was not acknowledged
		if err := o.FinishRun(ctx, sb.ID, run.ID, 0, nil); err == nil {
			break
		}
	}
	got, _ := o.Store.GetRun(ctx, run.ID)
	if got.Status != model.RunDone || round2Events(t, o, sb.ID, run.ID, model.EventRunDone) != 1 {
		t.Fatalf("finish: status %s with %d run.finished", got.Status, round2Events(t, o, sb.ID, run.ID, model.EventRunDone))
	}
}

// Wiki item 3: a claim handed to one pod instance is never handed to another, whether or not
// the first confirmed it, and a finish of an attempt the run was handed out past is refused.
func TestRound2ClaimStaysWithItsInstance(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	ctx := context.Background()
	if _, err := o.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	first, err := o.NextRunFor(ctx, sb.ID, "1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := o.NextRunFor(ctx, sb.ID, "2", 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another instance got the run: %v %+v", err, r)
	}
	again, err := o.NextRunFor(ctx, sb.ID, "1", 0)
	if err != nil || again.ID != first.ID || again.Attempt != first.Attempt+1 {
		t.Fatalf("the same instance asking again: %v %+v", err, again)
	}
	if err := o.FinishRunAttempt(ctx, sb.ID, first.ID, first.Attempt, 0, nil); !errors.Is(err, store.ErrStaleAttempt) {
		t.Fatalf("finish of the stale attempt: %v", err)
	}
	if n := round2Events(t, o, sb.ID, first.ID, model.EventRunStart); n != 1 {
		t.Fatalf("run.start emitted %d times", n)
	}
	if err := o.AckClaim(ctx, again, "1", again.Attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := o.NextRunFor(ctx, sb.ID, "1", 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a confirmed claim was handed out again: %v", err)
	}
	if err := o.FinishRunAttempt(ctx, sb.ID, first.ID, again.Attempt, 0, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := o.Store.GetRun(ctx, first.ID); got.Status != model.RunDone {
		t.Fatalf("after finish: %+v", got)
	}
}
