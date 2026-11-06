package orchestrator

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// failOnceAt returns a fault hook that fails the first transaction reaching point (after all of
// its writes, before its commit: the store rolls it back), and how many it failed.
func failOnceAt(point string) (func(string) error, *atomic.Int32) {
	var n atomic.Int32
	return func(p string) error {
		if p == point && n.CompareAndSwap(0, 1) {
			return errors.New("injected failure before the commit")
		}
		return nil
	}, &n
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

func round2Running(t *testing.T) (*Orchestrator, *model.Sandbox, *model.Run) {
	t.Helper()
	o, _, sb := reviewRunningSandbox(t)
	ctx := context.Background()
	if _, err := o.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	run, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return o, sb, run
}

// Wiki item 2: the cancel was committed, then run.cancel failed to write (error ignored), and a
// repeated cancel returned before writing it: the run read cancelled while its harness ran on.
// The status and the command are one transaction now: when it fails, neither is there and the
// caller is told; the client's retry writes both, once.
func TestRound2CancelIsAllOrNothing(t *testing.T) {
	o, sb, run := round2Running(t)
	ctx := context.Background()
	hook, failed := failOnceAt(store.FaultSettle)
	store.SetFaultHook(o.Store, hook)
	defer store.SetFaultHook(o.Store, nil)
	if _, err := o.CancelRun(ctx, sb.ID, run.ID); err == nil || failed.Load() != 1 {
		t.Fatalf("cancel with a failing transaction: %v (failed %d)", err, failed.Load())
	}
	if got, _ := o.Store.GetRun(ctx, run.ID); got.Status != model.RunRunning || round2Events(t, o, sb.ID, run.ID, model.EventRunCancel) != 0 {
		t.Fatalf("a failed cancel left status %s with %d run.cancel", got.Status, round2Events(t, o, sb.ID, run.ID, model.EventRunCancel))
	}
	if _, err := o.CancelRun(ctx, sb.ID, run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := o.CancelRun(ctx, sb.ID, run.ID); err != nil { // and once more: nothing new
		t.Fatal(err)
	}
	got, _ := o.Store.GetRun(ctx, run.ID)
	if got.Status != model.RunCancelled || round2Events(t, o, sb.ID, run.ID, model.EventRunCancel) != 1 || round2Events(t, o, sb.ID, run.ID, model.EventRunDone) != 1 {
		t.Fatalf("after the retries: status %s, %d run.cancel, %d run.finished", got.Status,
			round2Events(t, o, sb.ID, run.ID, model.EventRunCancel), round2Events(t, o, sb.ID, run.ID, model.EventRunDone))
	}
}

// Wiki item 2, the same gap for a finish: the result was committed and run.finished was lost,
// so clients watching the run never saw it end. A failed transaction leaves the run running and
// the runner's retry of /finish settles it with one run.finished.
func TestRound2FinishIsAllOrNothing(t *testing.T) {
	o, sb, run := round2Running(t)
	ctx := context.Background()
	hook, failed := failOnceAt(store.FaultSettle)
	store.SetFaultHook(o.Store, hook)
	defer store.SetFaultHook(o.Store, nil)
	if err := o.FinishRun(ctx, sb.ID, run.ID, 0, nil); err == nil || failed.Load() != 1 {
		t.Fatalf("finish with a failing transaction: %v (failed %d)", err, failed.Load())
	}
	if got, _ := o.Store.GetRun(ctx, run.ID); got.Status != model.RunRunning || round2Events(t, o, sb.ID, run.ID, model.EventRunDone) != 0 {
		t.Fatalf("a failed finish left status %s with %d run.finished", got.Status, round2Events(t, o, sb.ID, run.ID, model.EventRunDone))
	}
	for range 2 {
		if err := o.FinishRun(ctx, sb.ID, run.ID, 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := o.Store.GetRun(ctx, run.ID); got.Status != model.RunDone || round2Events(t, o, sb.ID, run.ID, model.EventRunDone) != 1 {
		t.Fatalf("after the retries: status %s with %d run.finished", got.Status, round2Events(t, o, sb.ID, run.ID, model.EventRunDone))
	}
}

// Codex round 1 of #31, finding 3: the cancellation of the running run failed (its transaction
// rolled back), cancelRunning said nothing, and Delete removed the sandbox and reported success:
// the run stayed running with no executor and no record to reconcile it from. The delete now
// fails and keeps the sandbox in deleting; its retry cancels the run and removes the sandbox.
func TestRound2DeleteKeepsTheSandboxUntilItsRunIsCancelled(t *testing.T) {
	o, sb, run := round2Running(t)
	ctx := context.Background()
	hook, failed := failOnceAt(store.FaultSettle)
	store.SetFaultHook(o.Store, hook)
	defer store.SetFaultHook(o.Store, nil)
	if err := o.Delete(ctx, sb.ID); err == nil || failed.Load() != 1 {
		t.Fatalf("delete with a failing cancellation: %v (failed %d)", err, failed.Load())
	}
	cur, err := o.Store.GetSandbox(ctx, sb.ID)
	if err != nil || cur.Status != model.StatusDeleting || cur.Error == "" {
		t.Fatalf("the sandbox after a failed cancellation: %v %+v", err, cur)
	}
	if got, _ := o.Store.GetRun(ctx, run.ID); got.Status != model.RunRunning {
		t.Fatalf("run: %+v", got)
	}
	o.Reconcile(ctx) // the reconciler retries a delete left in deleting
	if _, err := o.Store.GetSandbox(ctx, sb.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the retried delete left the sandbox: %v", err)
	}
	if got, _ := o.Store.GetRun(ctx, run.ID); got.Status != model.RunCancelled || round2Events(t, o, sb.ID, run.ID, model.EventRunDone) != 1 {
		t.Fatalf("run after the retried delete: %+v with %d run.finished", got, round2Events(t, o, sb.ID, run.ID, model.EventRunDone))
	}
}

// queueHookStore runs hook once, inside the next QueuedRun, before it reads the queue.
type queueHookStore struct {
	store.Store
	hook atomic.Pointer[func()]
}

func (s *queueHookStore) QueuedRun(ctx context.Context, sandboxID string) (*model.Run, error) {
	if h := s.hook.Swap(nil); h != nil {
		(*h)()
	}
	return s.Store.QueuedRun(ctx, sandboxID)
}

// Codex round 1 of #31, finding 2: two queued runs; the runner's retry of /next overlaps the
// request whose response is lost. The retry checked for a claim to hand out again (none yet),
// the original then claimed run 1, and the retry, reading the queue after that, claimed run 2:
// the continuation executed before the run it continues, without its session. The reclaim
// check and the claim are one decision now: the retry gets run 1 again.
func TestRound2OverlappingRetryDoesNotSkipAhead(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	st := &queueHookStore{Store: o.Store}
	o.Store = st
	ctx := context.Background()
	first, err := o.CreateRun(ctx, sb.ID, "first")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond) // queue order is creation order
	second, err := o.CreateRun(ctx, sb.ID, "second")
	if err != nil {
		t.Fatal(err)
	}
	var original *model.Run
	hook := func() {
		// The retry has checked for a claim to hand out again and is about to read the queue:
		// the original request claims now, and its response is lost.
		var err error
		if original, err = o.NextRunFor(ctx, sb.ID, "1", 0); err != nil {
			t.Error(err)
		}
	}
	st.hook.Store(&hook)
	retry, err := o.NextRunFor(ctx, sb.ID, "1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if original == nil || original.ID != first.ID {
		t.Fatalf("the original request: %+v", original)
	}
	if retry.ID != first.ID || retry.Attempt != original.Attempt+1 {
		t.Fatalf("the overlapping retry got %s (attempt %d), want %s again", retry.ID, retry.Attempt, first.ID)
	}
	if got, _ := o.Store.GetRun(ctx, second.ID); got.Status != model.RunQueued {
		t.Fatalf("the second run was claimed ahead of the first: %+v", got)
	}
	if n := round2Events(t, o, sb.ID, first.ID, model.EventRunStart); n != 1 {
		t.Fatalf("run.start emitted %d times", n)
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

// Codex round 2 of #31, finding 2: a forced sleep whose cancellation of the running run failed
// reported success and left the sandbox sleeping with the run running; an immediate wake gave
// it a healthy pod, so nothing ever settled the run (the reconciler only fails runs of
// sandboxes without one). The stop now stays pending until the cancellation commits.
func TestRound2ForcedSleepWaitsForTheCancellation(t *testing.T) {
	o, sb, run := round2Running(t)
	ctx := context.Background()
	hook, failed := failOnceAt(store.FaultSettle)
	store.SetFaultHook(o.Store, hook)
	defer store.SetFaultHook(o.Store, nil)
	_, sleepErr := o.Sleep(ctx, sb.ID, true)
	if failed.Load() != 1 {
		t.Fatal("the cancellation was not attempted")
	}
	_, _ = o.Wake(ctx, sb.ID) // the client wakes it right away
	if cur, _ := o.Store.GetSandbox(ctx, sb.ID); cur.Status == model.StatusSleeping || cur.Status == model.StatusWaking || cur.Status == model.StatusRunning {
		if got, _ := o.Store.GetRun(ctx, run.ID); got.Status == model.RunRunning {
			t.Fatalf("sleep answered %v, sandbox %s with its run still running", sleepErr, cur.Status)
		}
	}
	if sleepErr == nil {
		t.Fatal("a sleep whose cancellation failed reported success")
	}
	o.Reconcile(ctx) // finishes the stop: the run is cancelled, then the sandbox sleeps
	cur, _ := o.Store.GetSandbox(ctx, sb.ID)
	got, _ := o.Store.GetRun(ctx, run.ID)
	if cur.Status != model.StatusSleeping || got.Status != model.RunCancelled || round2Events(t, o, sb.ID, run.ID, model.EventRunDone) != 1 {
		t.Fatalf("after the reconciler: sandbox %s, run %s, %d run.finished", cur.Status, got.Status, round2Events(t, o, sb.ID, run.ID, model.EventRunDone))
	}
}

// Codex round 2 of #31, finding 4: the original /next stalled, its retry claimed run 1 and the
// runner confirmed it; when the original resumed it found no unconfirmed claim and took run 2
// while run 1 executed. An owner executing a confirmed run gets no other one.
func TestRound2DelayedRequestDoesNotClaimAheadOfAConfirmedRun(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	st := &queueHookStore{Store: o.Store}
	o.Store = st
	ctx := context.Background()
	first, err := o.CreateRun(ctx, sb.ID, "first")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	second, err := o.CreateRun(ctx, sb.ID, "second")
	if err != nil {
		t.Fatal(err)
	}
	hook := func() {
		// The original request stalls here; its retry claims run 1 and the runner confirms it.
		retry, err := o.NextRunFor(ctx, sb.ID, "1", 0)
		if err != nil || retry.ID != first.ID {
			t.Errorf("the retry: %v %+v", err, retry)
			return
		}
		if err := o.AckClaim(ctx, retry, "1", retry.Attempt); err != nil {
			t.Error(err)
		}
	}
	st.hook.Store(&hook)
	if r, err := o.NextRunFor(ctx, sb.ID, "1", 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the delayed original got %+v (%v) while run 1 executes", r, err)
	}
	if got, _ := o.Store.GetRun(ctx, second.ID); got.Status != model.RunQueued {
		t.Fatalf("run 2 was claimed while run 1 executes: %+v", got)
	}
	// Once run 1 is settled, run 2 is the owner's next.
	if err := o.FinishRun(ctx, sb.ID, first.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	if r, err := o.NextRunFor(ctx, sb.ID, "1", 0); err != nil || r.ID != second.ID {
		t.Fatalf("after run 1 finished: %v %+v", err, r)
	}
}

// runningHookStore runs hook once, inside the next RunningRun, before it reads.
type runningHookStore struct {
	store.Store
	hook atomic.Pointer[func()]
}

func (s *runningHookStore) RunningRun(ctx context.Context, sandboxID string) (*model.Run, error) {
	if h := s.hook.Swap(nil); h != nil {
		(*h)()
	}
	return s.Store.RunningRun(ctx, sandboxID)
}

// Codex round 3 of #31, finding 1: replica A's reconciler saw the stopped pod gone and stalled
// before cancelling its run; replica B finished the stop, woke the sandbox and a replacement pod
// started a new run; A then cancelled that new run (the stale move to sleeping was refused only
// afterwards). The cancellation is fenced on the stop it belongs to.
func TestRound2StaleStopRecoverySparesTheReplacementsRun(t *testing.T) {
	ctx := context.Background()
	rt := NewFakeRuntime()
	base := store.NewMemory()
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_stale", Slug: "dev", Tenant: "acme", Name: "s", Owner: "alice", Status: model.StatusStopping, CreatedAt: now, LastActivity: now}
	if err := rt.EnsureVolume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := base.CreateSandbox(ctx, sb); err != nil { // stopping, its pod already gone
		t.Fatal(err)
	}
	hooked := &runningHookStore{Store: base}
	a := New(hooked, rt, nil, events.New(), Config{}, nil)
	b := New(base, rt, nil, events.New(), Config{}, nil)
	var replacement *model.Run
	hook := func() {
		// A is about to read the running run of the stop it observed: meanwhile B finishes the
		// stop, the sandbox is woken and the replacement pod starts a run.
		b.Reconcile(ctx)
		if _, err := b.Wake(ctx, sb.ID); err != nil {
			t.Error(err)
			return
		}
		waitFor(t, "replacement running", func() bool { cur, _ := base.GetSandbox(ctx, sb.ID); return cur.Status == model.StatusRunning })
		if _, err := b.CreateRun(ctx, sb.ID, "new"); err != nil {
			t.Error(err)
			return
		}
		var err error
		if replacement, err = b.NextRun(ctx, sb.ID, time.Second); err != nil {
			t.Error(err)
		}
	}
	hooked.hook.Store(&hook)
	a.Reconcile(ctx) // observes the stop with no pod: recovers it
	if replacement == nil {
		t.Fatal("the replacement run never started")
	}
	got, _ := base.GetRun(ctx, replacement.ID)
	cur, _ := base.GetSandbox(ctx, sb.ID)
	if got.Status != model.RunRunning || cur.Status != model.StatusRunning {
		t.Fatalf("a stale stop recovery touched the replacement: run %s, sandbox %s", got.Status, cur.Status)
	}
}

// Codex round 3 of #31, finding 3: a pod lost while its run executed; the run's settlement
// failed (its transaction rolled back), the reconciler moved the sandbox to error all the same,
// and a wake gave it a healthy new pod: nothing ever settled the old run. The sandbox now stays
// as it is until the settlement commits, and a wake settles a leftover run first.
func TestRound2LostPodRunIsSettledBeforeAWake(t *testing.T) {
	o, rt, sb := reviewRunningSandbox(t)
	ctx := context.Background()
	if _, err := o.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	run, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := o.Store.GetSandbox(ctx, sb.ID)
	if err := rt.FakeRuntime.DeletePod(ctx, cur); err != nil { // the pod is lost
		t.Fatal(err)
	}
	hook, failed := failOnceAt(store.FaultSettle)
	store.SetFaultHook(o.Store, hook)
	defer store.SetFaultHook(o.Store, nil)
	o.Reconcile(ctx)
	if failed.Load() != 1 {
		t.Fatal("the run's settlement was not attempted")
	}
	if _, err := o.Wake(ctx, sb.ID); err != nil { // the client wakes it right away
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // a pod the wake started would be up by now
	o.Reconcile(ctx)
	if got, _ := o.Store.GetRun(ctx, run.ID); got.Status != model.RunFailed || round2Events(t, o, sb.ID, run.ID, model.EventRunDone) != 1 {
		t.Fatalf("the lost pod's run after a wake: %s with %d run.finished", got.Status, round2Events(t, o, sb.ID, run.ID, model.EventRunDone))
	}
}

// Finding 3, the wake side: a sandbox in error with a run still marked running (its settlement
// failed or has not happened) is not given a new pod until that run is settled.
func TestRound2WakeSettlesALeftoverRunFirst(t *testing.T) {
	o, sb, run := round2Running(t)
	ctx := context.Background()
	if _, err := o.setStatusFrom(ctx, sb.ID, []model.SandboxStatus{model.StatusRunning}, model.StatusError, nil); err != nil {
		t.Fatal(err)
	}
	hook, failed := failOnceAt(store.FaultSettle)
	store.SetFaultHook(o.Store, hook)
	defer store.SetFaultHook(o.Store, nil)
	if _, err := o.Wake(ctx, sb.ID); err == nil || failed.Load() != 1 {
		t.Fatalf("a wake over a run it could not settle: %v (failed %d)", err, failed.Load())
	}
	if cur, _ := o.Store.GetSandbox(ctx, sb.ID); cur.Status != model.StatusError {
		t.Fatalf("the wake went on: %s", cur.Status)
	}
	if _, err := o.Wake(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := o.Store.GetRun(ctx, run.ID); got.Status != model.RunFailed {
		t.Fatalf("leftover run after the wake: %s", got.Status)
	}
}

// Codex round 3 of #31, finding 4: run.start was emitted after the claim committed; a retry
// reclaiming the run in between delivered it without one, output and run.finished came first,
// and if the original request died there was never a run.start. It is written by the claim.
func TestRound2RunStartIsWrittenWithTheClaim(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	ctx := context.Background()
	if _, err := o.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	hs := &claimHookStore{Store: o.Store}
	o.Store = hs
	starts := -1
	hs.hook = func(r *model.Run) {
		// The original request committed its claim and stalls; the runner's retry reclaims.
		starts = round2Events(t, o, sb.ID, r.ID, model.EventRunStart)
		if again, err := o.NextRunFor(ctx, sb.ID, "1", 0); err != nil || again.ID != r.ID {
			t.Errorf("the retry: %v %+v", err, again)
		}
	}
	first, err := o.NextRunFor(ctx, sb.ID, "1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if starts != 1 {
		t.Fatalf("run.start events when the claim was committed: %d", starts)
	}
	if n := round2Events(t, o, sb.ID, first.ID, model.EventRunStart); n != 1 {
		t.Fatalf("run.start events after the claim and its reclaim: %d", n)
	}
}
