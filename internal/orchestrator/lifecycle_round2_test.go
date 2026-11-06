package orchestrator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// lifecycleRunningRunHook runs hook once, right after the next RunningRun read (the moment between
// "no run in progress" and the stop that follows it), or fails RunningRun with failErr.
type lifecycleRunningRunHook struct {
	store.Store
	mu      sync.Mutex
	hook    func()
	failErr error
}

func (s *lifecycleRunningRunHook) arm(hook func()) { s.mu.Lock(); s.hook = hook; s.mu.Unlock() }

func (s *lifecycleRunningRunHook) RunningRun(ctx context.Context, sandboxID string) (*model.Run, error) {
	s.mu.Lock()
	hook, failErr := s.hook, s.failErr
	s.hook = nil
	s.mu.Unlock()
	if failErr != nil {
		return nil, failErr
	}
	r, err := s.Store.RunningRun(ctx, sandboxID)
	if hook != nil {
		hook()
	}
	return r, err
}

// lifecycleRunningSandbox stores a running sandbox with a live fake pod and a queued run.
func lifecycleRunningSandbox(t *testing.T, st store.Store, rt *FakeRuntime, id string) *model.Sandbox {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	sb := &model.Sandbox{ID: id, Slug: "dev", Tenant: "acme", Name: id, Owner: "alice", Status: model.StatusRunning, AgentVersion: "img:1", CreatedAt: now, LastActivity: now}
	if err := rt.EnsureVolume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	sb.PodName, _ = rt.CreatePod(ctx, sb)
	if err := st.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	return sb
}

type lifecycleNextResult struct {
	run *model.Run
	err error
}

// lifecycleClaimDuring starts NextRun from inside the hook and gives it a moment to claim: long enough
// on the old code (nothing stops it), while on the fixed code the claim waits on the lock the
// stop holds and the hook returns after the timeout.
func lifecycleClaimDuring(o *Orchestrator, id string, done chan<- lifecycleNextResult) func() {
	return func() {
		got := make(chan lifecycleNextResult, 1)
		go func() {
			r, err := o.NextRun(context.Background(), id, 800*time.Millisecond)
			got <- lifecycleNextResult{r, err}
		}()
		select {
		case res := <-got:
			done <- res
		case <-time.After(300 * time.Millisecond):
			go func() { done <- <-got }()
		}
	}
}

// Sleep(force=false) checked "no run in progress" and then moved the sandbox to stopping as two
// separate steps; NextRun, having read "running", claimed the queued run in between, and the
// run was handed out to a pod that was being deleted (then cancelled with it). Now the idle
// check and the move to stopping happen under the lock the claim takes, and the claim requires
// a running sandbox: either the run is not handed out, or the sandbox is not stopped.
func TestRound2SleepDoesNotRaceAClaim(t *testing.T) {
	ctx := context.Background()
	rt := NewFakeRuntime()
	st := &lifecycleRunningRunHook{Store: store.NewMemory()}
	sb := lifecycleRunningSandbox(t, st, rt, "sb_race")
	o := New(st, rt, nil, events.New(), Config{StopTimeout: time.Second}, nil)
	run, err := o.CreateRun(ctx, sb.ID, "task")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan lifecycleNextResult, 1)
	st.arm(lifecycleClaimDuring(o, sb.ID, done))
	_, sleepErr := o.Sleep(ctx, sb.ID, false)
	res := <-done
	if res.err == nil && sleepErr == nil {
		got, _ := st.GetRun(ctx, run.ID)
		t.Fatalf("the run was handed out (now %s) and the sandbox was put to sleep", got.Status)
	}
	if sleepErr == nil {
		// The stop went first: the claim saw it and the run waits for the next pod.
		if !errors.Is(res.err, store.ErrNotFound) {
			t.Fatalf("NextRun after the stop: %v", res.err)
		}
		if got, _ := st.GetRun(ctx, run.ID); got.Status != model.RunQueued {
			t.Fatalf("run after a refused claim: %s", got.Status)
		}
		if got, _ := st.GetSandbox(ctx, sb.ID); got.Status != model.StatusSleeping {
			t.Fatalf("sandbox after sleep: %s", got.Status)
		}
	}
}

// The same interleaving many times over, without hooks: concurrent idle sleeps and claims never
// end with a sandbox stopped under a run it handed out.
func TestRound2ConcurrentSleepAndClaim(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		rt := NewFakeRuntime()
		st := store.NewMemory()
		sb := lifecycleRunningSandbox(t, st, rt, "sb_conc")
		o := New(st, rt, nil, events.New(), Config{StopTimeout: time.Second}, nil)
		run, err := o.CreateRun(ctx, sb.ID, "task")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var claimErr, sleepErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, claimErr = o.NextRun(ctx, sb.ID, 50*time.Millisecond) }()
		go func() { defer wg.Done(); _, sleepErr = o.Sleep(ctx, sb.ID, false) }()
		wg.Wait()
		got, _ := st.GetRun(ctx, run.ID)
		if claimErr == nil && sleepErr == nil {
			t.Fatalf("iteration %d: run handed out (now %s) and the sandbox put to sleep", i, got.Status)
		}
		if got.Status == model.RunCancelled {
			t.Fatalf("iteration %d: an idle sleep cancelled a run", i)
		}
	}
}

// Any RunningRun error, a database outage included, was taken for "no run in progress": an
// idle sleep (and the reconciler's idle timeout through it) stopped a sandbox it could not see
// into. Now only ErrNotFound means "no run"; anything else fails the sleep.
func TestRound2SleepFailsWhenRunningRunFails(t *testing.T) {
	ctx := context.Background()
	rt := NewFakeRuntime()
	st := &lifecycleRunningRunHook{Store: store.NewMemory()}
	sb := lifecycleRunningSandbox(t, st, rt, "sb_dberr")
	o := New(st, rt, nil, events.New(), Config{StopTimeout: time.Second}, nil)
	dbErr := errors.New("connection refused")
	st.mu.Lock()
	st.failErr = dbErr
	st.mu.Unlock()
	if _, err := o.Sleep(ctx, sb.ID, false); !errors.Is(err, dbErr) {
		t.Fatalf("Sleep with an unreadable run table: %v", err)
	}
	if got, _ := st.GetSandbox(ctx, sb.ID); got.Status != model.StatusRunning {
		t.Fatalf("sandbox stopped although its runs could not be read: %s", got.Status)
	}
	if _, _, err := rt.PodStatus(ctx, sb); err != nil {
		t.Fatalf("pod deleted: %v", err)
	}
}

// A rollout of a running sandbox read RunningRun and restarted on any error: a database error
// restarted a busy sandbox now. It is deferred instead, the desired version kept for later.
func TestRound2RolloutDefersWhenRunningRunFails(t *testing.T) {
	ctx := context.Background()
	rt := NewFakeRuntime()
	st := &lifecycleRunningRunHook{Store: store.NewMemory()}
	sb := lifecycleRunningSandbox(t, st, rt, "sb_rodberr")
	o := New(st, rt, nil, events.New(), Config{StopTimeout: time.Second}, nil)
	st.mu.Lock()
	st.failErr = errors.New("connection refused")
	st.mu.Unlock()
	res, err := o.Rollout(ctx, RolloutRequest{Sandbox: sb.ID, Version: "img:2", Admin: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Items[0].Mode != model.RolloutDeferred {
		t.Fatalf("rollout with an unreadable run table: %+v", res.Items[0])
	}
	got, _ := st.GetSandbox(ctx, sb.ID)
	if got.Status != model.StatusRunning || got.DesiredVersion != "img:2" {
		t.Fatalf("sandbox after a deferred rollout: %s desired=%q", got.Status, got.DesiredVersion)
	}
	// applyPending (after a run, and on every reconcile) must not take the error for idle either.
	o.applyPending(ctx, sb.ID)
	if got, _ := st.GetSandbox(ctx, sb.ID); got.Status != model.StatusRunning || got.AgentVersion != "img:1" {
		t.Fatalf("deferred rollout applied without knowing the runs: %s %s", got.Status, got.AgentVersion)
	}
}

// A rollout that read "idle" and restarted while NextRun claimed a run in between restarted the
// pod under that run. The restart now re-checks under the claim lock, and a run claimed first
// turns the rollout into a deferred one.
func TestRound2RolloutDoesNotRaceAClaim(t *testing.T) {
	ctx := context.Background()
	rt := NewFakeRuntime()
	st := &lifecycleRunningRunHook{Store: store.NewMemory()}
	sb := lifecycleRunningSandbox(t, st, rt, "sb_rorace")
	o := New(st, rt, nil, events.New(), Config{StopTimeout: time.Second}, nil)
	run, err := o.CreateRun(ctx, sb.ID, "task")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan lifecycleNextResult, 1)
	st.arm(lifecycleClaimDuring(o, sb.ID, done))
	res, err := o.Rollout(ctx, RolloutRequest{Sandbox: sb.ID, Version: "img:2", Admin: true})
	if err != nil {
		t.Fatal(err)
	}
	claimed := <-done
	item := res.Items[0]
	got, _ := st.GetRun(ctx, run.ID)
	if claimed.err == nil {
		if item.Mode != model.RolloutDeferred || got.Status != model.RunRunning {
			t.Fatalf("claimed run %s, rollout %+v", got.Status, item)
		}
		return
	}
	if item.Mode != model.RolloutNow || got.Status != model.RunQueued {
		t.Fatalf("refused claim, run %s, rollout %+v", got.Status, item)
	}
}
