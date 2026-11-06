package orchestrator

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Codex round 4 of #31, finding 1: replica A read the sandbox sleeping (or in error) and was
// about to settle a leftover run, in Wake or in the reconciler; meanwhile replica B woke the
// sandbox and the new pod started a run. A then read that run through RunningRun and failed it:
// healthy work killed, run.finished emitted. The settlement is fenced on the status A observed.
func TestRound4StaleLeftoverCleanupSparesTheNewRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status model.SandboxStatus
		act    func(ctx context.Context, a *Orchestrator, id string)
	}{
		{"wake from sleeping", model.StatusSleeping, func(ctx context.Context, a *Orchestrator, id string) { _, _ = a.Wake(ctx, id) }},
		{"wake from error", model.StatusError, func(ctx context.Context, a *Orchestrator, id string) { _, _ = a.Wake(ctx, id) }},
		{"reconcile sleeping", model.StatusSleeping, func(ctx context.Context, a *Orchestrator, _ string) { a.Reconcile(ctx) }},
		{"reconcile error", model.StatusError, func(ctx context.Context, a *Orchestrator, _ string) { a.Reconcile(ctx) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			rt := NewFakeRuntime()
			base := store.NewMemory()
			now := time.Now()
			sb := &model.Sandbox{ID: "sb_r4", Slug: "dev", Tenant: "acme", Name: "s", Owner: "alice", Status: tc.status, CreatedAt: now, LastActivity: now}
			if err := rt.EnsureVolume(ctx, sb); err != nil {
				t.Fatal(err)
			}
			if err := base.CreateSandbox(ctx, sb); err != nil {
				t.Fatal(err)
			}
			hooked := &runningHookStore{Store: base}
			a := New(hooked, rt, nil, events.New(), Config{}, nil)
			b := New(base, rt, nil, events.New(), Config{}, nil)
			var replacement *model.Run
			hook := func() {
				// A observed the sandbox without a pod and is about to look for a leftover run:
				// meanwhile B wakes it and the new pod claims a run.
				if _, err := b.Wake(ctx, sb.ID); err != nil {
					t.Error(err)
					return
				}
				waitFor(t, "new pod running", func() bool { cur, _ := base.GetSandbox(ctx, sb.ID); return cur.Status == model.StatusRunning })
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
			tc.act(ctx, a, sb.ID)
			if replacement == nil {
				t.Fatal("the new run never started")
			}
			got, _ := base.GetRun(ctx, replacement.ID)
			if got.Status != model.RunRunning {
				t.Fatalf("a stale cleanup settled the new pod's run: %s", got.Status)
			}
			if n := round2Events(t, b, sb.ID, replacement.ID, model.EventRunDone); n != 0 {
				t.Fatalf("run.finished emitted %d times for a live run", n)
			}
		})
	}
}

// lostPodRuntime runs hook once, right after a PodStatus that found the pod gone: the
// reconciler has made its observation and not acted on it yet.
type lostPodRuntime struct {
	*FakeRuntime
	hook atomic.Pointer[func()]
}

func (r *lostPodRuntime) PodStatus(ctx context.Context, sb *model.Sandbox) (bool, string, error) {
	ready, ip, err := r.FakeRuntime.PodStatus(ctx, sb)
	if err != nil && podGone(err) {
		if h := r.hook.Swap(nil); h != nil {
			(*h)()
		}
	}
	return ready, ip, err
}

type countingRetirer struct{ n atomic.Int32 }

func (c *countingRetirer) RetireSandbox(context.Context, string) error { c.n.Add(1); return nil }

// Codex round 5 of #31: replica A's reconciler saw a running sandbox's pod gone and stalled
// before acting; replica B force-slept the sandbox, woke it, and the replacement pod claimed a
// new run. The sandbox read running again, so A's status-only fence passed: A failed the new
// run, retired the replacement's identities and put the sandbox in error. The cleanup now runs
// under the tenant lock, fenced on the revision A observed.
func TestRound5StaleLostPodCleanupSparesTheReplacement(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRuntime()
	base := store.NewMemory()
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_r5", Slug: "dev", Tenant: "acme", Name: "s", Owner: "alice", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := fake.EnsureVolume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	var err error
	if sb.PodName, err = fake.CreatePod(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := base.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	rtA := &lostPodRuntime{FakeRuntime: fake}
	a := New(base, rtA, nil, events.New(), Config{}, nil)
	retiredByA := &countingRetirer{}
	a.Retirer = retiredByA
	b := New(base, fake, nil, events.New(), Config{}, nil)
	if _, err := b.CreateRun(ctx, sb.ID, "old"); err != nil {
		t.Fatal(err)
	}
	old, err := b.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := base.GetSandbox(ctx, sb.ID)
	if err := fake.DeletePod(ctx, cur); err != nil { // the pod is lost
		t.Fatal(err)
	}
	var replacement *model.Run
	hook := func() {
		// A observed the pod gone. Meanwhile B: a forced sleep (cancelling the old run), a
		// wake, and the replacement pod claims a new run.
		if _, err := b.Sleep(ctx, sb.ID, true); err != nil {
			t.Error(err)
			return
		}
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
	rtA.hook.Store(&hook)
	a.Reconcile(ctx)
	if replacement == nil {
		t.Fatal("the replacement run never started")
	}
	got, _ := base.GetRun(ctx, replacement.ID)
	after, _ := base.GetSandbox(ctx, sb.ID)
	if got.Status != model.RunRunning || after.Status != model.StatusRunning || retiredByA.n.Load() != 0 {
		t.Fatalf("a stale lost-pod cleanup touched the replacement: run %s, sandbox %s (%s), identities retired %d times",
			got.Status, after.Status, after.Error, retiredByA.n.Load())
	}
	if n := round2Events(t, b, sb.ID, replacement.ID, model.EventRunDone); n != 0 {
		t.Fatalf("run.finished emitted %d times for a live run", n)
	}
	if o, _ := base.GetRun(ctx, old.ID); o.Status != model.RunCancelled {
		t.Fatalf("the lost pod's run: %s, want cancelled by the stop", o.Status)
	}
}

// afterRunningRunStore runs hook once, right after the next RunningRun has read its run.
type afterRunningRunStore struct {
	store.Store
	hook atomic.Pointer[func()]
}

func (s *afterRunningRunStore) RunningRun(ctx context.Context, sandboxID string) (*model.Run, error) {
	r, err := s.Store.RunningRun(ctx, sandboxID)
	if h := s.hook.Swap(nil); h != nil {
		(*h)()
	}
	return r, err
}

// Codex round 6 of #31, the orchestrator side: the lost-pod cleanup read the running run, then
// its runner finished it and a settings change bumped the sandbox's revision. On the memory
// store the fenced settle answered ErrConflict (run already settled) instead of ErrFenced, and
// the cleanup went on to retire identities and move the sandbox to error on a stale view.
func TestRound6StaleLostPodCleanupStopsWhenItsRunWasSettledToo(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRuntime()
	base := store.NewMemory()
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_r6", Slug: "dev", Tenant: "acme", Name: "s", Owner: "alice", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := fake.EnsureVolume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	var err error
	if sb.PodName, err = fake.CreatePod(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if err := base.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	hooked := &afterRunningRunStore{Store: base}
	a := New(hooked, fake, nil, events.New(), Config{}, nil)
	retiredByA := &countingRetirer{}
	a.Retirer = retiredByA
	b := New(base, fake, nil, events.New(), Config{}, nil)
	if _, err := b.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	run, err := b.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := base.GetSandbox(ctx, sb.ID)
	if err := fake.DeletePod(ctx, cur); err != nil { // the pod is lost
		t.Fatal(err)
	}
	hook := func() {
		// The cleanup has read the run. Meanwhile its runner finishes it, and a settings change
		// moves the sandbox to a newer revision (straight on the store: the cleanup holds the
		// tenant lock).
		if err := b.FinishRun(ctx, sb.ID, run.ID, 0, nil); err != nil {
			t.Error(err)
		}
		moved, _ := base.GetSandbox(ctx, sb.ID)
		moved.IdleTimeout = 600
		if err := base.UpdateSandbox(ctx, moved); err != nil {
			t.Error(err)
		}
	}
	hooked.hook.Store(&hook)
	a.Reconcile(ctx)
	if hooked.hook.Load() != nil {
		t.Fatal("the cleanup never read the running run")
	}
	after, _ := base.GetSandbox(ctx, sb.ID)
	if after.Status != model.StatusRunning || retiredByA.n.Load() != 0 {
		t.Fatalf("a stale cleanup went on: sandbox %s (%s), identities retired %d times", after.Status, after.Error, retiredByA.n.Load())
	}
	if got, _ := base.GetRun(ctx, run.ID); got.Status != model.RunDone {
		t.Fatalf("the run its runner finished: %s", got.Status)
	}
}
