package orchestrator

import (
	"context"
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
