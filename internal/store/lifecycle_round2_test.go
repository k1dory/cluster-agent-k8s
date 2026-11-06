package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/store"
)

// lifecycleRunningRunHook runs hook once, right after the next RunningRun read: the moment between
// an idle stop's "no run in progress" and its move to stopping.
type lifecycleRunningRunHook struct {
	store.Store
	mu   sync.Mutex
	hook func()
}

func (s *lifecycleRunningRunHook) RunningRun(ctx context.Context, sandboxID string) (*model.Run, error) {
	s.mu.Lock()
	hook := s.hook
	s.hook = nil
	s.mu.Unlock()
	r, err := s.Store.RunningRun(ctx, sandboxID)
	if hook != nil {
		hook()
	}
	return r, err
}

// Two replicas on one database: replica A puts an idle sandbox to sleep while replica B's
// runner polls for work. B's claim used to land between A's "no run" and A's move to stopping,
// handing out a run on a pod being deleted. With the claim lock shared through Postgres, either
// the run stays queued (the sandbox sleeps) or the sleep is refused (the run executes).
func TestRound2PostgresSleepDoesNotRaceAClaimOnAnotherReplica(t *testing.T) {
	pg := lifecycleRound2Postgres(t)
	ctx := t.Context()
	rt := orchestrator.NewFakeRuntime()
	hooked := &lifecycleRunningRunHook{Store: pg}
	a := orchestrator.New(hooked, rt, nil, events.New(), orchestrator.Config{StopTimeout: 5 * time.Second}, nil)
	b := orchestrator.New(pg, rt, nil, events.New(), orchestrator.Config{StopTimeout: 5 * time.Second}, nil)
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_pgrace", Name: "race", Slug: "dev", Tenant: "acme", Owner: "alice", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := rt.EnsureVolume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	sb.PodName, _ = rt.CreatePod(ctx, sb)
	if err := pg.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	run, err := b.CreateRun(ctx, sb.ID, "task")
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		run *model.Run
		err error
	}
	done := make(chan result, 1)
	hooked.mu.Lock()
	hooked.hook = func() {
		got := make(chan result, 1)
		go func() {
			r, err := b.NextRun(context.Background(), sb.ID, time.Second)
			got <- result{r, err}
		}()
		select {
		case res := <-got:
			done <- res
		case <-time.After(400 * time.Millisecond):
			go func() { done <- <-got }()
		}
	}
	hooked.mu.Unlock()
	_, sleepErr := a.Sleep(ctx, sb.ID, false)
	claimed := <-done
	r, _ := pg.GetRun(ctx, run.ID)
	cur, _ := pg.GetSandbox(ctx, sb.ID)
	if claimed.err == nil && sleepErr == nil {
		t.Fatalf("run handed out on replica B (now %s) and the sandbox put to sleep on replica A (%s)", r.Status, cur.Status)
	}
	if sleepErr == nil && (r.Status != model.RunQueued || cur.Status != model.StatusSleeping) {
		t.Fatalf("after a sleep that went first: run %s, sandbox %s", r.Status, cur.Status)
	}
}
