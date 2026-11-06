package store_test

import (
	"context"
	"errors"
	"strings"
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
// handing out a run on a pod being deleted. The replicas are two stores (own pools, own lock
// limiters), so only a lock held in the database keeps them apart. Exactly one outcome is valid:
// the sleep went first (the run stays queued, the claim found nothing), or the claim did (the
// sleep is refused as a conflict, the run executes on a running sandbox).
func TestRound2PostgresSleepDoesNotRaceAClaimOnAnotherReplica(t *testing.T) {
	dsn := lifecycleRound2Schema(t)
	pgA, pgB := lifecycleRound2Open(t, dsn), lifecycleRound2Open(t, dsn)
	ctx := t.Context()
	rt := orchestrator.NewFakeRuntime()
	hooked := &lifecycleRunningRunHook{Store: pgA}
	a := orchestrator.New(hooked, rt, nil, events.New(), orchestrator.Config{StopTimeout: 5 * time.Second}, nil)
	b := orchestrator.New(pgB, rt, nil, events.New(), orchestrator.Config{StopTimeout: 5 * time.Second}, nil)
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_pgrace", Name: "race", Slug: "dev", Tenant: "acme", Owner: "alice", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := rt.EnsureVolume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	sb.PodName, _ = rt.CreatePod(ctx, sb)
	if err := pgA.CreateSandbox(ctx, sb); err != nil {
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
	r, err := pgB.GetRun(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := pgB.GetSandbox(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	sleptFirst := sleepErr == nil && errors.Is(claimed.err, store.ErrNotFound) &&
		r.Status == model.RunQueued && cur.Status == model.StatusSleeping
	claimedFirst := claimed.err == nil && claimed.run != nil && claimed.run.ID == run.ID &&
		errors.Is(sleepErr, orchestrator.ErrConflict) && strings.Contains(sleepErr.Error(), "a run is in progress") &&
		r.Status == model.RunRunning && cur.Status == model.StatusRunning
	if !sleptFirst && !claimedFirst {
		t.Fatalf("sleep: %v; claim: %+v, %v; run %s, sandbox %s", sleepErr, claimed.run, claimed.err, r.Status, cur.Status)
	}
}
