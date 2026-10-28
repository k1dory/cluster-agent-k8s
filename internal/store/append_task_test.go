package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// A message joins a run's task only while the run is queued: once the runner claims it, the
// harness may already have read the task, and the caller must queue a new run instead.
func testAppendQueuedTask(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	sb := &model.Sandbox{ID: "append-sb", Name: "a", Slug: "dev", Owner: "alice", Tenant: "acme", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := s.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	run := &model.Run{ID: "append-run", SandboxID: sb.ID, Tenant: sb.Tenant, Slug: sb.Slug, Task: "add tests", Status: model.RunQueued, CreatedAt: now}
	if err := s.CreateRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	r, err := s.AppendQueuedTask(ctx, run.ID, "\n\nuse pytest")
	if err != nil || r.Task != "add tests\n\nuse pytest" || r.Status != model.RunQueued {
		t.Fatalf("append to a queued run: %v %+v", err, r)
	}
	claimed, err := s.ClaimQueuedRun(ctx, sb.ID, now)
	if err != nil || claimed.Task != "add tests\n\nuse pytest" {
		t.Fatalf("claim: %v %+v", err, claimed)
	}
	if _, err := s.AppendQueuedTask(ctx, run.ID, "\n\nlate"); !errors.Is(err, ErrConflict) {
		t.Fatalf("append to a claimed run: %v", err)
	}
	if got, _ := s.GetRun(ctx, run.ID); got.Task != "add tests\n\nuse pytest" || got.Status != model.RunRunning {
		t.Fatalf("claimed run changed: %+v", got)
	}
	if _, err := s.AppendQueuedTask(ctx, "run_nope", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown run: %v", err)
	}
}

func TestMemoryAppendQueuedTask(t *testing.T) { testAppendQueuedTask(t, NewMemory()) }

func TestPostgresAppendQueuedTask(t *testing.T) {
	testAppendQueuedTask(t, reviewOpenPostgres(t, reviewPostgresURL(t, false)))
}
