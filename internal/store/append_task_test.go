package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// A message joins a run's task only while the run is queued: once the runner claims it, the
// harness may already have read the task, and the caller must queue a new run instead. A claim
// can be released back to the queue.
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
	// A claim the caller cannot go on with is undone: the run is queued again, claimable, and
	// accepts messages again.
	if err := s.ReleaseRun(ctx, run.ID); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got, _ := s.GetRun(ctx, run.ID); got.Status != model.RunQueued || got.StartedAt != nil {
		t.Fatalf("released run: %+v", got)
	}
	if err := s.ReleaseRun(ctx, run.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("release of a queued run: %v", err)
	}
	if err := s.ReleaseRun(ctx, "run_nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("release of an unknown run: %v", err)
	}
	if again, err := s.ClaimQueuedRun(ctx, sb.ID, now); err != nil || again.ID != run.ID {
		t.Fatalf("claim after release: %v %+v", err, again)
	}
}

// The claim NextRun makes: the oldest queued run is read, then claimed by id with the session
// it continues, in one conditional write. A second claim of the same run is refused; a session
// the run already has is kept.
func testClaimRun(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	sb := &model.Sandbox{ID: "claim-sb", Name: "c", Slug: "dev", Owner: "alice", Tenant: "acme", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := s.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	if _, err := s.QueuedRun(ctx, sb.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nothing queued: %v", err)
	}
	for i, id := range []string{"claim-1", "claim-2"} {
		r := &model.Run{ID: id, SandboxID: sb.ID, Tenant: sb.Tenant, Slug: sb.Slug, Task: id, Status: model.RunQueued,
			Mode: model.RunMessage, ResumeOf: "earlier", CreatedAt: now.Add(time.Duration(i) * time.Second)}
		if i == 1 {
			r.Session = "own"
		}
		if err := s.CreateRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	q, err := s.QueuedRun(ctx, sb.ID)
	if err != nil || q.ID != "claim-1" || q.Status != model.RunQueued {
		t.Fatalf("oldest queued: %v %+v", err, q)
	}
	r, err := s.ClaimRun(ctx, q.ID, now, "sess")
	if err != nil || r.Status != model.RunRunning || r.Session != "sess" || r.StartedAt == nil {
		t.Fatalf("claim: %v %+v", err, r)
	}
	if got, _ := s.GetRun(ctx, q.ID); got.Status != model.RunRunning || got.Session != "sess" {
		t.Fatalf("claim not stored: %+v", got)
	}
	if _, err := s.ClaimRun(ctx, q.ID, now, "sess"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second claim: %v", err)
	}
	if _, err := s.ClaimRun(ctx, "run_nope", now, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown run: %v", err)
	}
	if r, err := s.ClaimRun(ctx, "claim-2", now, "other"); err != nil || r.Session != "own" {
		t.Fatalf("a run's own session is kept: %v %+v", err, r)
	}
}

func TestMemoryClaimRun(t *testing.T) { testClaimRun(t, NewMemory()) }

func TestPostgresClaimRun(t *testing.T) {
	testClaimRun(t, reviewOpenPostgres(t, reviewPostgresURL(t, false)))
}

func TestMemoryAppendQueuedTask(t *testing.T) { testAppendQueuedTask(t, NewMemory()) }

func TestPostgresAppendQueuedTask(t *testing.T) {
	testAppendQueuedTask(t, reviewOpenPostgres(t, reviewPostgresURL(t, false)))
}
