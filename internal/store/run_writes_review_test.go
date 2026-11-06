package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// Run writes are conditional and narrow: a writer holding an older copy of a run can neither
// revive a settled run nor touch columns it does not own. Both stores run the same body so the
// memory store used by most tests behaves like Postgres.
func testRunWrites(t *testing.T, s Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	sb := &model.Sandbox{ID: "rw-sb", Name: "rw", Slug: "dev", Owner: "alice", Tenant: "acme", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := s.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	newRun := func(id string) *model.Run {
		r := &model.Run{ID: id, SandboxID: sb.ID, Tenant: sb.Tenant, Slug: sb.Slug, Task: "task " + id, Status: model.RunQueued,
			Mode: model.RunMessage, ResumeOf: "rw-prev", CreatedAt: now}
		if err := s.CreateRun(ctx, r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	// Identity columns are written once by CreateRun and never by a later transition.
	sameIdentity := func(t *testing.T, want *model.Run) {
		t.Helper()
		got, err := s.GetRun(ctx, want.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.SandboxID != want.SandboxID || got.Tenant != want.Tenant || got.Slug != want.Slug || got.Task != want.Task ||
			got.Mode != want.Mode || got.ResumeOf != want.ResumeOf || !got.CreatedAt.Equal(want.CreatedAt) {
			t.Fatalf("identity columns changed: %+v, want %+v", got, want)
		}
	}

	r := newRun("rw-1")
	stamp := RunStamp{AgentVersion: "img:2", AgentRef: "worker", AgentRevision: 3, EnvironmentRef: "base", EnvironmentRevision: 4}
	claimed, err := s.ClaimRun(ctx, r.ID, now, "sess-0", stamp)
	if err != nil || claimed.AgentVersion != "img:2" || claimed.AgentRevision != 3 || claimed.EnvironmentRef != "base" || claimed.EnvironmentRevision != 4 {
		t.Fatalf("claim stamps the run: %v %+v", err, claimed)
	}
	if err := s.RecordRunUsage(ctx, r.ID, model.Usage{Model: "m1", InputTokens: 10, Turns: 1}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordRunUsage(ctx, r.ID, model.Usage{InputTokens: 5, OutputTokens: 7, CostUSD: 0.5}, false); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetRun(ctx, r.ID)
	if got.Usage != (model.Usage{Model: "m1", InputTokens: 15, OutputTokens: 7, CostUSD: 0.5, Turns: 1}) {
		t.Fatalf("usage add: %+v", got.Usage)
	}
	if err := s.RecordRunUsage(ctx, r.ID, model.Usage{Model: "m2", InputTokens: 100}, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetRun(ctx, r.ID); got.Usage != (model.Usage{Model: "m2", InputTokens: 100}) {
		t.Fatalf("usage total replaces: %+v", got.Usage)
	}
	if err := s.SetRunSession(ctx, r.ID, "sess-1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetRun(ctx, r.ID); got.Session != "sess-1" || got.Status != model.RunRunning || got.AgentVersion != "img:2" {
		t.Fatalf("session write: %+v", got)
	}
	sameIdentity(t, r)

	// Settle: only from the listed statuses; usage nil keeps what was recorded.
	if _, err := s.SettleRun(ctx, r.ID, []model.RunStatus{model.RunQueued}, model.RunCancelled, 0, now, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("settle from a status the run is not in: %v", err)
	}
	done, err := s.SettleRun(ctx, r.ID, []model.RunStatus{model.RunRunning}, model.RunFailed, 3, now, nil)
	if err != nil || done.Status != model.RunFailed || done.ExitCode != 3 || done.FinishedAt == nil || done.Usage.InputTokens != 100 || done.Session != "sess-1" {
		t.Fatalf("settle: %v %+v", err, done)
	}
	if _, err := s.SettleRun(ctx, r.ID, []model.RunStatus{model.RunQueued, model.RunRunning}, model.RunCancelled, 0, now, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("second settle: %v", err)
	}
	if err := s.RecordRunUsage(ctx, r.ID, model.Usage{InputTokens: 1}, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("usage after the run finished: %v", err)
	}
	if got, _ := s.GetRun(ctx, r.ID); got.Status != model.RunFailed || got.Usage.InputTokens != 100 {
		t.Fatalf("finished run changed: %+v", got)
	}
	sameIdentity(t, r)
	if _, err := s.SettleRun(ctx, "rw-nope", []model.RunStatus{model.RunRunning}, model.RunDone, 0, now, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("settle a missing run: %v", err)
	}
	if err := s.RecordRunUsage(ctx, "rw-nope", model.Usage{}, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("usage of a missing run: %v", err)
	}
	if err := s.SetRunSession(ctx, "rw-nope", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session of a missing run: %v", err)
	}

	// A cancel racing a stream of usage lines: the run ends cancelled and no line is lost (a
	// cancelled harness still reports what it spent).
	r2 := newRun("rw-2")
	if _, err := s.ClaimRun(ctx, r2.ID, now, "", RunStamp{}); err != nil {
		t.Fatal(err)
	}
	const lines = 50
	var wg sync.WaitGroup
	for range lines {
		wg.Go(func() {
			if err := s.RecordRunUsage(ctx, r2.ID, model.Usage{OutputTokens: 1}, false); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Go(func() {
		if _, err := s.SettleRun(ctx, r2.ID, []model.RunStatus{model.RunRunning}, model.RunCancelled, 0, now, nil); err != nil {
			t.Error(err)
		}
	})
	wg.Wait()
	if got, _ := s.GetRun(ctx, r2.ID); got.Status != model.RunCancelled || got.FinishedAt == nil || got.Usage.OutputTokens != lines {
		t.Fatalf("cancel racing usage: %+v", got)
	}
	// And the final total a finish reports after the cancel is still recorded.
	if err := s.RecordRunUsage(ctx, r2.ID, model.Usage{OutputTokens: 80, CostUSD: 1}, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetRun(ctx, r2.ID); got.Status != model.RunCancelled || got.Usage.OutputTokens != 80 {
		t.Fatalf("total after cancel: %+v", got)
	}
	sameIdentity(t, r2)
}

func TestMemoryRunWrites(t *testing.T) { testRunWrites(t, NewMemory()) }

func TestPostgresRunWrites(t *testing.T) {
	testRunWrites(t, reviewOpenPostgres(t, reviewPostgresURL(t, false)))
}
