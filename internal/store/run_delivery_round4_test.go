package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// oldAppendEventSQL is AppendEvent as a release before #31 sends it: a bare INSERT with no
// events lock. During a rolling update those replicas keep writing next to the new ones.
const oldAppendEventSQL = `WITH ins AS (
		INSERT INTO events (sandbox_id, tenant, slug, run_id, type, data, at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id)
	SELECT id FROM ins, pg_notify('` + eventsChannel + `', id::text)`

// Codex round 4 of #31, finding 2: only the new code took the events lock. A new transaction
// held event N uncommitted while an older replica's bare INSERT drew N+1 and committed: the
// listeners moved past N and never published it (run.finished included). The database's
// trigger now draws every id under the lock, so the bare INSERT waits for the open commit and
// gets the higher id.
func TestRound4BareInsertOfAnOlderReplicaWaitsForTheOpenEvent(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := context.Background()
	r := round2Run(t, p, "dl-r4-order")
	if _, err := p.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	SetFaultHook(p, func(point string) error {
		if point == FaultSettle {
			once.Do(func() { close(entered); <-release }) // the settle's event is inserted, not committed
		}
		return nil
	})
	defer SetFaultHook(p, nil)
	done := &model.Event{SandboxID: r.SandboxID, RunID: r.ID, Type: model.EventRunDone, Data: "done"}
	settled := make(chan error, 1)
	go func() {
		_, err := p.SettleRunWithEvents(ctx, Settle{RunID: r.ID, From: []model.RunStatus{model.RunRunning}, To: model.RunDone,
			FinishedAt: time.Now(), Events: []*model.Event{done}})
		settled <- err
	}()
	<-entered
	var oldID int64
	inserted := make(chan error, 1)
	go func() {
		inserted <- p.pool.QueryRow(ctx, oldAppendEventSQL, r.SandboxID, "acme", "dev", "", model.EventStatus, "older replica", time.Now()).Scan(&oldID)
	}()
	select {
	case err := <-inserted:
		close(release)
		<-settled
		t.Fatalf("the older replica's bare INSERT committed id %d while event %d was still open (%v)", oldID, done.ID, err)
	case <-time.After(500 * time.Millisecond): // it waits for the open transaction's commit
	}
	close(release)
	if err := <-settled; err != nil {
		t.Fatal(err)
	}
	if err := <-inserted; err != nil {
		t.Fatal(err)
	}
	if oldID <= done.ID {
		t.Fatalf("the later insert got id %d, not above the open event's %d", oldID, done.ID)
	}
}

// Codex round 4 of #31, finding 3: once this release had written a batch's progress, the
// legacy record was no longer read. A new replica stored a cut-off body ("a"); an older replica
// of the rollout accepted its continuation ("a" plus a usage line) and moved only the legacy
// count to 2; that response was lost, and the retry on a new replica stored the usage again.
func TestRound4LegacyContinuationOfANewBatchIsNotStoredTwice(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-r4-mixed")
		if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "B", Lines: round2Lines("a"), Partial: true}); err != nil {
			t.Fatal(err)
		}
		// The older replica: it reads the legacy count (1), stores the rest, then the count.
		if err := s.AppendEvent(ctx, &model.Event{SandboxID: r.SandboxID, Tenant: "acme", Slug: "dev", RunID: r.ID, Type: model.EventRunOutput, Data: "u"}); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordRunUsage(ctx, r.ID, model.Usage{InputTokens: 10, CostUSD: 0.5}, false); err != nil {
			t.Fatal(err)
		}
		if err := s.PutIdempotent(ctx, &Idempotent{Key: legacyBatchKey(r.ID, "B"), Status: 2, Body: []byte{}}); err != nil {
			t.Fatal(err)
		}
		lines := round2Lines("a", "u")
		lines[1].Usage = &model.Usage{InputTokens: 10, CostUSD: 0.5}
		res, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "B", Lines: lines})
		if err != nil || res.Skipped != 2 || res.Accepted != 0 {
			t.Fatalf("the retry on a new replica: %v %+v", err, res)
		}
		got, _ := s.GetRun(ctx, r.ID)
		if out := round2Outputs(t, s, r); len(out) != 2 || got.Usage.CostUSD != 0.5 || got.Usage.InputTokens != 10 {
			t.Fatalf("after new, old, new: outputs=%v usage=%+v", out, got.Usage)
		}
		// The prefix this release recorded is still checked: another first line is refused.
		other := round2Lines("x", "u")
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "B", Lines: other}); !errors.Is(err, ErrBatchMismatch) {
			t.Fatalf("another body under the id: %v", err)
		}
	})
}

// Codex round 4 of #31, finding 4: neither store checked the age of a batch's progress when it
// looked it up. Memory dropped expired progress on every batch call, Postgres only after a new
// batch was accepted, so an expired batch was stored again in one store and skipped (or
// refused) in the other, depending on unrelated traffic. Expiry is now decided at the lookup.
func TestRound4BatchExpiryIsDecidedAtTheLookup(t *testing.T) {
	expired := outputBatchTTL + time.Hour
	for _, tc := range []struct {
		name string
		body func(t *testing.T, s Store, post func(id string, l []OutputLine, partial bool) *OutputResult, age func(id string))
	}{
		{"direct", func(t *testing.T, _ Store, post func(string, []OutputLine, bool) *OutputResult, age func(string)) {
			post("B", round2Lines("a", "b"), false)
			age("B")
			if res := post("B", round2Lines("a", "b"), false); res.Skipped != 0 || res.Accepted != 2 {
				t.Fatalf("an expired batch, posted again with no call in between: %+v", res)
			}
			// A whole batch, once expired, does not keep refusing a cut-off body either.
			age("B")
			if res := post("B", round2Lines("a"), true); res.Skipped != 0 || res.Accepted != 1 {
				t.Fatalf("a cut-off body under an expired whole batch: %+v", res)
			}
		}},
		{"retry-only traffic", func(t *testing.T, _ Store, post func(string, []OutputLine, bool) *OutputResult, age func(string)) {
			// Only a retry of another batch in between: memory used to clean up on it, Postgres not.
			post("C", round2Lines("c"), false)
			post("D", round2Lines("d1", "d2"), false)
			age("C")
			if res := post("D", round2Lines("d1", "d2"), false); res.Skipped != 2 || res.Accepted != 0 {
				t.Fatalf("a retry within the retention: %+v", res)
			}
			if res := post("C", round2Lines("c"), false); res.Skipped != 0 || res.Accepted != 1 {
				t.Fatalf("an expired batch after retry-only traffic: %+v", res)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bothStores(t, func(t *testing.T, s Store) {
				ctx := context.Background()
				r := round2Run(t, s, "dl-r4-ttl")
				if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
					t.Fatal(err)
				}
				post := func(id string, l []OutputLine, partial bool) *OutputResult {
					t.Helper()
					res, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: id, Lines: l, Partial: partial})
					if err != nil {
						t.Fatalf("batch %s: %v", id, err)
					}
					return res
				}
				tc.body(t, s, post, func(id string) { ageBatch(t, s, r.ID, id, expired) })
			})
		})
	}
}

// Codex round 6 of #31: the memory store answered ErrConflict for a run already settled before
// it looked at the sandbox fence, while Postgres checks the fence first. A cleanup whose
// observation went stale (the sandbox's revision moved) and whose run was settled meanwhile
// took the conflict for "settled elsewhere" on memory and went on. Both stores say ErrFenced.
func TestRound6StaleFenceWinsOverASettledRun(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-r6-fence")
		if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
			t.Fatal(err)
		}
		seen, err := s.GetSandbox(ctx, r.SandboxID)
		if err != nil {
			t.Fatal(err)
		}
		// Meanwhile: the runner finishes the run, and a settings change bumps the revision.
		if _, err := s.SettleRunWithEvents(ctx, Settle{RunID: r.ID, From: []model.RunStatus{model.RunRunning}, To: model.RunDone, FinishedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		moved := *seen
		moved.IdleTimeout = 600
		if err := s.UpdateSandbox(ctx, &moved); err != nil {
			t.Fatal(err)
		}
		_, err = s.SettleRunWithEvents(ctx, Settle{RunID: r.ID, From: []model.RunStatus{model.RunRunning}, To: model.RunFailed, FinishedAt: time.Now(),
			Sandbox: &SandboxFence{ID: seen.ID, Status: seen.Status, Revision: seen.Revision}})
		if !errors.Is(err, ErrFenced) {
			t.Fatalf("a stale fence over a settled run: %v, want ErrFenced", err)
		}
		if got, _ := s.GetRun(ctx, r.ID); got.Status != model.RunDone {
			t.Fatalf("the run: %s", got.Status)
		}
	})
}
