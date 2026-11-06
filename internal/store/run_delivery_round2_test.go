package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// round2Run is a sandbox with one queued run, in either store.
func round2Run(t *testing.T, s Store, id string) *model.Run {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	sb := &model.Sandbox{ID: "dl-" + id, Name: "dl-" + id, Slug: "dev", Owner: "alice", Tenant: "acme", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := s.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	r := &model.Run{ID: id, SandboxID: sb.ID, Tenant: sb.Tenant, Slug: sb.Slug, Task: "task", Status: model.RunQueued, CreatedAt: now}
	if err := s.CreateRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func round2Outputs(t *testing.T, s Store, r *model.Run) []string {
	t.Helper()
	evs, err := s.ListEvents(context.Background(), r.SandboxID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range evs {
		if e.RunID == r.ID && e.Type == model.EventRunOutput {
			out = append(out, e.Data)
		}
	}
	return out
}

func round2Lines(data ...string) []OutputLine {
	out := make([]OutputLine, len(data))
	for i, d := range data {
		out[i] = OutputLine{Data: d}
	}
	return out
}

// Wiki item 1 and 10: the lines of a batch, its usage and session and its progress are one
// write. The same batch posted at once through N replicas (a retry racing the original) stores
// one set of lines and one usage increment; the same id with another body is refused.
func TestRound2OutputBatchIsStoredOnce(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-batch")
		if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{Owner: "1"}); err != nil {
			t.Fatal(err)
		}
		batch := func() *OutputBatch {
			lines := round2Lines("a", "b", "u")
			lines[2].Usage = &model.Usage{InputTokens: 10, OutputTokens: 5, CostUSD: 0.5}
			lines[1].Session = "sess-1"
			return &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "b-1", Lines: lines}
		}
		var wg sync.WaitGroup
		results := make([]*OutputResult, 8)
		errs := make([]error, 8)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i], errs[i] = s.AppendRunOutput(ctx, batch())
			}(i)
		}
		wg.Wait()
		stored := 0
		for i, err := range errs {
			if err != nil {
				t.Fatalf("concurrent post %d: %v", i, err)
			}
			if results[i].Accepted > 0 {
				stored++
				if results[i].Accepted != 3 || results[i].Skipped != 0 || len(results[i].Events) != 3 {
					t.Fatalf("the post that stored: %+v", results[i])
				}
			} else if results[i].Skipped != 3 || len(results[i].Events) != 0 {
				t.Fatalf("a repeated post: %+v", results[i])
			}
		}
		if stored != 1 {
			t.Fatalf("%d of 8 identical posts stored the batch", stored)
		}
		got, err := s.GetRun(ctx, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if out := round2Outputs(t, s, r); len(out) != 3 || got.Usage.CostUSD != 0.5 || got.Usage.InputTokens != 10 || got.Session != "sess-1" {
			t.Fatalf("after 8 posts of one batch: outputs=%v usage=%+v session=%q", out, got.Usage, got.Session)
		}
		// Another body under the same id: refused, nothing stored.
		other := batch()
		other.Lines[0].Data = "changed"
		if _, err := s.AppendRunOutput(ctx, other); !errors.Is(err, ErrBatchMismatch) {
			t.Fatalf("same id, other body: %v", err)
		}
		short := batch()
		short.Lines = short.Lines[:2]
		if _, err := s.AppendRunOutput(ctx, short); !errors.Is(err, ErrBatchMismatch) {
			t.Fatalf("same id, fewer lines than stored: %v", err)
		}
		// The stored lines followed by more: a batch stored whole takes no longer body either
		// (TestRound2CompletedBatchTakesNoExtension).
		longer := batch()
		longer.Lines = append(longer.Lines, OutputLine{Data: "c"})
		if _, err := s.AppendRunOutput(ctx, longer); !errors.Is(err, ErrBatchMismatch) {
			t.Fatalf("a whole batch extended: %v", err)
		}
		got, _ = s.GetRun(ctx, r.ID)
		if out := round2Outputs(t, s, r); len(out) != 3 || got.Usage.CostUSD != 0.5 {
			t.Fatalf("after the refused bodies: outputs=%v usage=%+v", out, got.Usage)
		}
		// A run of another sandbox is not found.
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: "other", RunID: r.ID, Lines: round2Lines("x")}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("another sandbox's run: %v", err)
		}
	})
}

// Usage of a batch is applied the way RecordRunUsage applies it line by line: a total replaces,
// what follows it adds; a settled done run takes no more.
func TestRound2OutputBatchUsageOrder(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-usage")
		if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
			t.Fatal(err)
		}
		lines := round2Lines("a", "t", "b")
		lines[0].Usage = &model.Usage{InputTokens: 100}
		lines[1].Usage, lines[1].UsageTotal = &model.Usage{Model: "m", InputTokens: 7}, true
		lines[2].Usage = &model.Usage{OutputTokens: 3}
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, Lines: lines}); err != nil {
			t.Fatal(err)
		}
		got, _ := s.GetRun(ctx, r.ID)
		if got.Usage.InputTokens != 7 || got.Usage.OutputTokens != 3 || got.Usage.Model != "m" {
			t.Fatalf("total then delta: %+v", got.Usage)
		}
		if _, err := s.SettleRunWithEvents(ctx, Settle{RunID: r.ID, From: []model.RunStatus{model.RunRunning}, To: model.RunDone, FinishedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		late := round2Lines("late")
		late[0].Usage = &model.Usage{InputTokens: 1000}
		if res, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, Lines: late}); err != nil || res.Accepted != 1 {
			t.Fatalf("late output is stored: %v %+v", err, res)
		}
		if got, _ := s.GetRun(ctx, r.ID); got.Usage.InputTokens != 7 {
			t.Fatalf("a done run took usage: %+v", got.Usage)
		}
	})
}

// Wiki item 3: a claim whose response was lost is handed to the same owner again under a new
// attempt, never to another owner, until the owner confirms it; the earlier attempt is fenced.
func TestRound2ClaimIsReissuedToItsOwner(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-claim")
		c1, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{Owner: "1"})
		if err != nil || c1.Attempt != 1 {
			t.Fatalf("claim: %v %+v", err, c1)
		}
		if _, err := s.ReclaimRun(ctx, r.SandboxID, "2"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("another owner got the claim: %v", err)
		}
		if _, err := s.ReclaimRun(ctx, r.SandboxID, ""); !errors.Is(err, ErrNotFound) {
			t.Fatalf("an unnamed owner got the claim: %v", err)
		}
		// The owner asks again, several times at once (its retries racing): each gets the run
		// under its own attempt.
		var wg sync.WaitGroup
		attempts := make([]int, 4)
		for i := range attempts {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c, err := s.ReclaimRun(ctx, r.SandboxID, "1")
				if err != nil || c.ID != r.ID {
					t.Errorf("reclaim: %v %+v", err, c)
					return
				}
				attempts[i] = c.Attempt
			}(i)
		}
		wg.Wait()
		seen := map[int]bool{}
		for _, a := range attempts {
			if a < 2 || seen[a] {
				t.Fatalf("attempts handed out: %v", attempts)
			}
			seen[a] = true
		}
		cur, _ := s.GetRun(ctx, r.ID)
		if cur.Attempt != 5 || cur.Status != model.RunRunning {
			t.Fatalf("after four reclaims: %+v", cur)
		}
		// Every earlier attempt is fenced: no ack, no output, no settle.
		if err := s.AckRunClaim(ctx, r.ID, 1); !errors.Is(err, ErrStaleAttempt) {
			t.Fatalf("ack of a stale attempt: %v", err)
		}
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, Attempt: 1, Lines: round2Lines("x")}); !errors.Is(err, ErrStaleAttempt) {
			t.Fatalf("output of a stale attempt: %v", err)
		}
		if _, err := s.SettleRunWithEvents(ctx, Settle{RunID: r.ID, From: []model.RunStatus{model.RunRunning}, To: model.RunDone, FinishedAt: time.Now(), Attempt: 1,
			Events: []*model.Event{{SandboxID: r.SandboxID, RunID: r.ID, Type: model.EventRunDone}}}); !errors.Is(err, ErrStaleAttempt) || !errors.Is(err, ErrConflict) {
			t.Fatalf("settle of a stale attempt: %v", err)
		}
		if n := len(round2Outputs(t, s, r)); n != 0 {
			t.Fatalf("a stale attempt wrote %d lines", n)
		}
		// The current attempt confirms: the run is no longer handed out.
		if err := s.AckRunClaim(ctx, r.ID, 5); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ReclaimRun(ctx, r.SandboxID, "1"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a confirmed claim was handed out again: %v", err)
		}
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, Attempt: 5, Lines: round2Lines("x")}); err != nil {
			t.Fatalf("output of the current attempt: %v", err)
		}
		if _, err := s.SettleRunWithEvents(ctx, Settle{RunID: r.ID, From: []model.RunStatus{model.RunRunning}, To: model.RunDone, FinishedAt: time.Now(), Attempt: 5}); err != nil {
			t.Fatalf("settle of the current attempt: %v", err)
		}
		if err := s.AckRunClaim(ctx, "missing", 1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("ack of a missing run: %v", err)
		}
	})
}

// Wiki item 2: a transition and its events are one write. A settle that does not move the run
// appends none; one that does returns them with their ids and the run's tenant and slug.
func TestRound2SettleWritesItsEvents(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-settle")
		evs := func() []*model.Event {
			return []*model.Event{
				{SandboxID: r.SandboxID, RunID: r.ID, Type: model.EventRunCancel},
				{SandboxID: r.SandboxID, RunID: r.ID, Type: model.EventRunDone, Data: string(model.RunCancelled)},
			}
		}
		first := evs()
		got, err := s.SettleRunWithEvents(ctx, Settle{RunID: r.ID, From: []model.RunStatus{model.RunQueued, model.RunRunning}, To: model.RunCancelled, FinishedAt: time.Now(), Events: first})
		if err != nil || got.Status != model.RunCancelled {
			t.Fatalf("settle: %v %+v", err, got)
		}
		for _, e := range first {
			if e.ID == 0 || e.Tenant != "acme" || e.Slug != "dev" {
				t.Fatalf("event not stamped: %+v", e)
			}
		}
		if _, err := s.SettleRunWithEvents(ctx, Settle{RunID: r.ID, From: []model.RunStatus{model.RunQueued, model.RunRunning}, To: model.RunCancelled, FinishedAt: time.Now(), Events: evs()}); !errors.Is(err, ErrConflict) {
			t.Fatalf("second settle: %v", err)
		}
		if _, err := s.SettleRunWithEvents(ctx, Settle{RunID: "missing", From: []model.RunStatus{model.RunRunning}, To: model.RunDone}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("settle of a missing run: %v", err)
		}
		all, _ := s.ListEvents(ctx, r.SandboxID, 0, 100)
		if len(all) != 2 {
			t.Fatalf("events after a settle and a refused one: %+v", all)
		}
		// The repair of a missing command appends it once, however many replicas try at once.
		var wg sync.WaitGroup
		var mu sync.Mutex
		added := 0
		for range 6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := s.EnsureRunEvent(ctx, &model.Event{SandboxID: r.SandboxID, RunID: r.ID, Type: model.EventRunCancel})
				if err != nil {
					t.Error(err)
				}
				if ok {
					mu.Lock()
					added++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if added != 0 {
			t.Fatalf("run.cancel was already there, yet %d repairs appended one", added)
		}
		r2 := round2Run(t, s, "dl-settle2")
		if _, err := s.SettleRun(ctx, r2.ID, []model.RunStatus{model.RunQueued}, model.RunCancelled, 0, time.Now(), nil); err != nil {
			t.Fatal(err)
		}
		for range 6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := s.EnsureRunEvent(ctx, &model.Event{SandboxID: r2.SandboxID, RunID: r2.ID, Type: model.EventRunCancel})
				if err != nil {
					t.Error(err)
				}
				if ok {
					mu.Lock()
					added++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if added != 1 {
			t.Fatalf("six concurrent repairs appended %d run.cancel", added)
		}
	})
}

// Codex round 1 of #31, finding 4: a batch id whose body was stored whole took a longer body
// under the same id ("a", then "a" and a usage line): the usage was added. Only a body cut
// short by a 413 may be continued under its id.
func TestRound2CompletedBatchTakesNoExtension(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-ext")
		if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
			t.Fatal(err)
		}
		withUsage := round2Lines("a", "u")
		withUsage[1].Usage = &model.Usage{InputTokens: 10, CostUSD: 0.5}
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "whole", Lines: round2Lines("a")}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "whole", Lines: withUsage}); !errors.Is(err, ErrBatchMismatch) {
			t.Fatalf("a whole batch extended under its id: %v", err)
		}
		if res, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "whole", Lines: round2Lines("a")}); err != nil || res.Skipped != 1 || res.Accepted != 0 {
			t.Fatalf("the exact retry of a whole batch: %v %+v", err, res)
		}
		if got, _ := s.GetRun(ctx, r.ID); got.Usage.CostUSD != 0 {
			t.Fatalf("the refused extension added usage: %+v", got.Usage)
		}
		// A body cut short (413) is a prefix: the same id may carry the rest, once.
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "cut", Lines: round2Lines("a"), Partial: true}); err != nil {
			t.Fatal(err)
		}
		res, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "cut", Lines: withUsage})
		if err != nil || res.Skipped != 1 || res.Accepted != 1 {
			t.Fatalf("the rest of a cut batch: %v %+v", err, res)
		}
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "cut", Lines: append(withUsage, OutputLine{Data: "more"})}); !errors.Is(err, ErrBatchMismatch) {
			t.Fatalf("a cut batch, completed, extended again: %v", err)
		}
		if out, got := round2Outputs(t, s, r), func() *model.Run { g, _ := s.GetRun(ctx, r.ID); return g }(); len(out) != 3 || got.Usage.CostUSD != 0.5 {
			t.Fatalf("outputs=%v usage=%+v", out, got.Usage)
		}
	})
}

// failOnce returns a fault hook failing the first call at point, and a counter of the failures.
func failOnce(point string) (func(string) error, *int) {
	var mu sync.Mutex
	n := 0
	return func(p string) error {
		mu.Lock()
		defer mu.Unlock()
		if p == point && n == 0 {
			n++
			return errors.New("injected failure before the commit")
		}
		return nil
	}, &n
}

// Codex round 1 of #31, finding 5: a failure inside the transaction (after the lines, usage,
// session, progress and events are written, before the commit) leaves nothing behind, and the
// retry under the same batch id stores the batch exactly once.
func TestRound2OutputFailureBeforeCommitLeavesNothing(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-fault")
		if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
			t.Fatal(err)
		}
		hook, failed := failOnce(FaultOutput)
		SetFaultHook(s, hook)
		defer SetFaultHook(s, nil)
		batch := func() *OutputBatch {
			lines := round2Lines("a", "s", "u")
			lines[1].Session = "sess-f"
			lines[2].Usage = &model.Usage{InputTokens: 10, CostUSD: 0.5}
			return &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "b-f", Lines: lines}
		}
		if _, err := s.AppendRunOutput(ctx, batch()); err == nil || *failed != 1 {
			t.Fatalf("the injected failure: %v (failed %d)", err, *failed)
		}
		got, _ := s.GetRun(ctx, r.ID)
		if out := round2Outputs(t, s, r); len(out) != 0 || got.Usage.CostUSD != 0 || got.Session != "" {
			t.Fatalf("a failed batch left outputs=%v usage=%+v session=%q", out, got.Usage, got.Session)
		}
		res, err := s.AppendRunOutput(ctx, batch())
		if err != nil || res.Skipped != 0 || res.Accepted != 3 {
			t.Fatalf("the retry: %v %+v (its progress was rolled back too)", err, res)
		}
		if res, err := s.AppendRunOutput(ctx, batch()); err != nil || res.Skipped != 3 {
			t.Fatalf("a second retry: %v %+v", err, res)
		}
		got, _ = s.GetRun(ctx, r.ID)
		if out := round2Outputs(t, s, r); len(out) != 3 || got.Usage.CostUSD != 0.5 || got.Session != "sess-f" {
			t.Fatalf("after the retries: outputs=%v usage=%+v session=%q", out, got.Usage, got.Session)
		}
	})
}

// Finding 5, the settle: a failure before the commit leaves the run as it was and no events.
func TestRound2SettleFailureBeforeCommitLeavesNothing(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-sfault")
		if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
			t.Fatal(err)
		}
		hook, failed := failOnce(FaultSettle)
		SetFaultHook(s, hook)
		defer SetFaultHook(s, nil)
		settle := Settle{RunID: r.ID, From: []model.RunStatus{model.RunRunning}, To: model.RunCancelled, FinishedAt: time.Now(),
			Events: []*model.Event{{SandboxID: r.SandboxID, RunID: r.ID, Type: model.EventRunCancel}}}
		if _, err := s.SettleRunWithEvents(ctx, settle); err == nil || *failed != 1 {
			t.Fatalf("the injected failure: %v (failed %d)", err, *failed)
		}
		if got, _ := s.GetRun(ctx, r.ID); got.Status != model.RunRunning || got.FinishedAt != nil {
			t.Fatalf("a failed settle moved the run: %+v", got)
		}
		if evs, _ := s.ListEvents(ctx, r.SandboxID, 0, 100); len(evs) != 0 {
			t.Fatalf("a failed settle left events: %+v", evs)
		}
		settle.Events = []*model.Event{{SandboxID: r.SandboxID, RunID: r.ID, Type: model.EventRunCancel}}
		if got, err := s.SettleRunWithEvents(ctx, settle); err != nil || got.Status != model.RunCancelled {
			t.Fatalf("the retry: %v %+v", err, got)
		}
		if evs, _ := s.ListEvents(ctx, r.SandboxID, 0, 100); len(evs) != 1 || evs[0].Type != model.EventRunCancel {
			t.Fatalf("events after the retry: %+v", evs)
		}
	})
}

// Codex round 1 of #31, finding 2: the reclaim check and the claim were separate, so a retry
// overlapping the request whose response was lost could miss the claim of the first queued run
// and take the second. Decided together, every overlapping request of the owner gets the first.
func TestRound2ClaimDecisionIsSerialised(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		first := round2Run(t, s, "dl-ser")
		now := time.Now().UTC().Truncate(time.Microsecond)
		second := &model.Run{ID: "dl-ser-2", SandboxID: first.SandboxID, Tenant: "acme", Slug: "dev", Task: "next", Status: model.RunQueued,
			Mode: model.RunMessage, ResumeOf: first.ID, CreatedAt: now.Add(time.Second)}
		if err := s.CreateRun(ctx, second); err != nil {
			t.Fatal(err)
		}
		// Every request read the queue before any claimed: each names the run it saw first.
		var wg sync.WaitGroup
		got := make([]string, 8)
		for i := range got {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				target := first.ID
				if i%2 == 1 {
					target = second.ID // read after another request's claim moved the queue on
				}
				r, _, err := s.ClaimRunFor(ctx, first.SandboxID, target, time.Now(), "", RunStamp{Owner: "1"})
				if err != nil {
					if !errors.Is(err, ErrConflict) {
						t.Error(err)
					}
					return
				}
				got[i] = r.ID
			}(i)
		}
		wg.Wait()
		running := map[string]bool{}
		for _, id := range got {
			if id != "" {
				running[id] = true
			}
		}
		if len(running) != 1 {
			t.Fatalf("overlapping requests of one owner got runs %v", got)
		}
		// The first request may have taken the second run when it really was first in line here;
		// what matters is that no request after it took another one.
		remaining := first.ID
		if running[first.ID] {
			remaining = second.ID
		}
		if r, _ := s.GetRun(ctx, remaining); r.Status != model.RunQueued {
			t.Fatalf("both runs were claimed: %v", got)
		}
		// Another owner is not handed the unconfirmed claim: it takes the run still queued.
		r, reclaimed, err := s.ClaimRunFor(ctx, first.SandboxID, remaining, time.Now(), "", RunStamp{Owner: "2"})
		if err != nil || reclaimed || r.ID != remaining {
			t.Fatalf("another owner: %v reclaimed=%v %+v", err, reclaimed, r)
		}
	})
}

// Codex round 1 of #31, finding 1: event ids are drawn before the commit, and readers page by
// id. A transaction holding id N while another writer commits N+1 made the listener of another
// replica read past N, so output and run.finished vanished from live streams. The ids are now
// drawn under the events lock AppendEvent takes, held to the commit.
func TestRound2EventIdsBecomeVisibleInCommitOrder(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := round2Run(t, p, "dl-order")
	if _, err := p.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
		t.Fatal(err)
	}
	seen := make(chan *model.Event, 100)
	ready := make(chan struct{})
	go p.ListenEvents(ctx, func() { close(ready) }, func(e *model.Event) { seen <- e })
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("listener not ready")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	SetFaultHook(p, func(point string) error {
		if point == FaultSettle {
			once.Do(func() { close(entered); <-release }) // the settle's events are inserted, not committed
		}
		return nil
	})
	defer SetFaultHook(p, nil)
	settled := make(chan error, 1)
	go func() {
		_, err := p.SettleRunWithEvents(ctx, Settle{RunID: r.ID, From: []model.RunStatus{model.RunRunning}, To: model.RunDone, FinishedAt: time.Now(),
			Events: []*model.Event{{SandboxID: r.SandboxID, RunID: r.ID, Type: model.EventRunDone, Data: "done"}}})
		settled <- err
	}()
	<-entered
	appended := make(chan error, 1)
	go func() {
		appended <- p.AppendEvent(ctx, &model.Event{SandboxID: r.SandboxID, Tenant: "acme", Slug: "dev", Type: model.EventStatus, Data: "other writer"})
	}()
	want := map[string]bool{"done": false, "other writer": false}
	deadline := time.After(10 * time.Second)
	// Give the other writer, and the listener it wakes, every chance to run ahead: if its
	// commit gets through while the settle is open, wait until the listener has read past it.
	select {
	case err := <-appended:
		t.Logf("the other writer committed while the settle was open (%v)", err)
		for !want["other writer"] {
			select {
			case e := <-seen:
				want[e.Data] = true
			case <-deadline:
				t.Fatal("the listener never delivered the other writer's event")
			}
		}
	case <-time.After(500 * time.Millisecond): // it waits for the settle's commit: the fix
	}
	close(release)
	if err := <-settled; err != nil {
		t.Fatal(err)
	}
	for !want["done"] || !want["other writer"] {
		select {
		case e := <-seen:
			if _, ok := want[e.Data]; ok {
				want[e.Data] = true
			}
		case <-deadline:
			t.Fatalf("the listener never delivered: %v", want)
		}
	}
}
