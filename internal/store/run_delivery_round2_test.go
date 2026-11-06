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
		r, start, err := s.ClaimRunFor(ctx, first.SandboxID, remaining, time.Now(), "", RunStamp{Owner: "2"})
		if err != nil || start == nil || r.ID != remaining {
			t.Fatalf("another owner: %v start=%v %+v", err, start, r)
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

// Codex round 2 of #31, finding 1: the reclaim chose its candidate in a subquery and updated it
// by id. Under Read Committed a reclaim that waited on an acknowledgement (or a settle) holding
// the row then bumped the attempt of the row as committed, confirmed (or done): the executing
// runner was fenced out. The candidates are locked and read again before deciding.
func TestRound2ReclaimWaitsForTheRowItDecidesOn(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := context.Background()
	for _, tc := range []struct {
		name, sql string
		want      model.RunStatus
		acked     bool
	}{
		{"acknowledgement", `UPDATE runs SET claim_acked=true WHERE id=$1`, model.RunRunning, true},
		{"settle", `UPDATE runs SET status='done', finished_at=now() WHERE id=$1`, model.RunDone, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := round2Run(t, p, "dl-lock-"+tc.name)
			if _, err := p.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{Owner: "1"}); err != nil {
				t.Fatal(err)
			}
			tx, err := p.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err := tx.Exec(ctx, tc.sql, r.ID); err != nil {
				t.Fatal(err)
			}
			type result struct {
				r   *model.Run
				err error
			}
			done := make(chan result, 1)
			go func() {
				got, err := p.ReclaimRun(ctx, r.SandboxID, "1")
				done <- result{got, err}
			}()
			select {
			case res := <-done:
				t.Fatalf("the reclaim did not wait for the open %s: %+v %v", tc.name, res.r, res.err)
			case <-time.After(300 * time.Millisecond):
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			res := <-done
			if !errors.Is(res.err, ErrNotFound) {
				t.Fatalf("a reclaim after the %s committed: %+v %v", tc.name, res.r, res.err)
			}
			got, _ := p.GetRun(ctx, r.ID)
			if got.Attempt != 1 || got.Status != tc.want || got.ClaimAcked != tc.acked {
				t.Fatalf("the run after a reclaim raced the %s: %+v", tc.name, got)
			}
		})
	}
}

// Codex round 2 of #31, finding 4 (store side): an owner executing a confirmed run is busy.
func TestRound2ConfirmedRunMakesItsOwnerBusy(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-busy")
		c, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{Owner: "1"})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AckRunClaim(ctx, r.ID, c.Attempt); err != nil {
			t.Fatal(err)
		}
		next := &model.Run{ID: "dl-busy-2", SandboxID: r.SandboxID, Tenant: "acme", Slug: "dev", Task: "t", Status: model.RunQueued, CreatedAt: time.Now()}
		if err := s.CreateRun(ctx, next); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.ClaimRunFor(ctx, r.SandboxID, next.ID, time.Now(), "", RunStamp{Owner: "1"}); !errors.Is(err, ErrOwnerBusy) || !errors.Is(err, ErrNotFound) {
			t.Fatalf("a claim of a busy owner: %v", err)
		}
		if got, _ := s.GetRun(ctx, next.ID); got.Status != model.RunQueued {
			t.Fatalf("the busy owner's claim took the run: %+v", got)
		}
		if _, _, err := s.ClaimRunFor(ctx, r.SandboxID, next.ID, time.Now(), "", RunStamp{Owner: "2"}); err != nil {
			t.Fatalf("another owner: %v", err)
		}
	})
}

// Codex round 2 of #31, finding 3: a body cut off by a 413 under the id of a batch stored whole
// was accepted as its prefix and reset the batch to partial, so a third body extended it. A
// batch stored whole stays whole and takes only the same whole body.
func TestRound2CutBodyCannotReopenAWholeBatch(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-reopen")
		if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
			t.Fatal(err)
		}
		post := func(partial bool, lines []OutputLine) error {
			_, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "B", Lines: lines, Partial: partial})
			return err
		}
		if err := post(false, round2Lines("a")); err != nil {
			t.Fatal(err)
		}
		if err := post(true, round2Lines("a")); !errors.Is(err, ErrBatchMismatch) { // "a" + an oversized line
			t.Fatalf("a cut body under a whole batch's id: %v", err)
		}
		withUsage := round2Lines("a", "u")
		withUsage[1].Usage = &model.Usage{InputTokens: 10, CostUSD: 0.5}
		if err := post(false, withUsage); !errors.Is(err, ErrBatchMismatch) {
			t.Fatalf("the third body: %v", err)
		}
		if err := post(false, round2Lines("a")); err != nil {
			t.Fatalf("the same whole body again: %v", err)
		}
		got, _ := s.GetRun(ctx, r.ID)
		if out := round2Outputs(t, s, r); len(out) != 1 || got.Usage.CostUSD != 0 {
			t.Fatalf("outputs=%v usage=%+v", out, got.Usage)
		}
	})
}

// ageBatch moves the last call under a batch id d into the past (both forms of its progress).
func ageBatch(t *testing.T, s Store, runID, batchID string, d time.Duration) {
	t.Helper()
	switch st := s.(type) {
	case *Memory:
		st.mu.Lock()
		defer st.mu.Unlock()
		k := runID + "|" + batchID
		v, ok := st.batches[k]
		if !ok {
			t.Fatalf("no batch %s", k)
		}
		v.at = v.at.Add(-d)
		st.batches[k] = v
		if l, ok := st.idem[legacyBatchKey(runID, batchID)]; ok { // the form older replicas read
			l.CreatedAt = l.CreatedAt.Add(-d)
		}
	case *Postgres:
		tag, err := st.pool.Exec(context.Background(), `UPDATE run_output_batches SET touched_at = touched_at - $3::interval WHERE run_id=$1 AND batch_id=$2`,
			runID, batchID, d.String())
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("age batch: %v %v", err, tag)
		}
		if _, err := st.pool.Exec(context.Background(), `UPDATE idempotency SET created_at = created_at - $2::interval WHERE key=$1`,
			legacyBatchKey(runID, batchID), d.String()); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("store %T", s)
	}
}

// Codex round 2 of #31, finding 5: Postgres counted a batch's retention from its first call,
// memory from its last. A batch retried for longer than the retention (lost acknowledgements
// for a day) was dropped by another batch's cleanup on Postgres, and its next retry stored the
// lines and usage again. Both stores count from the last call now.
func TestRound2BatchRetentionIsRenewedByItsRetries(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-ttl")
		if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
			t.Fatal(err)
		}
		lines := round2Lines("a", "u")
		lines[1].Usage = &model.Usage{InputTokens: 10, CostUSD: 0.5}
		post := func(id string, l []OutputLine) *OutputResult {
			res, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: id, Lines: l})
			if err != nil {
				t.Fatal(err)
			}
			return res
		}
		post("B", lines)
		almost := outputBatchTTL - time.Hour
		ageBatch(t, s, r.ID, "B", almost)
		post("B", lines) // a retry (its acknowledgement was lost again)
		ageBatch(t, s, r.ID, "B", almost)
		post("C", round2Lines("c")) // another batch: its cleanup drops expired progress
		if res := post("B", lines); res.Skipped != 2 || res.Accepted != 0 {
			t.Fatalf("a batch retried within the retention was dropped: %+v", res)
		}
		// Not retried for longer than the retention: dropped on both stores alike.
		ageBatch(t, s, r.ID, "B", outputBatchTTL+time.Hour)
		post("D", round2Lines("d"))
		if res := post("B", lines); res.Skipped != 0 {
			t.Fatalf("an expired batch was kept: %+v", res)
		}
	})
}

// Codex round 3 of #31, finding 2: a release before run_output_batches recorded a batch's
// progress as an idempotency record (status = lines stored, no hash). A batch an older server
// stored, retried after the upgrade, was stored again with its usage. The legacy record is
// read when there is no new one, and written alongside it for older replicas of a rollout.
func TestRound2LegacyBatchProgressSurvivesTheUpgrade(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-legacy")
		if _, err := s.ClaimRun(ctx, r.ID, time.Now(), "", RunStamp{}); err != nil {
			t.Fatal(err)
		}
		// What the older release did for "a\n<usage>\n" under X-Batch-Id B: the lines, the
		// usage, then the progress record. Its response was lost.
		for _, d := range []string{"a", "u"} {
			if err := s.AppendEvent(ctx, &model.Event{SandboxID: r.SandboxID, Tenant: "acme", Slug: "dev", RunID: r.ID, Type: model.EventRunOutput, Data: d}); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.RecordRunUsage(ctx, r.ID, model.Usage{InputTokens: 10, CostUSD: 0.5}, false); err != nil {
			t.Fatal(err)
		}
		if err := s.PutIdempotent(ctx, &Idempotent{Key: "batch|" + r.ID + "|B", Status: 2, Body: []byte{}}); err != nil {
			t.Fatal(err)
		}
		lines := round2Lines("a", "u")
		lines[1].Usage = &model.Usage{InputTokens: 10, CostUSD: 0.5}
		res, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "B", Lines: lines})
		if err != nil || res.Skipped != 2 || res.Accepted != 0 {
			t.Fatalf("the retry after the upgrade: %v %+v", err, res)
		}
		got, _ := s.GetRun(ctx, r.ID)
		if out := round2Outputs(t, s, r); len(out) != 2 || got.Usage.CostUSD != 0.5 {
			t.Fatalf("after the retry: outputs=%v usage=%+v", out, got.Usage)
		}
		// The other way round: what this release stores, an older replica of the rollout skips.
		if _, err := s.AppendRunOutput(ctx, &OutputBatch{SandboxID: r.SandboxID, RunID: r.ID, BatchID: "C", Lines: round2Lines("x", "y", "z")}); err != nil {
			t.Fatal(err)
		}
		if rec, err := s.GetIdempotent(ctx, "batch|"+r.ID+"|C"); err != nil || rec.Status != 3 {
			t.Fatalf("the progress an older replica reads: %v %+v", err, rec)
		}
	})
}

// Codex round 3 of #31, finding 4 (store side): the claim appends its run.start in its own
// transaction; a reclaim appends none.
func TestRound2ClaimWritesItsRunStart(t *testing.T) {
	bothStores(t, func(t *testing.T, s Store) {
		ctx := context.Background()
		r := round2Run(t, s, "dl-start")
		c, start, err := s.ClaimRunFor(ctx, r.SandboxID, r.ID, time.Now(), "", RunStamp{Owner: "1", AgentVersion: "img:3"})
		if err != nil || start == nil || start.ID == 0 || start.Data != "img:3" || start.Tenant != "acme" {
			t.Fatalf("claim: %v %+v %+v", err, c, start)
		}
		if again, start, err := s.ClaimRunFor(ctx, r.SandboxID, "", time.Now(), "", RunStamp{Owner: "1"}); err != nil || start != nil || again.ID != r.ID {
			t.Fatalf("reclaim: %v %+v %+v", err, again, start)
		}
		evs, _ := s.ListEvents(ctx, r.SandboxID, 0, 100)
		if len(evs) != 1 || evs[0].Type != model.EventRunStart || evs[0].RunID != r.ID {
			t.Fatalf("events after a claim and a reclaim: %+v", evs)
		}
	})
}
