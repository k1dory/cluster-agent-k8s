package orchestrator

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// staleRunStore runs hook once, right after the next GetRun returns: the caller now holds a copy
// that another writer makes stale before the caller writes.
type staleRunStore struct {
	store.Store
	hook atomic.Pointer[func()]
}

func (s *staleRunStore) GetRun(ctx context.Context, id string) (*model.Run, error) {
	r, err := s.Store.GetRun(ctx, id)
	if h := s.hook.Swap(nil); h != nil {
		(*h)()
	}
	return r, err
}

func (s *staleRunStore) arm(fn func()) { s.hook.Store(&fn) }

func runDoneEvents(t *testing.T, o *Orchestrator, sandboxID, runID string) int {
	t.Helper()
	evs, err := o.Store.ListEvents(context.Background(), sandboxID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if e.RunID == runID && e.Type == model.EventRunDone {
			n++
		}
	}
	return n
}

// A cancel landing between Output's read of the run and its write used to be overwritten by
// the stale copy (status running, finished_at NULL): the runner had already exited on
// run.cancel, so the run stayed running forever and blocked Sleep and deferred rollouts.
func TestReviewCancelDuringOutputStaysCancelled(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	st := &staleRunStore{Store: o.Store}
	o.Store = st
	ctx := context.Background()
	if _, err := o.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	run, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	st.arm(func() {
		if _, err := o.CancelRun(ctx, sb.ID, run.ID); err != nil {
			t.Error(err)
		}
	})
	if err := o.Output(ctx, sb.ID, run.ID, `{"type":"usage","output_tokens":7}`); err != nil {
		t.Fatal(err)
	}
	// Output no longer reads the run before writing (the line and its usage are one store
	// write), so the window is gone: the cancel lands right after it instead, if it has not.
	if h := st.hook.Swap(nil); h != nil {
		(*h)()
	}
	got, err := o.Store.GetRun(ctx, run.ID)
	if err != nil || got.Status != model.RunCancelled || got.FinishedAt == nil {
		t.Fatalf("run after cancel during output: %v %+v", err, got)
	}
	if got.Usage.OutputTokens != 7 {
		t.Fatalf("usage reported while cancelling was lost: %+v", got.Usage)
	}
	if _, err := o.Store.RunningRun(ctx, sb.ID); err == nil {
		t.Fatal("a cancelled run still counts as running")
	}
	if _, err := o.Sleep(ctx, sb.ID, false); err != nil {
		t.Fatalf("sleep after the run was cancelled: %v", err)
	}
	if n := runDoneEvents(t, o, sb.ID, run.ID); n != 1 {
		t.Fatalf("run.finished emitted %d times", n)
	}
}

// A finish whose read predates a cancel neither revives the run nor emits a second
// run.finished, and the usage total the harness reports is still recorded.
func TestReviewFinishRacingCancelKeepsUsage(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	st := &staleRunStore{Store: o.Store}
	o.Store = st
	ctx := context.Background()
	if _, err := o.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	run, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	st.arm(func() {
		if _, err := o.CancelRun(ctx, sb.ID, run.ID); err != nil {
			t.Error(err)
		}
	})
	usage := model.Usage{Model: "m", InputTokens: 40, OutputTokens: 9, CostUSD: 0.2}
	if err := o.FinishRun(ctx, sb.ID, run.ID, 0, &usage); err != nil {
		t.Fatal(err)
	}
	got, err := o.Store.GetRun(ctx, run.ID)
	if err != nil || got.Status != model.RunCancelled || got.Usage != usage {
		t.Fatalf("run after finish racing cancel: %v %+v", err, got)
	}
	if n := runDoneEvents(t, o, sb.ID, run.ID); n != 1 {
		t.Fatalf("run.finished emitted %d times", n)
	}
	// The reverse order: a cancel whose read predates the finish leaves the finished result.
	if _, err := o.CreateRun(ctx, sb.ID, "task 2"); err != nil {
		t.Fatal(err)
	}
	run2, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	st.arm(func() {
		if err := o.FinishRun(ctx, sb.ID, run2.ID, 0, &usage); err != nil {
			t.Error(err)
		}
	})
	r, err := o.CancelRun(ctx, sb.ID, run2.ID)
	if err != nil || r.Status != model.RunDone || r.Usage != usage {
		t.Fatalf("cancel racing finish: %v %+v", err, r)
	}
	if n := runDoneEvents(t, o, sb.ID, run2.ID); n != 1 {
		t.Fatalf("run.finished emitted %d times", n)
	}
}

// claimHookStore runs hook once, right after the store claimed a run and before NextRun
// resumes: another writer acting on the freshly claimed run.
type claimHookStore struct {
	store.Store
	hook func(r *model.Run)
}

func (s *claimHookStore) ClaimRun(ctx context.Context, runID string, startedAt time.Time, session string, stamp store.RunStamp) (*model.Run, error) {
	r, err := s.Store.ClaimRun(ctx, runID, startedAt, session, stamp)
	if h := s.hook; h != nil && err == nil {
		s.hook = nil
		h(r)
	}
	return r, err
}

// ClaimRunFor is the claim NextRun makes (with the reclaim check): the same hook.
func (s *claimHookStore) ClaimRunFor(ctx context.Context, sandboxID, runID string, startedAt time.Time, session string, stamp store.RunStamp) (*model.Run, bool, error) {
	r, reclaimed, err := s.Store.ClaimRunFor(ctx, sandboxID, runID, startedAt, session, stamp)
	if h := s.hook; h != nil && err == nil {
		s.hook = nil
		h(r)
	}
	return r, reclaimed, err
}

// The claim stamps what executes the run in the same write. NextRun used to stamp it with a
// second, full-row write from its copy afterwards: a usage line or a cancel landing between
// the claim and that write was overwritten (the run back to running with no usage).
func TestReviewClaimStampsAgentVersion(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	ctx := context.Background()
	if _, err := o.mutate(ctx, sb.ID, func(s *model.Sandbox) error {
		s.AgentVersion, s.AgentRef, s.AgentRevision, s.EnvironmentRef, s.EnvironmentRevision = "img:7", "worker", 2, "base", 5
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	hs := &claimHookStore{Store: o.Store}
	o.Store = hs
	hs.hook = func(r *model.Run) {
		if err := o.Output(ctx, sb.ID, r.ID, `{"type":"usage","output_tokens":3}`); err != nil {
			t.Error(err)
		}
		if _, err := o.CancelRun(ctx, sb.ID, r.ID); err != nil {
			t.Error(err)
		}
	}
	if _, err := o.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	run, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil || run.AgentVersion != "img:7" || run.AgentRevision != 2 || run.EnvironmentRevision != 5 {
		t.Fatalf("claimed run: %v %+v", err, run)
	}
	got, _ := o.Store.GetRun(ctx, run.ID)
	if got.Status != model.RunCancelled || got.FinishedAt == nil || got.Usage.OutputTokens != 3 {
		t.Fatalf("cancel and usage recorded between the claim and NextRun's return were lost: %+v", got)
	}
	if got.AgentVersion != "img:7" || got.AgentRef != "worker" || got.EnvironmentRef != "base" {
		t.Fatalf("stamp: %+v", got)
	}
}
