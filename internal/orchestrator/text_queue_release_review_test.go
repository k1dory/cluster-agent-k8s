package orchestrator

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// One storage interruption covers the session read and the compensating write.
// No external database or process is affected by this fixture.
type reviewSessionOutageStore struct {
	store.Store
	predecessor string
	outage      atomic.Bool
}

func (s *reviewSessionOutageStore) GetRun(ctx context.Context, id string) (*model.Run, error) {
	if id == s.predecessor && s.outage.Load() {
		return nil, errors.New("fixture: store unavailable during session read")
	}
	return s.Store.GetRun(ctx, id)
}

func (s *reviewSessionOutageStore) ReleaseRun(ctx context.Context, id string) error {
	if s.outage.Load() {
		return errors.New("fixture: store still unavailable during release")
	}
	return s.Store.ReleaseRun(ctx, id)
}

func TestReviewTextResumeRemainsClaimableAfterReleaseFailure(t *testing.T) {
	ctx := t.Context()
	st := &reviewSessionOutageStore{Store: store.NewMemory()}
	o, sb := reviewTextQueueSandbox(t, st)
	first, _, err := o.Say(ctx, sb.ID, "inspect the fixture project")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.NextRun(ctx, sb.ID, 0); err != nil {
		t.Fatal(err)
	}
	next, _, err := o.Say(ctx, sb.ID, "add tests for the findings")
	if err != nil || next == nil || next.ID == first.ID || next.Status != model.RunQueued {
		t.Fatalf("follow-up was not queued: %+v, %v", next, err)
	}
	if err := o.Output(ctx, sb.ID, first.ID, `{"type":"system","subtype":"init","session_id":"fixture-session"}`); err != nil {
		t.Fatal(err)
	}
	if err := o.FinishRun(ctx, sb.ID, first.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	st.predecessor = first.ID
	st.outage.Store(true)
	if got, err := o.NextRun(ctx, sb.ID, 0); err == nil || got != nil {
		t.Fatalf("run must not be handed to the runner with unreadable context: %+v, %v", got, err)
	}
	st.outage.Store(false)
	got, err := o.NextRun(ctx, sb.ID, 0)
	if err != nil || got == nil {
		persisted, readErr := st.Store.GetRun(ctx, next.ID)
		t.Fatalf("store recovered, but the undelivered run cannot be claimed: next=%v stored=%+v read=%v", err, persisted, readErr)
	}
	if got.ID != next.ID || got.Session != "fixture-session" || got.Task != "add tests for the findings" {
		t.Fatalf("retry changed the message or its session: %+v", got)
	}
}
