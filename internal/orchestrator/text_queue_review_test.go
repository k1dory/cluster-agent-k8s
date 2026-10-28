package orchestrator

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

type reviewSessionReadStore struct {
	store.Store
	target string
	fail   atomic.Bool
}

func (s *reviewSessionReadStore) GetRun(ctx context.Context, id string) (*model.Run, error) {
	if id == s.target && s.fail.CompareAndSwap(true, false) {
		return nil, errors.New("fixture: temporary session read failure")
	}
	return s.Store.GetRun(ctx, id)
}

func reviewTextQueueSandbox(t *testing.T, st store.Store) (*Orchestrator, *model.Sandbox) {
	t.Helper()
	sb := &model.Sandbox{ID: "sb_text_queue", Name: "fixture", Tenant: "fixture", Slug: "fixture",
		Status: model.StatusRunning, CreatedAt: time.Now(), LastActivity: time.Now()}
	if err := st.CreateSandbox(t.Context(), sb); err != nil {
		t.Fatal(err)
	}
	return New(st, NewFakeRuntime(), nil, events.New(), Config{}, nil), sb
}

// An unreadable predecessor is not evidence that the conversation has no session.
// The fixture fails one read only; retry must preserve the queued message and context.
func TestReviewTextResumeRetriesSessionReadFailure(t *testing.T) {
	st := &reviewSessionReadStore{Store: store.NewMemory()}
	o, sb := reviewTextQueueSandbox(t, st)
	ctx := t.Context()
	first, _, err := o.Say(ctx, sb.ID, "inspect the fixture project")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.NextRun(ctx, sb.ID, 0); err != nil {
		t.Fatal(err)
	}
	next, _, err := o.Say(ctx, sb.ID, "add tests for the findings")
	if err != nil || next.ID == first.ID || next.Status != model.RunQueued {
		t.Fatalf("follow-up was not queued: %+v, %v", next, err)
	}
	if err := o.Output(ctx, sb.ID, first.ID, `{"type":"system","subtype":"init","session_id":"fixture-session"}`); err != nil {
		t.Fatal(err)
	}
	if err := o.FinishRun(ctx, sb.ID, first.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	st.target = first.ID
	st.fail.Store(true)
	got, err := o.NextRun(ctx, sb.ID, 0)
	if err != nil {
		// A transient error may be returned, provided the next poll can still claim the run.
		got, err = o.NextRun(ctx, sb.ID, 0)
	}
	if err != nil || got == nil {
		t.Fatalf("message could not resume after the read recovered: %+v, %v", got, err)
	}
	if got.ID != next.ID || got.Session != "fixture-session" {
		t.Fatalf("temporary read failure lost conversation context: id=%q session=%q, want id=%q session=fixture-session", got.ID, got.Session, next.ID)
	}
}

type reviewClaimBeforeAppendStore struct {
	store.Store
	sandbox string
	claim   bool
}

func (s *reviewClaimBeforeAppendStore) AppendQueuedTask(ctx context.Context, id, text string) (*model.Run, error) {
	if s.claim {
		s.claim = false
		if _, err := s.Store.ClaimQueuedRun(ctx, s.sandbox, time.Now()); err != nil {
			return nil, err
		}
	}
	return s.Store.AppendQueuedTask(ctx, id, text)
}

// Deterministically put the claim between Say's snapshot and its conditional append.
func TestReviewTextMessageSurvivesClaimBeforeAppend(t *testing.T) {
	st := &reviewClaimBeforeAppendStore{Store: store.NewMemory()}
	o, sb := reviewTextQueueSandbox(t, st)
	ctx := t.Context()
	first, _, err := o.Say(ctx, sb.ID, "first fixture task")
	if err != nil {
		t.Fatal(err)
	}
	st.sandbox, st.claim = sb.ID, true
	next, _, err := o.Say(ctx, sb.ID, "second fixture task")
	if err != nil {
		t.Fatal(err)
	}
	if next.ID == first.ID || next.ResumeOf != first.ID || next.Task != "second fixture task" || next.Status != model.RunQueued {
		t.Fatalf("message lost after concurrent claim: %+v", next)
	}
	claimed, err := st.GetRun(ctx, first.ID)
	if err != nil || claimed.Task != "first fixture task" || claimed.Status != model.RunRunning {
		t.Fatalf("claimed task was changed: %+v, %v", claimed, err)
	}
	if err := o.Output(ctx, sb.ID, first.ID, `{"type":"system","subtype":"init","session_id":"fixture-session"}`); err != nil {
		t.Fatal(err)
	}
	if err := o.FinishRun(ctx, sb.ID, first.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	got, err := o.NextRun(ctx, sb.ID, 0)
	if err != nil || got == nil || got.ID != next.ID || got.Session != "fixture-session" {
		t.Fatalf("follow-up did not resume: %+v, %v", got, err)
	}
}
