package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

func TestReviewPendingFSContinuesPastAnsweredPage(t *testing.T) {
	ctx := t.Context()
	st := store.NewMemory()
	o := New(st, NewFakeRuntime(), nil, events.New(), Config{}, nil)
	for i := 0; i <= 100; i++ {
		id := fmt.Sprintf("request-%03d", i)
		data, _ := json.Marshal(model.FSRequest{ID: id, Op: model.FSList, Path: "repo"})
		if err := st.AppendEvent(ctx, &model.Event{SandboxID: "review", Type: model.EventFSRequest, Data: string(data), At: time.Now()}); err != nil {
			t.Fatal(err)
		}
		if i < 100 {
			if err := o.AnswerFS(ctx, "review", model.FSResult{Request: id, OK: true}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A restarted runner starts at cursor zero; completed history must not hide pending work.
	pending, err := o.PendingFS(ctx, "review", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("one unanswered request follows a completed page, got %d pending requests", len(pending))
	}
}

// appendHookStore runs hook, once, right after an event of type typ was appended: inside the
// caller's emit, before the caller can do anything else.
type appendHookStore struct {
	store.Store
	typ  string
	hook func(e *model.Event)
}

func (s *appendHookStore) AppendEvent(ctx context.Context, e *model.Event) error {
	if err := s.Store.AppendEvent(ctx, e); err != nil {
		return err
	}
	if h := s.hook; h != nil && e.Type == s.typ {
		s.hook = nil
		h(e)
	}
	return nil
}

// The FS waiter subscribed to every event of the sandbox; a run streaming output while the
// runner answered filled its 64-slot buffer, the hub dropped the fs.result and the request
// timed out although it had been answered. The burst and the answer are published here while
// FS is still inside the append of its request, so nothing is drained before they land: only
// a subscription that takes fs.result alone keeps the answer.
func TestReviewFSAnswerSurvivesOutputBurst(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	ctx := t.Context()
	hs := &appendHookStore{Store: o.Store, typ: model.EventFSRequest}
	o.Store = hs
	hs.hook = func(e *model.Event) {
		var req model.FSRequest
		if err := json.Unmarshal([]byte(e.Data), &req); err != nil {
			t.Error(err)
			return
		}
		for range 200 {
			o.Hub.Publish(model.Event{SandboxID: sb.ID, Type: model.EventRunOutput, Data: "line"})
		}
		if err := o.AnswerFS(ctx, sb.ID, model.FSResult{Request: req.ID, OK: true, Size: 5}); err != nil {
			t.Error(err)
		}
	}
	res, err := o.FS(ctx, sb.ID, model.FSRequest{Op: model.FSList, Path: "repo"}, false, 300*time.Millisecond)
	if err != nil || !res.OK || res.Size != 5 {
		t.Fatalf("answer after an output burst: %v %+v", err, res)
	}
}
