package orchestrator

import (
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

// The FS waiter subscribed to every event of the sandbox; a run streaming output while the
// runner answered filled its 64-slot buffer, the hub dropped the fs.result and the request
// timed out although it had been answered.
func TestReviewFSAnswerSurvivesOutputBurst(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	ctx := t.Context()
	reqs, cancel := o.Hub.SubscribeTypes(sb.ID, model.EventFSRequest)
	defer cancel()
	go func() {
		e := <-reqs
		var req model.FSRequest
		_ = json.Unmarshal([]byte(e.Data), &req)
		for range 200 {
			o.Hub.Publish(model.Event{SandboxID: sb.ID, Type: model.EventRunOutput, Data: "line"})
		}
		_ = o.AnswerFS(ctx, sb.ID, model.FSResult{Request: req.ID, OK: true, Size: 5})
	}()
	res, err := o.FS(ctx, sb.ID, model.FSRequest{Op: model.FSList, Path: "repo"}, false, 2*time.Second)
	if err != nil || !res.OK || res.Size != 5 {
		t.Fatalf("answer after an output burst: %v %+v", err, res)
	}
}
