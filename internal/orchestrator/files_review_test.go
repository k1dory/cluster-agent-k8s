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
