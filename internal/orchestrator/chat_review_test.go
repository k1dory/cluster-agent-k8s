package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Messages sent at the same time join one conversation: exactly one run is created, the rest
// are input to it.
func TestConcurrentMessagesShareOneConversation(t *testing.T) {
	ctx := context.Background()
	o := New(store.NewMemory(), NewFakeRuntime(), nil, events.New(), Config{PreviewDomain: "preview.test"}, nil)
	o.leading.Store(true)
	sb, err := o.Create(ctx, CreateRequest{Name: "c", Slug: "backend-dev", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, o, sb.ID, model.StatusRunning)
	const n = 12
	var wg sync.WaitGroup
	deliveries := make(chan string, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, how, err := o.Say(ctx, sb.ID, fmt.Sprintf("message %d", i))
			if err != nil {
				t.Error(err)
				return
			}
			deliveries <- how
		}(i)
	}
	close(start)
	wg.Wait()
	close(deliveries)
	counts := map[string]int{}
	for d := range deliveries {
		counts[d]++
	}
	runs, _ := o.Store.ListRuns(ctx, sb.ID)
	if len(runs) != 1 || counts[DeliveredNew] != 1 || counts[DeliveredInput] != n-1 {
		t.Fatalf("runs=%d deliveries=%v: concurrent messages must share one run", len(runs), counts)
	}
	// After the run ends, concurrent follow-ups still produce a single resume run.
	if _, err := o.NextRun(ctx, sb.ID, time.Second); err != nil {
		t.Fatal(err)
	}
	_ = o.Output(ctx, sb.ID, runs[0].ID, `{"type":"system","session_id":"s-1"}`)
	if err := o.FinishRun(ctx, sb.ID, runs[0].ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	start = make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, _, err := o.Say(ctx, sb.ID, "follow-up"); err != nil {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	runs, _ = o.Store.ListRuns(ctx, sb.ID)
	if len(runs) != 2 {
		t.Fatalf("follow-ups must share one resume run, got %d runs", len(runs))
	}
}

// A long history of answered requests does not hide a new one from the runner.
func TestPendingFSLooksPastAnsweredHistory(t *testing.T) {
	ctx := context.Background()
	o := New(store.NewMemory(), NewFakeRuntime(), nil, events.New(), Config{PreviewDomain: "preview.test"}, nil)
	sb, err := o.Create(ctx, CreateRequest{Name: "h", Slug: "backend-dev", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 230; i++ {
		req := model.FSRequest{ID: fmt.Sprintf("fs_%d", i), Op: model.FSList, Path: "."}
		b, _ := json.Marshal(req)
		_ = o.emit(ctx, model.Event{SandboxID: sb.ID, Type: model.EventFSRequest, Data: string(b)})
		if i != 150 && i != 229 {
			_ = o.AnswerFS(ctx, sb.ID, model.FSResult{Request: req.ID, OK: true})
		}
	}
	pending, err := o.PendingFS(ctx, sb.ID, 0)
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending: %v %d", err, len(pending))
	}
	var ids []string
	for _, e := range pending {
		var req model.FSRequest
		_ = json.Unmarshal([]byte(e.Data), &req)
		ids = append(ids, req.ID)
	}
	if ids[0] != "fs_150" || ids[1] != "fs_229" {
		t.Fatalf("pending ids: %v", ids)
	}
	// From a cursor past the first unanswered one, only the later one remains.
	later, _ := o.PendingFS(ctx, sb.ID, pending[0].ID)
	if len(later) != 1 {
		t.Fatalf("after cursor: %d", len(later))
	}
}
