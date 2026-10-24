package orchestrator

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

type reviewChatStore struct {
	store.Store
	delay   atomic.Bool
	read    chan struct{}
	release chan struct{}
}

func (s *reviewChatStore) ListRuns(ctx context.Context, sandboxID string) ([]*model.Run, error) {
	runs, err := s.Store.ListRuns(ctx, sandboxID)
	if err == nil && s.delay.CompareAndSwap(true, false) {
		close(s.read)
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return runs, err
}

// Keep the delayed-read regression alongside the concurrent-writer test shipped in #11.
func TestReviewConcurrentMessagesUseOneConversation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	st := &reviewChatStore{Store: store.NewMemory(), read: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(st.release) }) }
	t.Cleanup(release)
	if err := st.CreateSandbox(ctx, &model.Sandbox{ID: "chat", Slug: "dev", Tenant: "acme", Owner: "alice", Status: model.StatusRunning}); err != nil {
		t.Fatal(err)
	}
	o := New(st, NewFakeRuntime(), nil, events.New(), Config{}, nil)
	type result struct {
		run *model.Run
		err error
	}
	say := func(text string, out chan<- result) {
		r, _, err := o.Say(ctx, "chat", text)
		out <- result{r, err}
	}
	first, second := make(chan result, 1), make(chan result, 1)
	st.delay.Store(true)
	go say("first message", first)
	select {
	case <-st.read:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go say("second message", second)
	var b result
	secondFinished := false
	select {
	case b = <-second:
		secondFinished = true
	case <-time.After(100 * time.Millisecond): // allow implementations that serialize per sandbox
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	release()
	a := <-first
	if !secondFinished {
		b = <-second
	}
	if a.err != nil || b.err != nil {
		t.Fatalf("messages: first=%v second=%v", a.err, b.err)
	}
	if a.run.ID != b.run.ID {
		t.Fatal("two concurrent messages started separate fresh runs instead of joining one queued conversation")
	}
}
