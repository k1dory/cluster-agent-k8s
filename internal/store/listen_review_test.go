package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// A failed max(id) read at startup used to leave the cursor at 0, replaying every stored event
// into the hub. The start is retried instead, and abandoned only when the context ends.
func TestListenStartRetriesInsteadOfReplaying(t *testing.T) {
	calls := 0
	last, ok := listenStart(context.Background(), func(context.Context) (int64, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("connection refused")
		}
		return 42, nil
	}, time.Millisecond)
	if !ok || last != 42 || calls != 3 {
		t.Fatalf("start = %d, %v after %d reads; want 42 after 3", last, ok, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := listenStart(ctx, func(context.Context) (int64, error) { return 0, errors.New("down") }, time.Hour); ok {
		t.Fatal("start reported success after the context ended")
	}
}

// The listener signals readiness only once its starting cursor is known, and every event
// appended after the signal is delivered even when the first cursor reads failed. sandboxd
// serves no request before the signal, so an answer a request waits for is never appended
// below the cursor (it was: the retry delay let requests in, their answers were skipped).
func TestListenLoopReadyOnlyAfterTheCursor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	log := []int64{1, 2, 3} // already stored: before the feed starts
	reads := 0
	readyAt := -1
	read := func(context.Context) (int64, error) {
		mu.Lock()
		defer mu.Unlock()
		reads++
		if reads < 3 {
			return 0, errors.New("connection refused")
		}
		return log[len(log)-1], nil
	}
	ready := make(chan struct{})
	got := make(chan int64, 16)
	once := func(ctx context.Context, last *int64) error {
		for ctx.Err() == nil {
			mu.Lock()
			for _, id := range log {
				if id > *last {
					got <- id
					*last = id
				}
			}
			mu.Unlock()
			time.Sleep(time.Millisecond)
		}
		return ctx.Err()
	}
	go listenLoop(ctx, read, func() { mu.Lock(); readyAt = reads; mu.Unlock(); close(ready) }, once, time.Millisecond)
	<-ready
	mu.Lock()
	if readyAt != 3 {
		t.Fatalf("ready after %d cursor reads, want after the first successful one (3)", readyAt)
	}
	log = append(log, 4) // a request's answer, appended once the replica serves
	mu.Unlock()
	select {
	case id := <-got:
		if id != 4 {
			t.Fatalf("delivered %d: the feed replayed events from before its start", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an event appended after ready was never delivered")
	}
}

// On a real database: after ready, an appended event reaches fn.
func TestPostgresListenEventsDeliversAfterReady(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := p.AppendEvent(ctx, &model.Event{SandboxID: "listen-sb", Type: "old"}); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	got := make(chan *model.Event, 4)
	go p.ListenEvents(ctx, func() { close(ready) }, func(e *model.Event) { got <- e })
	<-ready
	if err := p.AppendEvent(ctx, &model.Event{SandboxID: "listen-sb", Type: "fs.result"}); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-got:
		if e.Type != "fs.result" {
			t.Fatalf("delivered %+v first", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event appended after ready not delivered")
	}
}
