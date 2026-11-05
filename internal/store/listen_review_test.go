package store

import (
	"context"
	"errors"
	"testing"
	"time"
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
