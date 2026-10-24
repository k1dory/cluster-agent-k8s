package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// boundedLocks is a store whose locks come from a small shared pool, like the PostgreSQL
// store's bounded set of lock connections: a lock taken while holding another one can starve.
type boundedLocks struct {
	store.Store
	slots chan struct{}
}

func (b *boundedLocks) WithTenantLock(ctx context.Context, key string, fn func(context.Context) error) error {
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	case <-ctx.Done():
		return ctx.Err()
	}
	return b.Store.WithTenantLock(ctx, key, fn)
}

// Messages to a sleeping sandbox must wake it even when every lock slot is taken by messages
// waiting their turn: the wake happens after the conversation lock is released.
func TestConcurrentMessagesWakeASleepingSandbox(t *testing.T) {
	st := &boundedLocks{Store: store.NewMemory(), slots: make(chan struct{}, 2)}
	o := New(st, NewFakeRuntime(), nil, events.New(), Config{PreviewDomain: "preview.test"}, nil)
	o.leading.Store(true)
	ctx := context.Background()
	sb, err := o.Create(ctx, CreateRequest{Name: "w", Slug: "backend-dev", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, o, sb.ID, model.StatusRunning)
	if _, err := o.Sleep(ctx, sb.ID, true); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if _, _, err := o.Say(ctx, sb.ID, fmt.Sprintf("message %d", i)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("say: %v", err)
	}
	runs, _ := o.Store.ListRuns(ctx, sb.ID)
	if len(runs) != 1 {
		t.Fatalf("one run expected, got %d", len(runs))
	}
	waitStatus(t, o, sb.ID, model.StatusRunning)
}
