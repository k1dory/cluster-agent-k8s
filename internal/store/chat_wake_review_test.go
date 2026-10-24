package store_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/store"
)

const reviewConcurrentWakeCount = 8

// Synchronize independent conversations once each has its database lock, as can happen
// when messages for sleeping sandboxes arrive together on the same replica.
type reviewChatBarrier struct {
	store.Store
	entered atomic.Int32
	ready   chan struct{}
}

func (s *reviewChatBarrier) WithTenantLock(ctx context.Context, key string, fn func(context.Context) error) error {
	return s.Store.WithTenantLock(ctx, key, func(ctx context.Context) error {
		if strings.HasPrefix(key, "sandbox:") {
			if s.entered.Add(1) == reviewConcurrentWakeCount {
				close(s.ready)
			}
			select {
			case <-s.ready:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return fn(ctx)
	})
}

func TestReviewPostgresChatWakesConcurrentSleepingSandboxes(t *testing.T) {
	dsn := os.Getenv("SANDBOX_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("set SANDBOX_TEST_POSTGRES_URL to run the PostgreSQL chat/wake regression")
	}
	setup, cancelSetup := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancelSetup()
	admin, err := pgx.Connect(setup, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("review_chat_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(setup, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close(setup)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("cleanup schema: %v", err)
		}
		admin.Close(ctx)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	q.Set("pool_max_conns", "16") // standard pool: eight lock holders, eight spare query connections
	u.RawQuery = q.Encode()
	pg, err := store.OpenPostgres(setup, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	st := &reviewChatBarrier{Store: pg, ready: make(chan struct{})}
	runtime := orchestrator.NewFakeRuntime()
	o := orchestrator.New(st, runtime, nil, events.New(), orchestrator.Config{}, nil)
	for i := range reviewConcurrentWakeCount {
		sb := &model.Sandbox{ID: fmt.Sprintf("sleeping-%d", i), Name: "review", Slug: "dev", Tenant: "acme", Owner: "alice",
			Status: model.StatusSleeping, CreatedAt: time.Now(), LastActivity: time.Now()}
		if err := pg.CreateSandbox(setup, sb); err != nil {
			t.Fatal(err)
		}
		if err := runtime.EnsureVolume(setup, sb); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	results := make(chan error, reviewConcurrentWakeCount)
	for i := range reviewConcurrentWakeCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := o.Say(ctx, fmt.Sprintf("sleeping-%d", i), "continue the task")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Errorf("chat must queue and wake without exhausting nested lock slots: %v", err)
		}
	}
	for i := range reviewConcurrentWakeCount {
		sb, err := pg.GetSandbox(setup, fmt.Sprintf("sleeping-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if sb.Status != model.StatusWaking && sb.Status != model.StatusRunning {
			t.Errorf("accepted message must wake its sandbox, got %s", sb.Status)
		}
	}
}
