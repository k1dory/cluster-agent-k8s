package store

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

type headStore interface {
	Store
	EventHead
}

// eventHeadStores runs body on the memory store and, with SANDBOX_TEST_POSTGRES_URL, on
// PostgreSQL.
func eventHeadStores(t *testing.T, body func(t *testing.T, s headStore)) {
	t.Run("memory", func(t *testing.T) { body(t, NewMemory()) })
	t.Run("postgres", func(t *testing.T) { body(t, reviewOpenPostgres(t, reviewPostgresURL(t, false))) })
}

// The head a trace stream reads is its replay boundary: every id at or below it must already
// be visible, or an event that commits later below the head is taken for history and skipped.
// Concurrent writers; a reader reads the head and then what is visible up to it. At the end no
// event may exist at or below a head that was not visible right after that head was read.
func TestRound2EventHeadIsACommittedPrefix(t *testing.T) {
	eventHeadStores(t, func(t *testing.T, s headStore) {
		ctx := context.Background()
		const writers, each = 6, 25
		var wg sync.WaitGroup
		for w := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range each {
					if err := s.AppendEvent(ctx, &model.Event{SandboxID: "sb-head", Tenant: "acme", Slug: "dev", Type: "t", Data: fmt.Sprintf("%d/%d", w, i)}); err != nil {
						t.Error(err)
						return
					}
				}
			}()
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		type sample struct {
			head    int64
			visible map[int64]bool
		}
		read := func() map[int64]bool {
			evs, err := s.QueryEvents(ctx, Filter{SandboxID: "sb-head", Limit: 5000})
			if err != nil {
				t.Fatal(err)
			}
			m := map[int64]bool{}
			for _, e := range evs {
				m[e.ID] = true
			}
			return m
		}
		var samples []sample
		for running := true; running; {
			select {
			case <-done:
				running = false
			default:
			}
			head, err := s.LastEventID(ctx)
			if err != nil {
				t.Fatal(err)
			}
			samples = append(samples, sample{head, read()})
		}
		final := read()
		if len(final) != writers*each {
			t.Fatalf("%d events, want %d", len(final), writers*each)
		}
		for _, sm := range samples {
			for id := range final {
				if id <= sm.head && !sm.visible[id] {
					t.Fatalf("event %d committed after a head of %d was read", id, sm.head)
				}
			}
		}
	})
}

// The same on PostgreSQL, deterministically: writer A holds the events lock (as AppendEvent
// does from its id to its commit) with its row inserted but not committed. The head must stay
// below A's id however long A takes, and a writer B meanwhile must wait rather than commit an
// id above A's: with a bare bigserial B committed first and the head stepped over A.
func TestRound2PostgresEventHeadWaitsForALateCommit(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := context.Background()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, eventsLockSQL); err != nil {
		t.Fatal(err)
	}
	var slow int64
	if err := tx.QueryRow(ctx, `INSERT INTO events (sandbox_id, tenant, slug, run_id, type, data, at)
		VALUES ('sb','acme','dev','','slow','',now()) RETURNING id`).Scan(&slow); err != nil {
		t.Fatal(err)
	}
	fast := make(chan error, 1)
	go func() {
		fast <- p.AppendEvent(ctx, &model.Event{SandboxID: "sb", Tenant: "acme", Slug: "dev", Type: "fast"})
	}()
	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		head, err := p.LastEventID(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if head >= slow {
			t.Fatalf("the head is %d while event %d is not committed", head, slow)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-fast; err != nil {
		t.Fatal(err)
	}
	head, err := p.LastEventID(ctx)
	if err != nil || head <= slow {
		t.Fatalf("head after both committed: %d %v (slow %d)", head, err, slow)
	}
}
