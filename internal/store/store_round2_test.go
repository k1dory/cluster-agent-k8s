package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// Round 2 of the review (wiki ревью-codex-agent-sandbox-main-2026-11-06): one body per
// contract, run on the memory store and, with SANDBOX_TEST_POSTGRES_URL, on PostgreSQL.

// round2Store is a store under test with a way to age an Idempotency-Key reservation past
// IdempotencyStale without waiting for it.
type round2Store struct {
	Store
	age func(t *testing.T, key string)
}

func round2Run(t *testing.T, body func(t *testing.T, s round2Store)) {
	t.Run("memory", func(t *testing.T) {
		m := NewMemory()
		var offset atomic.Int64
		m.SetIdempotencyClock(func() time.Time { return time.Now().Add(time.Duration(offset.Load())) })
		body(t, round2Store{Store: m, age: func(*testing.T, string) { offset.Add(int64(IdempotencyStale + time.Minute)) }})
	})
	t.Run("postgres", func(t *testing.T) {
		p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
		body(t, round2Store{Store: p, age: func(t *testing.T, key string) {
			if _, err := p.pool.Exec(context.Background(), `UPDATE idempotency SET created_at = created_at - $2::interval WHERE key=$1`,
				key, (IdempotencyStale + time.Minute).String()); err != nil {
				t.Fatal(err)
			}
		}})
	})
}

func round2Sandbox(id string) *model.Sandbox {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &model.Sandbox{ID: id, Name: "r2", Slug: "dev", Owner: "alice", Tenant: "acme", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
}

// Item 4: a reservation is finished only by the generation that holds it. A takeover of an
// abandoned one is won by exactly one of the callers racing for it, keeps the seed (what the
// keyed request creates is named from it), and leaves the old holder unable to overwrite or
// drop it.
func TestRound2IdempotencyGenerations(t *testing.T) {
	round2Run(t, func(t *testing.T, s round2Store) {
		ctx := context.Background()
		key := "acme|POST /v1/sandboxes|gen"
		first, reserved, err := s.ReserveIdempotent(ctx, key, "h")
		if err != nil || !reserved || first.Generation != 1 || first.Seed == "" {
			t.Fatalf("first reservation: %v %v %+v", err, reserved, first)
		}
		if rec, reserved, err := s.ReserveIdempotent(ctx, key, "h"); err != nil || reserved || !rec.InProgress() {
			t.Fatalf("repeat while in progress: %v %v %+v", err, reserved, rec)
		}
		// Abandoned: N retries race for it, one takes it over.
		s.age(t, key)
		var won atomic.Int32
		var wg sync.WaitGroup
		var taken *Idempotent
		var mu sync.Mutex
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rec, reserved, err := s.ReserveIdempotent(ctx, key, "h")
				if err != nil {
					t.Error(err)
					return
				}
				if reserved {
					won.Add(1)
					mu.Lock()
					taken = rec
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if won.Load() != 1 || taken.Generation != 2 || taken.Seed != first.Seed {
			t.Fatalf("takeover: %d winners, %+v (first %+v)", won.Load(), taken, first)
		}
		// The old holder was slow, not dead: neither its result nor its release lands.
		if err := s.PutIdempotent(ctx, &Idempotent{Key: key, BodyHash: "h", Status: 201, Body: []byte("old"), Generation: 1}); !errors.Is(err, ErrConflict) {
			t.Fatalf("finish by the superseded generation: %v", err)
		}
		if err := s.ReleaseIdempotent(ctx, key, 1); err != nil {
			t.Fatal(err)
		}
		if rec, err := s.GetIdempotent(ctx, key); err != nil || rec.Generation != 2 || !rec.InProgress() {
			t.Fatalf("after the old holder's release: %v %+v", err, rec)
		}
		if err := s.PutIdempotent(ctx, &Idempotent{Key: key, BodyHash: "h", Status: 201, Body: []byte("new"), Generation: 2}); err != nil {
			t.Fatal(err)
		}
		// Finished: replayed, not taken over (however old), not released.
		if err := s.ReleaseIdempotent(ctx, key, 2); err != nil {
			t.Fatal(err)
		}
		s.age(t, key)
		rec, reserved, err := s.ReserveIdempotent(ctx, key, "h")
		if err != nil || reserved || rec.Status != 201 || string(rec.Body) != "new" || rec.Seed != first.Seed {
			t.Fatalf("replay: %v %v %+v", err, reserved, rec)
		}
		// A different body never takes over an abandoned reservation.
		other := "acme|POST /v1/sandboxes|other"
		if _, reserved, err := s.ReserveIdempotent(ctx, other, "h1"); err != nil || !reserved {
			t.Fatal(err)
		}
		s.age(t, other)
		if rec, reserved, err := s.ReserveIdempotent(ctx, other, "h2"); err != nil || reserved || rec.BodyHash != "h1" {
			t.Fatalf("takeover with another body: %v %v %+v", err, reserved, rec)
		}
	})
}

// Item 5: DeleteItem and a conditional PutItem of the same item end in one of their serial
// outcomes: put then delete, or delete then a refused put. Never "deleted, then alive again".
func TestRound2DeleteItemRacesPutItem(t *testing.T) {
	round2Run(t, func(t *testing.T, s round2Store) {
		ctx := context.Background()
		for i := range 60 {
			name := fmt.Sprintf("race-%d", i)
			it := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: name, Spec: json.RawMessage(`{"image":"a"}`)}
			if err := s.PutItem(ctx, it, 0); err != nil {
				t.Fatal(err)
			}
			var putErr, delErr error
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				next := *it
				next.Spec = json.RawMessage(`{"image":"b"}`)
				putErr = s.PutItem(ctx, &next, 1)
			}()
			go func() { defer wg.Done(); delErr = s.DeleteItem(ctx, it.Kind, it.Tenant, name) }()
			wg.Wait()
			if delErr != nil || putErr != nil && !errors.Is(putErr, ErrConflict) {
				t.Fatalf("%s: delete %v, put %v", name, delErr, putErr)
			}
			if got, err := s.GetItem(ctx, it.Kind, it.Tenant, name, 0); !errors.Is(err, ErrNotFound) {
				t.Fatalf("%s: deleted, then alive again (put %v): %+v %v", name, putErr, got, err)
			}
		}
	})
}

// Item 5, deterministically: a DeleteItem waits for the item's lock while a writer holds it.
// Before the fix it did not take the lock and returned at once.
func TestRound2PostgresDeleteItemTakesTheItemLock(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := context.Background()
	it := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "locked", Spec: json.RawMessage(`{}`)}
	if err := p.PutItem(ctx, it, 0); err != nil {
		t.Fatal(err)
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "catalog:"+it.Kind+"|"+it.Tenant+"|"+it.Name); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.DeleteItem(ctx, it.Kind, it.Tenant, it.Name) }()
	select {
	case err := <-done:
		t.Fatalf("DeleteItem did not wait for the item's lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Item 6: an event that takes a smaller id but commits later must not be stepped over by a
// reader that pages by id. Writer A holds the events lock (as AppendEvent does from its id to
// its commit) with its row inserted but not committed; writer B's AppendEvent must wait, so a
// reader can never see B's id while A's is still invisible.
func TestRound2PostgresEventCursorSurvivesALateCommit(t *testing.T) {
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
	// The reader polls while A is open: whatever it sees, it moves its cursor past it.
	var cursor int64
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		evs, err := p.ListEvents(ctx, "sb", cursor, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range evs {
			cursor = e.ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-fast; err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for start := time.Now(); time.Since(start) < 2*time.Second && len(seen) < 2; {
		evs, err := p.ListEvents(ctx, "sb", cursor, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range evs {
			cursor = e.ID
			seen[e.Type] = true
		}
	}
	if !seen["slow"] || !seen["fast"] {
		t.Fatalf("the reader stepped over the late commit (id %d): saw %v, cursor %d", slow, seen, cursor)
	}
}

// Item 6 on both stores: concurrent writers and a reader paging by id; the reader ends having
// read every event exactly once.
func TestRound2EventReaderMissesNothing(t *testing.T) {
	round2Run(t, func(t *testing.T, s round2Store) {
		ctx := context.Background()
		const writers, each = 6, 25
		var wg sync.WaitGroup
		for w := range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range each {
					if err := s.AppendEvent(ctx, &model.Event{SandboxID: "sb-cursor", Tenant: "acme", Slug: "dev", Type: "t", Data: fmt.Sprintf("%d/%d", w, i)}); err != nil {
						t.Error(err)
						return
					}
				}
			}()
		}
		stop := make(chan struct{})
		go func() { wg.Wait(); close(stop) }()
		seen := map[string]int{}
		var cursor int64
		read := func() {
			evs, err := s.ListEvents(ctx, "sb-cursor", cursor, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range evs {
				if e.ID <= cursor {
					t.Fatalf("id %d after cursor %d", e.ID, cursor)
				}
				cursor = e.ID
				seen[e.Data]++
			}
		}
		for done := false; !done; {
			select {
			case <-stop:
				done = true
			default:
			}
			read()
		}
		read()
		if len(seen) != writers*each {
			t.Fatalf("reader saw %d of %d events", len(seen), writers*each)
		}
		for d, n := range seen {
			if n != 1 {
				t.Fatalf("event %s read %d times", d, n)
			}
		}
	})
}

// Item 8: nothing the caller passes in or gets back shares memory with the stored record.
func TestRound2RecordsAreCopies(t *testing.T) {
	round2Run(t, func(t *testing.T, s round2Store) {
		ctx := context.Background()
		exp := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
		sb := round2Sandbox("copies")
		in := exp // the caller's own time: mutated below, exp keeps the stored value
		sb.ExpiresAt = &in
		sb.Launch = &model.Launch{Image: "img", Env: map[string]string{"A": "1"}, HarnessFiles: map[string]string{".cfg": "x"},
			MCPServers: []model.MCPServer{{Name: "m", URL: "http://m"}}}
		sb.Connections = []string{"gh"}
		if err := s.CreateSandbox(ctx, sb); err != nil {
			t.Fatal(err)
		}
		mutate := func(c *model.Sandbox) {
			*c.ExpiresAt = c.ExpiresAt.Add(time.Hour)
			c.Launch.Env["A"] = "2"
			c.Launch.HarnessFiles[".cfg"] = "y"
			c.Launch.MCPServers[0].URL = "http://evil"
			c.Connections[0] = "evil"
		}
		check := func(stage string) {
			got, err := s.GetSandbox(ctx, sb.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !got.ExpiresAt.Equal(exp) || got.Launch.Env["A"] != "1" || got.Launch.HarnessFiles[".cfg"] != "x" ||
				got.Launch.MCPServers[0].URL != "http://m" || got.Connections[0] != "gh" {
				t.Fatalf("%s: the stored record changed: %+v %+v", stage, got, got.Launch)
			}
		}
		mutate(sb)
		check("input mutated after create")
		got, _ := s.GetSandbox(ctx, sb.ID)
		mutate(got)
		check("read mutated")
		list, _ := s.ListSandboxes(ctx)
		for _, l := range list {
			if l.ID == sb.ID {
				mutate(l)
			}
		}
		check("listed mutated")

		started := time.Now().UTC().Truncate(time.Microsecond)
		run := &model.Run{ID: "copies-run", SandboxID: sb.ID, Tenant: "acme", Slug: "dev", Task: "t", Status: model.RunQueued, CreatedAt: started}
		if err := s.CreateRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		claimed, err := s.ClaimRun(ctx, run.ID, started, "", RunStamp{})
		if err != nil {
			t.Fatal(err)
		}
		*claimed.StartedAt = claimed.StartedAt.Add(time.Hour)
		r, _ := s.GetRun(ctx, run.ID)
		*r.StartedAt = r.StartedAt.Add(time.Hour)
		if r, _ := s.GetRun(ctx, run.ID); !r.StartedAt.Equal(started) {
			t.Fatalf("the stored run's start moved: %v", r.StartedAt)
		}
	})
}

// Item 9: duplicates are refused with the same errors on both stores.
func TestRound2DuplicatesAreRefused(t *testing.T) {
	round2Run(t, func(t *testing.T, s round2Store) {
		ctx := context.Background()
		a := round2Sandbox("dup-a")
		a.Preview = &model.Preview{Port: 3000, Access: "private", Host: "a.preview.test"}
		if err := s.CreateSandbox(ctx, a); err != nil {
			t.Fatal(err)
		}
		again := round2Sandbox("dup-a")
		if err := s.CreateSandbox(ctx, again); !errors.Is(err, ErrConflict) {
			t.Fatalf("second sandbox with the same id: %v", err)
		}
		if got, _ := s.GetSandbox(ctx, "dup-a"); got.Preview == nil || got.Preview.Host != "a.preview.test" {
			t.Fatalf("the first record was overwritten: %+v", got)
		}
		b := round2Sandbox("dup-b")
		b.Preview = &model.Preview{Port: 3000, Access: "private", Host: "a.preview.test"}
		if err := s.CreateSandbox(ctx, b); !errors.Is(err, ErrConflict) {
			t.Fatalf("second sandbox with the same preview host: %v", err)
		}
		b.Preview = nil
		if err := s.CreateSandbox(ctx, b); err != nil {
			t.Fatal(err)
		}
		b.Preview = &model.Preview{Port: 3000, Access: "private", Host: "a.preview.test"}
		if err := s.UpdateSandbox(ctx, b); !errors.Is(err, ErrDuplicate) || errors.Is(err, ErrConflict) {
			t.Fatalf("update to a taken preview host: %v", err)
		}

		run := &model.Run{ID: "dup-run", SandboxID: a.ID, Tenant: "acme", Slug: "dev", Task: "one", Status: model.RunQueued, CreatedAt: time.Now()}
		if err := s.CreateRun(ctx, run); err != nil {
			t.Fatal(err)
		}
		run2 := *run
		run2.Task = "two"
		if err := s.CreateRun(ctx, &run2); !errors.Is(err, ErrConflict) {
			t.Fatalf("second run with the same id: %v", err)
		}
		if got, _ := s.GetRun(ctx, run.ID); got.Task != "one" {
			t.Fatalf("the first run was overwritten: %+v", got)
		}

		now := time.Now().UTC().Truncate(time.Microsecond)
		n, err := s.NextInstance(ctx)
		if err != nil {
			t.Fatal(err)
		}
		in := &model.Instance{N: n, SandboxID: a.ID, Slug: "dev", Tenant: "acme", PodName: "p", Serial: "serial-1", IssuedAt: now, NotAfter: now.Add(time.Hour)}
		if err := s.CreateInstance(ctx, in); err != nil {
			t.Fatal(err)
		}
		dupN := *in
		dupN.Serial = "serial-2"
		if err := s.CreateInstance(ctx, &dupN); !errors.Is(err, ErrConflict) {
			t.Fatalf("second instance with the same number: %v", err)
		}
		n2, _ := s.NextInstance(ctx)
		dupSerial := *in
		dupSerial.N = n2
		if err := s.CreateInstance(ctx, &dupSerial); !errors.Is(err, ErrConflict) {
			t.Fatalf("second instance with the same serial: %v", err)
		}
	})
}

// Item 9: no limit means DefaultEventLimit on both stores.
func TestRound2DefaultEventLimit(t *testing.T) {
	round2Run(t, func(t *testing.T, s round2Store) {
		ctx := context.Background()
		for i := range DefaultEventLimit + 5 {
			if err := s.AppendEvent(ctx, &model.Event{SandboxID: "sb-limit", Tenant: "acme", Slug: "dev", Type: "t", Data: fmt.Sprint(i)}); err != nil {
				t.Fatal(err)
			}
		}
		if evs, err := s.ListEvents(ctx, "sb-limit", 0, 0); err != nil || len(evs) != DefaultEventLimit {
			t.Fatalf("ListEvents without a limit: %d %v", len(evs), err)
		}
		if evs, err := s.QueryEvents(ctx, Filter{SandboxID: "sb-limit"}); err != nil || len(evs) != DefaultEventLimit {
			t.Fatalf("QueryEvents without a limit: %d %v", len(evs), err)
		}
	})
}

// Item 9: a wait for a tenant lock ends with its context; the callback does not run.
func TestRound2TenantLockWaitHonoursContext(t *testing.T) {
	round2Run(t, func(t *testing.T, s round2Store) {
		held, release := make(chan struct{}), make(chan struct{})
		holder := make(chan error, 1)
		go func() {
			holder <- s.WithTenantLock(context.Background(), "acme-lock", func(context.Context) error {
				close(held)
				<-release
				return nil
			})
		}()
		<-held
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		ran := false
		start := time.Now()
		err := s.WithTenantLock(ctx, "acme-lock", func(context.Context) error { ran = true; return nil })
		if err == nil || ran || time.Since(start) > 5*time.Second {
			t.Fatalf("waiter: err %v, ran %v after %v", err, ran, time.Since(start))
		}
		close(release)
		if err := <-holder; err != nil {
			t.Fatal(err)
		}
	})
}

// Item 17: a pool of one connection would deadlock the first WithTenantLock (its transaction
// holds the only connection while the callback waits for another); OpenPostgres refuses it.
func TestRound2PoolOfOneConnectionIsRefused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := OpenPostgres(ctx, "postgres://u:p@127.0.0.1:1/db?sslmode=disable&pool_max_conns=1")
	if err == nil || !strings.Contains(err.Error(), "pool_max_conns=1") || !strings.Contains(err.Error(), "at least 2") {
		t.Fatalf("pool of one connection: %v", err)
	}
}
