package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Round 2 of the review (wiki ревью-codex-agent-sandbox-main-2026-11-06), item 4: an
// Idempotency-Key never yields two resources, whatever happens between the creation and the
// recording of its result.

// idemFaultStore fails or holds the steps around a keyed request, as a replica that loses its
// client, its database or its process would. A cancelled context fails the write, as it does on
// PostgreSQL (the memory store ignores contexts).
type idemFaultStore struct {
	*store.Memory
	putDown    atomic.Bool
	holdPut    chan struct{} // when set, the next PutIdempotent waits for it to close
	holdLock   chan struct{} // when set, the next WithTenantLock waits for it to close
	afterWrite func()        // runs after CreateSandbox
	mu         sync.Mutex
	putErrs    []error
}

func (s *idemFaultStore) PutIdempotent(ctx context.Context, rec *store.Idempotent) error {
	s.mu.Lock()
	hold := s.holdPut
	s.holdPut = nil
	s.mu.Unlock()
	if hold != nil {
		<-hold
	}
	err := ctx.Err()
	if err == nil && s.putDown.Load() {
		err = errors.New("fixture: store unavailable")
	}
	if err == nil {
		err = s.Memory.PutIdempotent(ctx, rec)
	}
	s.mu.Lock()
	s.putErrs = append(s.putErrs, err)
	s.mu.Unlock()
	return err
}

func (s *idemFaultStore) WithTenantLock(ctx context.Context, tenant string, fn func(context.Context) error) error {
	s.mu.Lock()
	hold := s.holdLock
	s.holdLock = nil
	s.mu.Unlock()
	if hold != nil {
		<-hold
	}
	return s.Memory.WithTenantLock(ctx, tenant, fn)
}

func (s *idemFaultStore) CreateSandbox(ctx context.Context, sb *model.Sandbox) error {
	err := s.Memory.CreateSandbox(ctx, sb)
	if err == nil && s.afterWrite != nil {
		s.afterWrite()
	}
	return err
}

// idemFaults puts the fault store under the stack and returns it with a clock that ages
// reservations past IdempotencyStale.
func idemFaults(t *testing.T) (*stack, *idemFaultStore, func()) {
	t.Helper()
	s := newStack(t)
	mem := s.orch.Store.(*store.Memory)
	var offset atomic.Int64
	mem.SetIdempotencyClock(func() time.Time { return time.Now().Add(time.Duration(offset.Load())) })
	fs := &idemFaultStore{Memory: mem}
	s.orch.Store = fs
	return s, fs, func() { offset.Add(int64(store.IdempotencyStale + time.Minute)) }
}

var round2CreateBody = map[string]any{"name": "db", "slug": "backend-dev", "owner": "alice"}

func round2Create(t *testing.T, s *stack, key string) (int, string, bool) {
	t.Helper()
	resp, body := call(t, "POST", s.platform.URL+"/v1/sandboxes", "t0k", round2CreateBody, map[string]string{"Idempotency-Key": key})
	var sb model.Sandbox
	_ = json.Unmarshal(body, &sb)
	return resp.StatusCode, sb.ID, resp.Header.Get("Idempotency-Replayed") == "true"
}

func round2Count(t *testing.T, s *stack) int {
	t.Helper()
	c, err := s.orch.Store.CountSandboxes(context.Background(), "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	return c.Total
}

// The client hangs up once the sandbox exists, before the key's result is written. The result
// is still stored (on a context the client cannot cancel), and the retry replays it.
func TestRound2IdempotentResultSurvivesTheClientHangingUp(t *testing.T) {
	s, fs, _ := idemFaults(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs.afterWrite = cancel
	raw, _ := json.Marshal(round2CreateBody)
	raw = append(raw, '\n') // as call's encoder writes it: the same body, the same hash
	req := httptest.NewRequest("POST", "/v1/sandboxes", bytes.NewReader(raw)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer t0k")
	req.Header.Set("Idempotency-Key", "hangup")
	w := httptest.NewRecorder()
	s.p.Routes().ServeHTTP(w, req)
	fs.afterWrite = nil
	var first model.Sandbox
	if err := json.Unmarshal(w.Body.Bytes(), &first); err != nil || w.Code != 201 || first.ID == "" {
		t.Fatalf("first attempt: %d %s", w.Code, w.Body)
	}
	code, id, replayed := round2Create(t, s, "hangup")
	if code != 201 || id != first.ID || !replayed {
		t.Fatalf("retry: %d %s replayed=%v, want a replay of %s (put errors %v)", code, id, replayed, first.ID, fs.putErrs)
	}
	if n := round2Count(t, s); n != 1 {
		t.Fatalf("%d sandboxes for one key", n)
	}
}

// The replica dies (here: its database write fails) after creating the sandbox and before
// recording the result. Once the reservation is abandoned, the retry that takes it over finds
// the sandbox the first attempt created instead of creating a second.
func TestRound2TakeoverFindsWhatTheAbandonedAttemptCreated(t *testing.T) {
	s, fs, age := idemFaults(t)
	fs.putDown.Store(true)
	code, first, _ := round2Create(t, s, "abandoned")
	fs.putDown.Store(false)
	if code != 201 || first == "" {
		t.Fatalf("first attempt: %d", code)
	}
	if code, _, _ := round2Create(t, s, "abandoned"); code != 409 {
		t.Fatalf("retry while the reservation is fresh: %d, want 409", code)
	}
	age()
	code, id, _ := round2Create(t, s, "abandoned")
	if code != 201 || id != first {
		t.Fatalf("takeover: %d %s, want the first attempt's %s", code, id, first)
	}
	if code, id, replayed := round2Create(t, s, "abandoned"); code != 201 || id != first || !replayed {
		t.Fatalf("after the takeover: %d %s replayed=%v", code, id, replayed)
	}
	if n := round2Count(t, s); n != 1 {
		t.Fatalf("%d sandboxes for one key", n)
	}
}

// The first holder is slow, not dead: it has created the sandbox and waits to record the
// result while a retry takes the reservation over. The retry answers with the same sandbox and
// records it; the old holder's late write is refused by generation, not stored over it.
func TestRound2SlowHolderCannotOverwriteItsSuccessor(t *testing.T) {
	s, fs, age := idemFaults(t)
	release := make(chan struct{})
	fs.holdPut = release
	type result struct {
		code int
		id   string
	}
	slow := make(chan result, 1)
	go func() {
		code, id, _ := round2Create(t, s, "slow-put")
		slow <- result{code, id}
	}()
	round2WaitFor(t, func() bool { return round2Count(t, s) == 1 })
	age()
	code, id, _ := round2Create(t, s, "slow-put")
	if code != 201 {
		t.Fatalf("takeover: %d", code)
	}
	close(release)
	old := <-slow
	if old.code != 201 || old.id != id {
		t.Fatalf("slow holder: %+v, successor %s", old, id)
	}
	rec, err := fs.Memory.GetIdempotent(context.Background(), "|POST /v1/sandboxes|slow-put")
	if err != nil || rec.Generation != 2 || rec.InProgress() {
		t.Fatalf("record: %v %+v", err, rec)
	}
	refused := false
	for _, err := range fs.putErrs {
		refused = refused || errors.Is(err, store.ErrConflict)
	}
	if !refused {
		t.Fatalf("the superseded holder's write was not refused: %v", fs.putErrs)
	}
	if code, rid, replayed := round2Create(t, s, "slow-put"); code != 201 || rid != id || !replayed {
		t.Fatalf("replay: %d %s %v", code, rid, replayed)
	}
	if n := round2Count(t, s); n != 1 {
		t.Fatalf("%d sandboxes for one key", n)
	}
}

// The first holder is slow before it creates anything: the retry that takes over creates the
// sandbox; the old holder's insert of the same keyed id is refused, and it answers with the
// successor's sandbox rather than an error or a second one.
func TestRound2SlowHolderBeforeCreationFindsItsSuccessorsSandbox(t *testing.T) {
	s, fs, age := idemFaults(t)
	release := make(chan struct{})
	fs.holdLock = release
	type result struct {
		code int
		id   string
	}
	slow := make(chan result, 1)
	go func() {
		code, id, _ := round2Create(t, s, "slow-lock")
		slow <- result{code, id}
	}()
	round2WaitFor(t, func() bool {
		_, err := fs.Memory.GetIdempotent(context.Background(), "|POST /v1/sandboxes|slow-lock")
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return err == nil && fs.holdLock == nil
	})
	age()
	code, id, _ := round2Create(t, s, "slow-lock")
	if code != 201 || id == "" {
		t.Fatalf("takeover: %d", code)
	}
	close(release)
	if old := <-slow; old.code != 201 || old.id != id {
		t.Fatalf("slow holder: %+v, successor %s", old, id)
	}
	if n := round2Count(t, s); n != 1 {
		t.Fatalf("%d sandboxes for one key", n)
	}
}

// The same for a run: the takeover of an abandoned POST /runs returns the queued run.
func TestRound2RunTakeoverFindsTheQueuedRun(t *testing.T) {
	s, fs, age := idemFaults(t)
	code, sbID, _ := round2Create(t, s, "")
	if code != 201 {
		t.Fatalf("create: %d", code)
	}
	path := s.platform.URL + "/v1/sandboxes/" + sbID + "/runs"
	run := func() (int, string) {
		resp, body := call(t, "POST", path, "t0k", map[string]any{"task": "build"}, map[string]string{"Idempotency-Key": "run-key"})
		var r model.Run
		_ = json.Unmarshal(body, &r)
		return resp.StatusCode, r.ID
	}
	fs.putDown.Store(true)
	code, first := run()
	fs.putDown.Store(false)
	if code != 202 || first == "" {
		t.Fatalf("first attempt: %d", code)
	}
	age()
	if code, id := run(); code != 202 || id != first {
		t.Fatalf("takeover: %d %s, want %s", code, id, first)
	}
	runs, _ := s.orch.Store.ListRuns(context.Background(), sbID)
	n := 0
	for _, r := range runs {
		if r.Task == "build" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d runs for one key", n)
	}
}

func round2WaitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for start := time.Now(); !cond(); {
		if time.Since(start) > 5*time.Second {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
