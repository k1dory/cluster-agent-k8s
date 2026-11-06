package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
// client, its database or its process would. An ended context fails what it fails on
// PostgreSQL (the memory store ignores contexts): the writes and reads below, and the commit
// of a tenant lock's transaction after its callback ran.
type idemFaultStore struct {
	*store.Memory
	putDown    atomic.Bool
	readsDown  atomic.Bool   // GetSandbox and GetRun fail
	notesDown  atomic.Bool   // NoteKeyedSaid fails
	lockDown   atomic.Bool   // WithTenantLock fails
	holdPut    chan struct{} // when set, the next PutIdempotent waits for it to close
	holdLock   chan struct{} // when set, the next WithTenantLock waits for it to close
	afterWrite hook          // runs after CreateSandbox
	afterRun   hook          // runs after CreateRun
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
	if s.lockDown.Load() {
		return errors.New("fixture: lock unavailable")
	}
	if err := s.Memory.WithTenantLock(ctx, tenant, fn); err != nil {
		return err
	}
	return ctx.Err() // the commit, on Postgres, fails on an ended context
}

func (s *idemFaultStore) CreateSandbox(ctx context.Context, sb *model.Sandbox) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.Memory.CreateSandbox(ctx, sb)
	if err == nil {
		s.afterWrite.run()
	}
	return err
}

func (s *idemFaultStore) CreateKeyedSandbox(ctx context.Context, sb *model.Sandbox, seed string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.Memory.CreateKeyedSandbox(ctx, sb, seed)
	if err == nil {
		s.afterWrite.run()
	}
	return err
}

func (s *idemFaultStore) CreateRun(ctx context.Context, r *model.Run) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := s.Memory.CreateRun(ctx, r)
	if err == nil {
		s.afterRun.run()
	}
	return err
}

func (s *idemFaultStore) GetSandbox(ctx context.Context, id string) (*model.Sandbox, error) {
	if err := s.readErr(ctx); err != nil {
		return nil, err
	}
	return s.Memory.GetSandbox(ctx, id)
}

func (s *idemFaultStore) GetRun(ctx context.Context, id string) (*model.Run, error) {
	if err := s.readErr(ctx); err != nil {
		return nil, err
	}
	return s.Memory.GetRun(ctx, id)
}

func (s *idemFaultStore) NoteKeyedSaid(ctx context.Context, seed, said string) error {
	if s.notesDown.Load() {
		return errors.New("fixture: store unavailable")
	}
	return s.Memory.NoteKeyedSaid(ctx, seed, said)
}

func (s *idemFaultStore) readErr(ctx context.Context) error {
	if s.readsDown.Load() {
		return errors.New("fixture: store unavailable")
	}
	return ctx.Err()
}

// hook is a test callback a handler goroutine may run while the test replaces it.
type hook struct{ fn atomic.Pointer[func()] }

func (h *hook) set(fn func()) {
	if fn == nil {
		h.fn.Store(nil)
		return
	}
	h.fn.Store(&fn)
}

func (h *hook) run() {
	if fn := h.fn.Load(); fn != nil {
		(*fn)()
	}
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
	fs.afterWrite.set(cancel)
	raw, _ := json.Marshal(round2CreateBody)
	raw = append(raw, '\n') // as call's encoder writes it: the same body, the same hash
	req := httptest.NewRequest("POST", "/v1/sandboxes", bytes.NewReader(raw)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer t0k")
	req.Header.Set("Idempotency-Key", "hangup")
	w := httptest.NewRecorder()
	s.p.Routes().ServeHTTP(w, req)
	fs.afterWrite.set(nil)
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

// --- review round 1 of #32 ------------------------------------------------------------------

// Finding 1: the client hangs up right after the sandbox row is written. On PostgreSQL the
// lock's commit then fails and so do reads on the request's context: creation reports an
// error. The handler still finds the sandbox (its recovery reads are detached), and if even
// they fail, the release keeps the seed: either way the retry gets the one sandbox.
func TestRound2HangupDuringCreationNeverYieldsASecondSandbox(t *testing.T) {
	for _, readsDown := range []bool{false, true} {
		t.Run(map[bool]string{false: "recovered", true: "recovery-fails"}[readsDown], func(t *testing.T) {
			s, fs, _ := idemFaults(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fs.afterWrite.set(func() {
				cancel()
				fs.readsDown.Store(readsDown)
			})
			raw, _ := json.Marshal(round2CreateBody)
			raw = append(raw, '\n')
			req := httptest.NewRequest("POST", "/v1/sandboxes", bytes.NewReader(raw)).WithContext(ctx)
			req.Header.Set("Authorization", "Bearer t0k")
			req.Header.Set("Idempotency-Key", "hangup-commit")
			w := httptest.NewRecorder()
			s.p.Routes().ServeHTTP(w, req)
			fs.afterWrite.set(nil)
			fs.readsDown.Store(false)
			if n := round2Count(t, s); n != 1 {
				t.Fatalf("first attempt left %d sandboxes (%d %s)", n, w.Code, w.Body)
			}
			if !readsDown && w.Code != 201 {
				t.Fatalf("first attempt: %d %s, want the sandbox it created", w.Code, w.Body)
			}
			code, id, _ := round2Create(t, s, "hangup-commit")
			if code != 201 || id == "" {
				t.Fatalf("retry: %d", code)
			}
			if n := round2Count(t, s); n != 1 {
				t.Fatalf("%d sandboxes for one key (first attempt %d %s)", n, w.Code, w.Body)
			}
			// Review round 2 of #32, finding 1: the success every retry replays is a sandbox
			// that was provisioned, not a bare row the reconciler later marks failed.
			round2Provisioned(t, s, id)
		})
	}
}

// Finding 4: the replica dies right after the run row is written, before it wakes the sleeping
// sandbox for it. The retry that takes over returns the run and wakes the sandbox.
func TestRound2RecoveredRunWakesItsSandbox(t *testing.T) {
	s, fs, age := idemFaults(t)
	code, sbID, _ := round2Create(t, s, "")
	if code != 201 {
		t.Fatalf("create: %d", code)
	}
	if resp, body := call(t, "POST", s.platform.URL+"/v1/sandboxes/"+sbID+"/sleep?force=true", "t0k", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("sleep: %d %s", resp.StatusCode, body)
	}
	round2WaitFor(t, func() bool {
		sb, _ := fs.Memory.GetSandbox(context.Background(), sbID)
		return sb.Status == model.StatusSleeping
	})
	fs.afterRun.set(func() { panic(http.ErrAbortHandler) }) // the process dies: no wake, no result
	path := s.platform.URL + "/v1/sandboxes/" + sbID + "/runs"
	req, _ := http.NewRequest("POST", path, bytes.NewReader([]byte(`{"task":"build"}`+"\n")))
	req.Header.Set("Authorization", "Bearer t0k")
	req.Header.Set("Idempotency-Key", "wake-key")
	// net/http's transport retries a request with an Idempotency-Key once after the connection
	// broke, as a client would: that retry finds the reservation fresh (409).
	if resp, err := http.DefaultClient.Do(req); err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 409 {
			t.Fatalf("the dying attempt answered %d %s", resp.StatusCode, b)
		}
	}
	fs.afterRun.set(nil)
	if sb, _ := fs.Memory.GetSandbox(context.Background(), sbID); sb.Status != model.StatusSleeping {
		t.Fatalf("the dying attempt woke the sandbox: %s", sb.Status)
	}
	age()
	resp, body := call(t, "POST", path, "t0k", map[string]any{"task": "build"}, map[string]string{"Idempotency-Key": "wake-key"})
	if resp.StatusCode != 202 {
		t.Fatalf("takeover: %d %s", resp.StatusCode, body)
	}
	round2WaitFor(t, func() bool {
		sb, _ := fs.Memory.GetSandbox(context.Background(), sbID)
		return sb.Status == model.StatusWaking || sb.Status == model.StatusRunning
	})
	runs, _ := fs.Memory.ListRuns(context.Background(), sbID)
	if len(runs) != 1 {
		t.Fatalf("%d runs for one key", len(runs))
	}
}

// Finding 3: a slow message attempt is held before Say while a later attempt delivers the
// message. When the slow one resumes it finds that delivery under Say's sandbox lock and
// delivers nothing: not a second run, not a second append to a queued task, not a second
// input event to a run in progress.
func TestRound2SlowMessageAttemptDeliversNothingTwice(t *testing.T) {
	for _, mode := range []string{"new-run", "queued-append", "input"} {
		t.Run(mode, func(t *testing.T) {
			s, fs, age := idemFaults(t)
			if mode == "input" {
				s.orch.Cfg.DefaultHarnessInput = "stream-json"
			}
			code, sbID, _ := round2Create(t, s, "")
			if code != 201 {
				t.Fatalf("create: %d", code)
			}
			ctx := context.Background()
			var active string
			if mode != "new-run" {
				resp, body := call(t, "POST", s.platform.URL+"/v1/sandboxes/"+sbID+"/runs", "t0k", map[string]any{"task": "first"}, nil)
				var r model.Run
				_ = json.Unmarshal(body, &r)
				if resp.StatusCode != 202 {
					t.Fatalf("run: %d %s", resp.StatusCode, body)
				}
				active = r.ID
				if mode == "input" {
					if _, err := fs.Memory.ClaimRun(ctx, r.ID, time.Now(), "", store.RunStamp{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			path := s.platform.URL + "/v1/sandboxes/" + sbID + "/messages"
			send := func() (int, MessageResponse) {
				resp, body := call(t, "POST", path, "t0k", map[string]any{"text": "deploy it"}, map[string]string{"Idempotency-Key": "msg-key"})
				var m MessageResponse
				_ = json.Unmarshal(body, &m)
				return resp.StatusCode, m
			}
			release := make(chan struct{})
			fs.mu.Lock()
			fs.holdLock = release // Say's sandbox lock is the request's first
			fs.mu.Unlock()
			type result struct {
				code int
				m    MessageResponse
			}
			slow := make(chan result, 1)
			go func() { c, m := send(); slow <- result{c, m} }()
			round2WaitFor(t, func() bool { fs.mu.Lock(); defer fs.mu.Unlock(); return fs.holdLock == nil })
			age()
			code, fast := send()
			if code != 202 || fast.Run == nil {
				t.Fatalf("takeover: %d %+v", code, fast)
			}
			close(release)
			old := <-slow
			if old.code != 202 || old.m.Run == nil || old.m.Run.ID != fast.Run.ID || old.m.Delivery != fast.Delivery {
				t.Fatalf("slow attempt: %+v, the later one %+v", old, fast)
			}
			runs, _ := fs.Memory.ListRuns(ctx, sbID)
			switch mode {
			case "new-run":
				if len(runs) != 1 {
					t.Fatalf("%d runs for one message", len(runs))
				}
			case "queued-append":
				got, _ := fs.Memory.GetRun(ctx, active)
				if len(runs) != 1 || strings.Count(got.Task, "deploy it") != 1 {
					t.Fatalf("%d runs, task %q", len(runs), got.Task)
				}
			case "input":
				evs, _ := fs.Memory.ListEvents(ctx, sbID, 0, 0)
				n := 0
				for _, e := range evs {
					if e.Type == model.EventInput && e.Data == "deploy it" {
						n++
					}
				}
				if len(runs) != 1 || n != 1 {
					t.Fatalf("%d runs, %d input events for one message", len(runs), n)
				}
			}
		})
	}
}

// Finding 3: the delivery record could not be written (the attempt died right after queuing
// the run); the retry finds the run by its keyed id instead of queuing a second one.
func TestRound2MessageRetryFindsTheRunWithoutARecord(t *testing.T) {
	s, fs, age := idemFaults(t)
	code, sbID, _ := round2Create(t, s, "")
	if code != 201 {
		t.Fatalf("create: %d", code)
	}
	path := s.platform.URL + "/v1/sandboxes/" + sbID + "/messages"
	fs.notesDown.Store(true)
	fs.putDown.Store(true)
	resp, _ := call(t, "POST", path, "t0k", map[string]any{"text": "hello"}, map[string]string{"Idempotency-Key": "msg-norecord"})
	fs.notesDown.Store(false)
	fs.putDown.Store(false)
	if resp.StatusCode != 202 {
		t.Fatalf("first attempt: %d", resp.StatusCode)
	}
	age()
	if resp, body := call(t, "POST", path, "t0k", map[string]any{"text": "hello"}, map[string]string{"Idempotency-Key": "msg-norecord"}); resp.StatusCode != 202 {
		t.Fatalf("retry: %d %s", resp.StatusCode, body)
	}
	runs, _ := fs.Memory.ListRuns(context.Background(), sbID)
	if len(runs) != 1 || strings.Count(runs[0].Task, "hello") != 1 {
		t.Fatalf("%d runs for one message (%+v)", len(runs), runs)
	}
}

// Finding 5: a reservation a replica of the earlier release left unfinished has no seed; the
// request is not run again (it may already have created a randomly named sandbox), on both
// stores.
func TestRound2LegacyReservationIsNotRunAgain(t *testing.T) {
	for _, backend := range []string{"memory", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			s := newStack(t)
			if backend == "postgres" {
				s.orch.Store = reviewPostgres(t)
			}
			ctx := context.Background()
			raw, _ := json.Marshal(round2CreateBody)
			sum := sha256.Sum256(append(raw, '\n'))
			// The older replica reserved, created its sandbox (random id) and died.
			if err := s.orch.Store.PutIdempotent(ctx, &store.Idempotent{Key: "|POST /v1/sandboxes|legacy", BodyHash: hex.EncodeToString(sum[:]),
				Status: 0, Body: []byte{}, CreatedAt: time.Now().Add(-store.IdempotencyStale - time.Minute)}); err != nil {
				t.Fatal(err)
			}
			if code, _, _ := round2Create(t, s, ""); code != 201 {
				t.Fatalf("the older replica's sandbox: %d", code)
			}
			resp, body := call(t, "POST", s.platform.URL+"/v1/sandboxes", "t0k", round2CreateBody, map[string]string{"Idempotency-Key": "legacy"})
			if resp.StatusCode != 409 || !strings.Contains(string(body), "upgrade") {
				t.Fatalf("legacy reservation: %d %s", resp.StatusCode, body)
			}
			if n := round2Count(t, s); n != 1 {
				t.Fatalf("%d sandboxes", n)
			}
		})
	}
}

// Finding 7: two sandboxes with the same name and owner derive the same preview host; the
// second preview is a 409 preview_host_taken, not a 500, on both stores.
func TestRound2TakenPreviewHostIs409(t *testing.T) {
	for _, backend := range []string{"memory", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			s := newStack(t)
			if backend == "postgres" {
				s.orch.Store = reviewPostgres(t)
			}
			var ids []string
			for range 2 {
				code, id, _ := round2Create(t, s, "")
				if code != 201 {
					t.Fatalf("create: %d", code)
				}
				ids = append(ids, id)
			}
			preview := func(id string) (*http.Response, []byte) {
				return call(t, "PUT", s.platform.URL+"/v1/sandboxes/"+id+"/preview", "t0k", map[string]any{"port": 3000}, nil)
			}
			if resp, body := preview(ids[0]); resp.StatusCode != 200 {
				t.Fatalf("first preview: %d %s", resp.StatusCode, body)
			}
			resp, body := preview(ids[1])
			wantErr(t, "second preview", resp, body, 409, CodePreviewTaken)
		})
	}
}

// round2Provisioned waits for the sandbox to have its pod (waking or running).
func round2Provisioned(t *testing.T, s *stack, id string) {
	t.Helper()
	ctx := context.Background()
	round2WaitFor(t, func() bool {
		sb, err := s.orch.Store.GetSandbox(ctx, id)
		if err != nil || sb.Status != model.StatusWaking && sb.Status != model.StatusRunning {
			return false
		}
		ok, _, _ := s.rt.PodStatus(ctx, sb)
		return ok
	})
}

// Review round 2 of #32, finding 2: the client hangs up right after the run row is written,
// before the wake. The success stored for every retry to replay is not left with a sleeping
// sandbox: the wake does not end with the client.
func TestRound2RunHangupStillWakesTheSandbox(t *testing.T) {
	s, fs, _ := idemFaults(t)
	code, sbID, _ := round2Create(t, s, "")
	if code != 201 {
		t.Fatalf("create: %d", code)
	}
	if resp, body := call(t, "POST", s.platform.URL+"/v1/sandboxes/"+sbID+"/sleep?force=true", "t0k", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("sleep: %d %s", resp.StatusCode, body)
	}
	round2WaitFor(t, func() bool {
		sb, _ := fs.Memory.GetSandbox(context.Background(), sbID)
		return sb.Status == model.StatusSleeping
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs.afterRun.set(cancel)
	req := httptest.NewRequest("POST", "/v1/sandboxes/"+sbID+"/runs", bytes.NewReader([]byte(`{"task":"build"}`+"\n"))).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer t0k")
	req.Header.Set("Idempotency-Key", "run-hangup")
	w := httptest.NewRecorder()
	s.p.Routes().ServeHTTP(w, req)
	fs.afterRun.set(nil)
	if w.Code != 202 {
		t.Fatalf("first attempt: %d %s", w.Code, w.Body)
	}
	resp, body := call(t, "POST", s.platform.URL+"/v1/sandboxes/"+sbID+"/runs", "t0k", map[string]any{"task": "build"}, map[string]string{"Idempotency-Key": "run-hangup"})
	if resp.StatusCode != 202 || resp.Header.Get("Idempotency-Replayed") != "true" {
		t.Fatalf("retry: %d %s", resp.StatusCode, body)
	}
	round2Provisioned(t, s, sbID)
}

// Review round 2 of #32, finding 3: the creation succeeded, its result was not recorded, and
// the sandbox was deleted (here by its owner; a short ttl the same) before the retry took the
// reservation over. The retry does not make it again.
func TestRound2DeletedSandboxIsNotRecreatedByARetry(t *testing.T) {
	s, fs, age := idemFaults(t)
	fs.putDown.Store(true)
	code, id, _ := round2Create(t, s, "deleted")
	fs.putDown.Store(false)
	if code != 201 || id == "" {
		t.Fatalf("first attempt: %d", code)
	}
	if resp, body := call(t, "DELETE", s.platform.URL+"/v1/sandboxes/"+id, "t0k", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d %s", resp.StatusCode, body)
	}
	age()
	resp, body := call(t, "POST", s.platform.URL+"/v1/sandboxes", "t0k", round2CreateBody, map[string]string{"Idempotency-Key": "deleted"})
	if resp.StatusCode != 409 || !strings.Contains(string(body), "deleted") {
		t.Fatalf("retry after the deletion: %d %s", resp.StatusCode, body)
	}
	if n := round2Count(t, s); n != 0 {
		t.Fatalf("the deleted sandbox came back: %d sandboxes", n)
	}
}

// Review round 3 of #32, finding 1: attempt A pauses before its insert; B takes the
// reservation over and creates the sandbox; the sandbox is deleted; A resumes. Its insert of
// the same id is refused by the reservation (it has created its sandbox already), and A
// answers that the sandbox was deleted rather than making it again.
func TestRound2SupersededCreateDoesNotResurrectADeletedSandbox(t *testing.T) {
	s, fs, age := idemFaults(t)
	release := make(chan struct{})
	fs.mu.Lock()
	fs.holdLock = release
	fs.mu.Unlock()
	type result struct {
		code int
		id   string
	}
	slow := make(chan result, 1)
	go func() {
		code, id, _ := round2Create(t, s, "resurrect")
		slow <- result{code, id}
	}()
	round2WaitFor(t, func() bool {
		_, err := fs.Memory.GetIdempotent(context.Background(), "|POST /v1/sandboxes|resurrect")
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return err == nil && fs.holdLock == nil
	})
	age()
	code, id, _ := round2Create(t, s, "resurrect")
	if code != 201 || id == "" {
		t.Fatalf("takeover: %d", code)
	}
	if resp, body := call(t, "DELETE", s.platform.URL+"/v1/sandboxes/"+id, "t0k", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d %s", resp.StatusCode, body)
	}
	close(release)
	if old := <-slow; old.code != 409 {
		t.Fatalf("the superseded attempt: %+v, want 409", old)
	}
	if n := round2Count(t, s); n != 0 {
		t.Fatalf("the deleted sandbox came back: %d sandboxes", n)
	}
}

// Review round 3 of #32, finding 3: the first attempt dies right after its insert, leaving
// the sandbox creating. The retry's recovery cannot take the tenant lock: it answers with an
// error, not a stored 201 for a sandbox nothing provisioned, and the next retry provisions it.
func TestRound2FailedRecoveryIsNotStoredAsSuccess(t *testing.T) {
	s, fs, age := idemFaults(t)
	fs.afterWrite.set(func() { panic(http.ErrAbortHandler) })
	raw, _ := json.Marshal(round2CreateBody)
	req, _ := http.NewRequest("POST", s.platform.URL+"/v1/sandboxes", bytes.NewReader(append(raw, '\n')))
	req.Header.Set("Authorization", "Bearer t0k")
	req.Header.Set("Idempotency-Key", "recovery-fails")
	if resp, err := http.DefaultClient.Do(req); err == nil { // the transport's own retry: 409
		resp.Body.Close()
	}
	fs.afterWrite.set(nil)
	age()
	fs.lockDown.Store(true)
	code, _, _ := round2Create(t, s, "recovery-fails")
	fs.lockDown.Store(false)
	if code < 500 {
		t.Fatalf("recovery without the lock answered %d, want a failure to retry", code)
	}
	code, id, replayed := round2Create(t, s, "recovery-fails")
	if code != 201 || replayed {
		t.Fatalf("retry after the failed recovery: %d replayed=%v", code, replayed)
	}
	round2Provisioned(t, s, id)
	if n := round2Count(t, s); n != 1 {
		t.Fatalf("%d sandboxes for one key", n)
	}
}
