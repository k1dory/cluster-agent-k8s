package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/registrar"
	"agent-sandbox/internal/store"
)

// round2Store injects the failures and interleavings of a multi-replica deployment into the
// writes the agent API used to make one by one. These tests only use methods every release of
// the store has, so they run unchanged against the code before the fix and fail there.
type round2Store struct {
	store.Store
	rendezvous  atomic.Int32  // > 0: that many batch-progress reads wait for each other
	allArrived  chan struct{} // closed when the last of them arrives
	failPut     atomic.Bool   // batch-progress writes fail
	failUsage   atomic.Int32  // that many usage writes fail
	failSession atomic.Int32  // that many session writes fail
}

var errRound2 = errors.New("injected store failure")

func (s *round2Store) GetIdempotent(ctx context.Context, key string) (*store.Idempotent, error) {
	rec, err := s.Store.GetIdempotent(ctx, key)
	if strings.HasPrefix(key, "batch|") {
		if n := s.rendezvous.Add(-1); n >= 0 {
			// Replicas handling the same batch have all read its progress before any of them
			// stores a line.
			if n == 0 {
				close(s.allArrived)
			}
			select {
			case <-s.allArrived:
			case <-time.After(2 * time.Second):
			}
		}
	}
	return rec, err
}

func (s *round2Store) PutIdempotent(ctx context.Context, rec *store.Idempotent) error {
	if strings.HasPrefix(rec.Key, "batch|") && s.failPut.Load() {
		return errRound2
	}
	return s.Store.PutIdempotent(ctx, rec)
}

func (s *round2Store) RecordRunUsage(ctx context.Context, id string, u model.Usage, replace bool) error {
	if s.failUsage.Add(-1) >= 0 {
		return errRound2
	}
	return s.Store.RecordRunUsage(ctx, id, u, replace)
}

func (s *round2Store) SetRunSession(ctx context.Context, id, session string) error {
	if s.failSession.Add(-1) >= 0 {
		return errRound2
	}
	return s.Store.SetRunSession(ctx, id, session)
}

type round2Pod struct {
	s     *stack
	st    *round2Store
	sb    model.Sandbox
	cert  map[string]string
	runID string
}

// newRound2Pod is a running sandbox with a bootstrapped pod and one queued run (not claimed).
func newRound2Pod(t *testing.T) *round2Pod {
	t.Helper()
	s := newStack(t)
	st := &round2Store{Store: s.orch.Store, allArrived: make(chan struct{})}
	s.orch.Store = st
	api, gw := s.platform.URL, s.gateway.URL
	resp, body := call(t, "POST", api+"/v1/sandboxes", "t0k", map[string]any{"name": "r2", "slug": "backend-dev", "owner": "alice"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	p := &round2Pod{s: s, st: st}
	_ = json.Unmarshal(body, &p.sb)
	s.tokens["r2-token"] = registrar.PodInfo{Name: "agent-r2", SandboxID: p.sb.ID, Slug: "backend-dev", Tenant: "alice"}
	_, csr, _ := ca.NewCSR("backend-dev")
	_, body = call(t, "POST", gw+"/bootstrap", "r2-token", registrar.BootstrapRequest{CSR: string(csr)}, nil)
	var boot registrar.BootstrapResponse
	_ = json.Unmarshal(body, &boot)
	blk, _ := pem.Decode([]byte(boot.Cert))
	if blk == nil {
		t.Fatalf("bootstrap: %s", body)
	}
	p.cert = map[string]string{identity.HeaderCertDER: base64.StdEncoding.EncodeToString(blk.Bytes)}
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+p.sb.ID+"/runs", "t0k", map[string]string{"task": "once"}, nil)
	var run model.Run
	if err := json.Unmarshal(body, &run); err != nil || run.ID == "" {
		t.Fatalf("create run: %d %s", resp.StatusCode, body)
	}
	p.runID = run.ID
	return p
}

func (p *round2Pod) headers(kv ...string) map[string]string {
	h := map[string]string{}
	for k, v := range p.cert {
		h[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		h[kv[i]] = kv[i+1]
	}
	return h
}

// next long-polls as the pod; the run as JSON fields (attempt is not a field of older releases).
func (p *round2Pod) next(t *testing.T) (int, map[string]any) {
	t.Helper()
	resp, body := call(t, "GET", p.s.gateway.URL+"/agent/runs/next?wait=1s", "", nil, p.headers())
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return resp.StatusCode, m
}

func (p *round2Pod) post(t *testing.T, batch, body string, kv ...string) (int, string) {
	t.Helper()
	resp, out := call(t, "POST", p.s.gateway.URL+"/agent/runs/"+p.runID+"/events", "", body, p.headers(append([]string{"X-Batch-Id", batch}, kv...)...))
	return resp.StatusCode, string(out)
}

// postAsRunner posts as the runner's spool does: a 5xx or a lost response is sent again.
func (p *round2Pod) postAsRunner(t *testing.T, batch, body string) {
	t.Helper()
	for range 3 {
		if code, _ := p.post(t, batch, body); code < 500 {
			return
		}
	}
	t.Fatal("the batch was never acknowledged")
}

func (p *round2Pod) run(t *testing.T) model.Run {
	t.Helper()
	_, body := call(t, "GET", p.s.platform.URL+"/v1/sandboxes/"+p.sb.ID+"/runs/"+p.runID, "t0k", nil, nil)
	var r model.Run
	_ = json.Unmarshal(body, &r)
	return r
}

func (p *round2Pod) events(t *testing.T, typ string) []model.Event {
	t.Helper()
	evs, err := p.st.ListEvents(context.Background(), p.sb.ID, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []model.Event
	for _, e := range evs {
		if e.RunID == p.runID && e.Type == typ {
			out = append(out, *e)
		}
	}
	return out
}

func (p *round2Pod) claim(t *testing.T) map[string]any {
	t.Helper()
	code, run := p.next(t)
	if code != 200 || run["id"] != p.runID {
		t.Fatalf("claim: %d %v", code, run)
	}
	return run
}

const round2UsageLine = `{"type":"usage","input_tokens":10,"output_tokens":5,"cost_usd":0.5}`

// Wiki item 1: two replicas handling the same X-Batch-Id at once (the runner retried after a
// network error while the original was still in flight) both read "nothing stored yet" and
// both stored the lines and the usage.
func TestRound2ConcurrentSameBatchStoresOnce(t *testing.T) {
	p := newRound2Pod(t)
	p.claim(t)
	p.st.rendezvous.Store(2)
	var wg sync.WaitGroup
	codes := make([]int, 6)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _ = p.post(t, "b-1", "a\nb\n"+round2UsageLine+"\n")
		}(i)
	}
	wg.Wait()
	for _, c := range codes {
		if c != 200 {
			t.Fatalf("posts: %v", codes)
		}
	}
	if out, r := p.events(t, model.EventRunOutput), p.run(t); len(out) != 3 || r.Usage.CostUSD != 0.5 || r.Usage.InputTokens != 10 {
		t.Fatalf("six concurrent posts of one batch: %d lines, usage %+v", len(out), r.Usage)
	}
}

// Wiki item 1: the lines were stored, the write of the batch's progress failed and was ignored:
// the runner's retry of the batch stored every line again.
func TestRound2BatchRetryAfterProgressWriteFailure(t *testing.T) {
	p := newRound2Pod(t)
	p.claim(t)
	p.st.failPut.Store(true)
	body := "a\nb\n" + round2UsageLine + "\n"
	p.post(t, "b-1", body)
	p.post(t, "b-1", body) // the response was lost: the runner sends it again
	if out, r := p.events(t, model.EventRunOutput), p.run(t); len(out) != 3 || r.Usage.CostUSD != 0.5 {
		t.Fatalf("retry after a failed progress write: %d lines, usage %+v", len(out), r.Usage)
	}
}

// Wiki item 1: the same X-Batch-Id with another body is refused, as Idempotency-Key is, instead
// of silently skipping lines that were never stored.
func TestRound2BatchIdWithOtherBodyIsRefused(t *testing.T) {
	p := newRound2Pod(t)
	p.claim(t)
	if code, out := p.post(t, "b-1", "a\nb\n"); code != 200 {
		t.Fatalf("first: %d %s", code, out)
	}
	if code, out := p.post(t, "b-1", "x\ny\nz\n"); code != 422 {
		t.Fatalf("same id, other body: %d %s", code, out)
	}
	if out := p.events(t, model.EventRunOutput); len(out) != 2 || out[0].Data != "a" {
		t.Fatalf("lines after the refused body: %+v", out)
	}
}

// Wiki item 10: the usage write failed after the line was stored; the error was logged and the
// batch acknowledged, so the runner never sent it again and the run's cost was lost.
func TestRound2UsageWriteFailureIsNotAcknowledged(t *testing.T) {
	p := newRound2Pod(t)
	p.claim(t)
	p.st.failUsage.Store(1)
	p.postAsRunner(t, "b-1", "a\n"+round2UsageLine+"\n")
	if out, r := p.events(t, model.EventRunOutput), p.run(t); len(out) != 2 || r.Usage.CostUSD != 0.5 || r.Usage.InputTokens != 10 {
		t.Fatalf("after a failed usage write: %d lines, usage %+v", len(out), r.Usage)
	}
}

// Wiki item 10: the session id was cached on the replica before its write succeeded, so when
// the write failed every later line naming the same session was skipped and resume had none.
func TestRound2SessionWriteFailureIsRetried(t *testing.T) {
	p := newRound2Pod(t)
	p.claim(t)
	p.st.failSession.Store(1)
	line := `{"type":"system","session_id":"sess-r2"}`
	p.postAsRunner(t, "b-1", line+"\n")
	p.postAsRunner(t, "b-2", line+"\n")
	if r := p.run(t); r.Session != "sess-r2" {
		t.Fatalf("session after a failed write: %q", r.Session)
	}
}

// Wiki item 3: the claim committed, its response was lost, and the runner's retry only looked
// at queued runs: the run stayed running forever with no runner. The same pod asking again gets
// it back under a new attempt; the earlier attempt is fenced off.
func TestRound2LostClaimResponseIsHandedOutAgain(t *testing.T) {
	p := newRound2Pod(t)
	first := p.claim(t) // the response never reaches the runner
	code, again := p.next(t)
	if code != 200 || again["id"] != p.runID {
		t.Fatalf("the same pod asking again after a lost response: %d %v", code, again)
	}
	a1, _ := first["attempt"].(float64)
	a2, _ := again["attempt"].(float64)
	if a1 < 1 || a2 <= a1 {
		t.Fatalf("attempts: first %v, again %v", first["attempt"], again["attempt"])
	}
	stale, cur := strconv.Itoa(int(a1)), strconv.Itoa(int(a2))
	gw := p.s.gateway.URL + "/agent/runs/" + p.runID
	if code, out := p.post(t, "b-1", "late\n", "X-Run-Attempt", stale); code != 409 {
		t.Fatalf("output of the stale attempt: %d %s", code, out)
	}
	if resp, out := call(t, "GET", gw+"/input?after=0&wait=1s", "", nil, p.headers("X-Run-Attempt", stale)); resp.StatusCode != 409 {
		t.Fatalf("input poll of the stale attempt: %d %s", resp.StatusCode, out)
	}
	if resp, out := call(t, "POST", gw+"/finish", "", map[string]int{"exit_code": 0}, p.headers("X-Run-Attempt", stale)); resp.StatusCode != 409 {
		t.Fatalf("finish of the stale attempt: %d %s", resp.StatusCode, out)
	}
	if code, out := p.post(t, "b-2", "ok\n", "X-Run-Attempt", cur); code != 200 {
		t.Fatalf("output of the current attempt: %d %s", code, out)
	}
	// The runner's first call about the run confirmed the claim: it is not handed out again.
	if code, run := p.next(t); code != 204 {
		t.Fatalf("a confirmed claim was handed out again: %d %v", code, run)
	}
	if resp, out := call(t, "POST", gw+"/finish", "", map[string]int{"exit_code": 0}, p.headers("X-Run-Attempt", cur)); resp.StatusCode != 204 {
		t.Fatalf("finish of the current attempt: %d %s", resp.StatusCode, out)
	}
	if r := p.run(t); r.Status != model.RunDone {
		t.Fatalf("run after finish: %+v", r)
	}
	if out := p.events(t, model.EventRunOutput); len(out) != 1 || out[0].Data != "ok" {
		t.Fatalf("output: %+v", out)
	}
}

// Wiki item 2: a run cancelled without its run.cancel (a replica of an older release wrote the
// status and died, or failed to write the event) used to leave the harness running: the runner
// acts on the event, not on the status. Its input poll now delivers the command.
func TestRound2CancelledRunWithoutCommandIsDeliveredOnPoll(t *testing.T) {
	p := newRound2Pod(t)
	p.claim(t)
	if _, err := p.st.SettleRun(context.Background(), p.runID, []model.RunStatus{model.RunRunning}, model.RunCancelled, 0, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		resp, body := call(t, "GET", p.s.gateway.URL+"/agent/runs/"+p.runID+"/input?after=0&wait=1s", "", nil, p.headers())
		var evs []model.Event
		_ = json.Unmarshal(body, &evs)
		if resp.StatusCode != 200 || len(evs) != 1 || evs[0].Type != model.EventRunCancel {
			t.Fatalf("input poll of a cancelled run: %d %s", resp.StatusCode, body)
		}
	}
	if n := len(p.events(t, model.EventRunCancel)); n != 1 {
		t.Fatalf("run.cancel written %d times", n)
	}
}
