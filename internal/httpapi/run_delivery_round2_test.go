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

// round2Store loses the acknowledgement of a committed output batch: the store committed, the
// caller sees an error (a connection that broke during COMMIT).
type round2Store struct {
	store.Store
	loseAck atomic.Int32 // that many committed batches answer with an error
}

func (s *round2Store) AppendRunOutput(ctx context.Context, b *store.OutputBatch) (*store.OutputResult, error) {
	res, err := s.Store.AppendRunOutput(ctx, b)
	if err == nil && s.loseAck.Add(-1) >= 0 {
		return nil, errors.New("conn closed while committing")
	}
	return res, err
}

type round2Pod struct {
	s     *stack
	st    *round2Store
	base  store.Store // the memory store under st: fault hooks go here
	sb    model.Sandbox
	cert  map[string]string
	runID string
}

// newRound2Pod is a running sandbox with a bootstrapped pod and one queued run (not claimed).
func newRound2Pod(t *testing.T) *round2Pod {
	t.Helper()
	s := newStack(t)
	base := s.orch.Store
	st := &round2Store{Store: base}
	s.orch.Store = st
	api, gw := s.platform.URL, s.gateway.URL
	resp, body := call(t, "POST", api+"/v1/sandboxes", "t0k", map[string]any{"name": "r2", "slug": "backend-dev", "owner": "alice"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	p := &round2Pod{s: s, st: st, base: base}
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
// both stored the lines and the usage. (The interleaving is forced in the store's contract test
// TestRound2OutputBatchIsStoredOnce; this is the same through the gateway.)
func TestRound2ConcurrentSameBatchStoresOnce(t *testing.T) {
	p := newRound2Pod(t)
	p.claim(t)
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

// Wiki items 1 and 10: the lines were stored, then a later write of the same post (the batch's
// progress, the usage, the session) failed: the progress was lost and the retry duplicated the
// lines, or the usage or session was lost and the batch acknowledged anyway. A failure anywhere
// in the transaction now stores nothing and answers 5xx; the runner's retry stores it whole.
func TestRound2FailedBatchIsStoredWholeOnRetry(t *testing.T) {
	p := newRound2Pod(t)
	p.claim(t)
	var failed atomic.Int32
	store.SetFaultHook(p.base, func(point string) error {
		if point == store.FaultOutput && failed.CompareAndSwap(0, 1) {
			return errors.New("injected failure before the commit")
		}
		return nil
	})
	defer store.SetFaultHook(p.base, nil)
	body := `{"type":"system","session_id":"sess-r2"}` + "\na\n" + round2UsageLine + "\n"
	if code, out := p.post(t, "b-1", body); code < 500 || failed.Load() != 1 {
		t.Fatalf("a post whose transaction failed: %d %s (failed %d)", code, out, failed.Load())
	}
	if out, r := p.events(t, model.EventRunOutput), p.run(t); len(out) != 0 || r.Usage.CostUSD != 0 || r.Session != "" {
		t.Fatalf("a failed post left %d lines, usage %+v, session %q", len(out), r.Usage, r.Session)
	}
	if code, out := p.post(t, "b-1", body); code != 200 || !strings.Contains(out, `"skipped":0`) {
		t.Fatalf("the runner's retry: %d %s", code, out)
	}
	if code, out := p.post(t, "b-1", body); code != 200 || !strings.Contains(out, `"skipped":3`) {
		t.Fatalf("a second retry: %d %s", code, out)
	}
	if out, r := p.events(t, model.EventRunOutput), p.run(t); len(out) != 3 || r.Usage.CostUSD != 0.5 || r.Session != "sess-r2" {
		t.Fatalf("after the retries: %d lines, usage %+v, session %q", len(out), r.Usage, r.Session)
	}
}

// Codex round 1 of #31, finding 6: a commit whose acknowledgement was lost is a 5xx with the
// batch stored. The answer no longer claims "stored 0 lines", and the retry under the same
// X-Batch-Id (which the spec now requires) stores nothing twice.
func TestRound2LostCommitAcknowledgementIsSafeToRetry(t *testing.T) {
	p := newRound2Pod(t)
	p.claim(t)
	p.st.loseAck.Store(1)
	body := "a\nb\n" + round2UsageLine + "\n"
	code, out := p.post(t, "b-1", body)
	if code < 500 || strings.Contains(out, "stored 0") || !strings.Contains(out, "same X-Batch-Id") {
		t.Fatalf("a post whose commit was not acknowledged: %d %s", code, out)
	}
	if code, out := p.post(t, "b-1", body); code != 200 || !strings.Contains(out, `"skipped":3`) {
		t.Fatalf("the retry: %d %s", code, out)
	}
	if out, r := p.events(t, model.EventRunOutput), p.run(t); len(out) != 3 || r.Usage.CostUSD != 0.5 {
		t.Fatalf("after the retry: %d lines, usage %+v", len(out), r.Usage)
	}
}

// Wiki item 1: the same X-Batch-Id with another body is refused, as Idempotency-Key is, instead
// of silently skipping lines that were never stored. Codex round 1 of #31, finding 4: so is a
// longer body under the id of one that was stored whole (it added its usage).
func TestRound2BatchIdWithOtherBodyIsRefused(t *testing.T) {
	p := newRound2Pod(t)
	p.claim(t)
	if code, out := p.post(t, "b-1", "a\nb\n"); code != 200 {
		t.Fatalf("first: %d %s", code, out)
	}
	if code, out := p.post(t, "b-1", "x\ny\nz\n"); code != 422 {
		t.Fatalf("same id, other body: %d %s", code, out)
	}
	if code, out := p.post(t, "b-1", "a\nb\n"+round2UsageLine+"\n"); code != 422 {
		t.Fatalf("same id, the whole body extended: %d %s", code, out)
	}
	if out, r := p.events(t, model.EventRunOutput), p.run(t); len(out) != 2 || out[0].Data != "a" || r.Usage.CostUSD != 0 {
		t.Fatalf("after the refused bodies: %+v, usage %+v", out, r.Usage)
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
