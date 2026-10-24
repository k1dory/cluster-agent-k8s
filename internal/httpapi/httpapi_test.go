package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/events"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/ingress"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/registrar"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/usage"
)

type stack struct {
	platform, gateway *httptest.Server
	tokens            registrar.StaticResolver
	rt                *orchestrator.FakeRuntime
	orch              *orchestrator.Orchestrator
}

func newStack(t *testing.T) *stack {
	t.Helper()
	st := store.NewMemory()
	c, _ := ca.Generate("test", time.Hour)
	tokens := registrar.StaticResolver{}
	reg := &registrar.Registrar{CA: c, Store: st, Resolver: tokens, TTL: time.Hour, GatewayCA: []byte("GWROOT")}
	hub := events.New()
	rt := orchestrator.NewFakeRuntime()
	orch := orchestrator.New(st, rt, reg, hub, orchestrator.Config{PreviewDomain: "preview.test",
		Quotas: map[string]orchestrator.Quota{"bob": {MaxSandboxes: 1}}}, nil)
	pols := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Allow: []policy.Rule{
		{Host: "api.anthropic.com", Paths: []string{"/v1/**"}, Inject: map[string]string{"X-Api-Key": "secret:anthropic"}},
		{Host: "api.sandbox.internal", Paths: []string{"/agent/**"}},
	}})
	az := &authz.Handler{Policies: pols, Secrets: secrets.Static{"alice/anthropic": "sk-alice"}, Checker: reg, Toucher: orch,
		Recorder: orch, Quiet: map[string]bool{"api.sandbox.internal": true}}
	ing := &ingress.Handler{Store: st, Waker: orch, TicketKey: []byte("k")}
	p := &Platform{Orch: orch, Hub: hub, Policies: pols, Ingress: ing, Token: "t0k", Tenants: map[string]string{"alice-tok": "alice", "bob-tok": "bob"}}
	g := &Gateway{Orch: orch, Registrar: reg, Authz: az}
	s := &stack{platform: httptest.NewServer(p.Routes()), gateway: httptest.NewServer(g.Routes()), tokens: tokens, rt: rt, orch: orch}
	t.Cleanup(s.platform.Close)
	t.Cleanup(s.gateway.Close)
	return s
}

func call(t *testing.T, method, url, token string, body any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if s, ok := body.(string); ok {
			buf.WriteString(s)
		} else {
			_ = json.NewEncoder(&buf).Encode(body)
		}
	}
	req, _ := http.NewRequest(method, url, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	_, _ = out.ReadFrom(resp.Body)
	return resp, out.Bytes()
}

func TestEndToEnd(t *testing.T) {
	s := newStack(t)
	api := s.platform.URL
	gw := s.gateway.URL

	// Unauthenticated platform calls are refused.
	if resp, _ := call(t, "GET", api+"/v1/sandboxes", "", nil, nil); resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	// Create a sandbox.
	resp, body := call(t, "POST", api+"/v1/sandboxes", "t0k", map[string]any{"name": "shop", "slug": "backend-dev", "owner": "alice"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var sb model.Sandbox
	_ = json.Unmarshal(body, &sb)
	deadline := time.Now().Add(5 * time.Second)
	for sb.Status != model.StatusRunning && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		_, body = call(t, "GET", api+"/v1/sandboxes/"+sb.ID, "t0k", nil, nil)
		_ = json.Unmarshal(body, &sb)
	}
	if sb.Status != model.StatusRunning {
		t.Fatalf("sandbox not running: %+v", sb)
	}

	// Bootstrap: the init container's call.
	s.tokens["pod-token"] = registrar.PodInfo{Name: "agent-x", SandboxID: sb.ID, Slug: "backend-dev", Tenant: "alice"}
	_, csr, _ := ca.NewCSR("backend-dev")
	resp, body = call(t, "POST", gw+"/bootstrap", "pod-token", registrar.BootstrapRequest{CSR: string(csr)}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("bootstrap: %d %s", resp.StatusCode, body)
	}
	var boot registrar.BootstrapResponse
	_ = json.Unmarshal(body, &boot)
	if boot.Instance != 1 || boot.GatewayCA != "GWROOT" {
		t.Fatalf("bootstrap response: %+v", boot)
	}
	if resp, _ := call(t, "POST", gw+"/bootstrap", "wrong", registrar.BootstrapRequest{CSR: string(csr)}, nil); resp.StatusCode != 401 {
		t.Fatalf("bad bootstrap token: %d", resp.StatusCode)
	}
	blk, _ := pem.Decode([]byte(boot.Cert))
	certHdr := map[string]string{identity.HeaderCertDER: base64.StdEncoding.EncodeToString(blk.Bytes)}
	leaf, _ := x509.ParseCertificate(blk.Bytes)
	if leaf.Subject.CommonName != "backend-dev" || len(leaf.URIs) != 3 {
		t.Fatalf("leaf: %s %v", leaf.Subject.CommonName, leaf.URIs)
	}

	// authz as Caddy would call it.
	h := map[string]string{"X-Forwarded-Host": "api.anthropic.com", "X-Forwarded-Method": "POST", "X-Forwarded-Uri": "/v1/messages"}
	for k, v := range certHdr {
		h[k] = v
	}
	resp, _ = call(t, "GET", gw+"/authz", "", nil, h)
	if resp.StatusCode != 200 || resp.Header.Get("X-Api-Key") != "sk-alice" || resp.Header.Get(authz.HeaderInstance) != "1" {
		t.Fatalf("authz allow: %d %v", resp.StatusCode, resp.Header)
	}
	h["X-Forwarded-Host"] = "evil.example.com"
	if resp, _ = call(t, "GET", gw+"/authz", "", nil, h); resp.StatusCode != 403 {
		t.Fatalf("authz deny: %d", resp.StatusCode)
	}

	// Queue a run, agent picks it up, streams output, gets input, finishes.
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/runs", "t0k", map[string]string{"task": "write tests"}, nil)
	if resp.StatusCode != 202 {
		t.Fatalf("create run: %d %s", resp.StatusCode, body)
	}
	var run model.Run
	_ = json.Unmarshal(body, &run)

	resp, body = call(t, "GET", gw+"/agent/runs/next?wait=2s", "", nil, certHdr)
	var got model.Run
	_ = json.Unmarshal(body, &got)
	if resp.StatusCode != 200 || got.ID != run.ID || got.Task != "write tests" {
		t.Fatalf("next run: %d %s", resp.StatusCode, body)
	}
	claudeResult := `{"type":"result","subtype":"success","num_turns":4,"total_cost_usd":0.0421,"usage":{"input_tokens":12,"output_tokens":640,"cache_read_input_tokens":22000,"cache_creation_input_tokens":1500},"modelUsage":{"claude-opus-5-5":{}}}`
	if resp, body = call(t, "POST", gw+"/agent/runs/"+run.ID+"/events", "", "hello\nworld\n"+claudeResult+"\n", certHdr); resp.StatusCode != 200 || !strings.Contains(string(body), `"accepted":3`) {
		t.Fatalf("events: %d %s", resp.StatusCode, body)
	}
	if resp, _ = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/runs/"+run.ID+"/input", "t0k", map[string]string{"text": "use pytest"}, nil); resp.StatusCode != 204 {
		t.Fatalf("input: %d", resp.StatusCode)
	}
	resp, body = call(t, "GET", gw+"/agent/runs/"+run.ID+"/input?wait=2s", "", nil, certHdr)
	var inputs []model.Event
	_ = json.Unmarshal(body, &inputs)
	if resp.StatusCode != 200 || len(inputs) != 1 || inputs[0].Data != "use pytest" {
		t.Fatalf("poll input: %d %s", resp.StatusCode, body)
	}
	if resp, _ = call(t, "POST", gw+"/agent/runs/"+run.ID+"/finish", "", map[string]int{"exit_code": 0}, certHdr); resp.StatusCode != 204 {
		t.Fatalf("finish: %d", resp.StatusCode)
	}
	// Another sandbox's identity cannot touch this run.
	s.tokens["pod-token-2"] = registrar.PodInfo{Name: "agent-y", SandboxID: "other", Slug: "backend-dev", Tenant: "x"}

	// SSE replay contains the whole trail.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", api+"/v1/sandboxes/"+sb.ID+"/events", nil)
	req.Header.Set("Authorization", "Bearer t0k")
	sse, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer sse.Body.Close()
	var types []string
	sc := bufio.NewScanner(sse.Body)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: ") {
			types = append(types, strings.TrimPrefix(line, "event: "))
		}
		if len(types) >= 11 {
			break
		}
	}
	want := []string{"status", "status", "egress.allow", "egress.deny", "run.queued", "run.started", "run.output", "run.output", "run.output", "input", "run.finished"}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Fatalf("event trail %v, want %v", types, want)
	}

	// Second run: cancel it; the agent sees run.cancel on the input poll; JSON event page filters by run.
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/runs", "t0k", map[string]string{"task": "long job"}, nil)
	var run2 model.Run
	_ = json.Unmarshal(body, &run2)
	call(t, "GET", gw+"/agent/runs/next?wait=2s", "", nil, certHdr)
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/runs/"+run2.ID+"/cancel", "t0k", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"status":"cancelled"`) {
		t.Fatalf("cancel: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", gw+"/agent/runs/"+run2.ID+"/input?wait=2s", "", nil, certHdr)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"type":"run.cancel"`) {
		t.Fatalf("agent must see run.cancel: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/events?stream=false&run="+run2.ID, "t0k", nil, nil)
	var page []model.Event
	_ = json.Unmarshal(body, &page)
	if resp.StatusCode != 200 || len(page) != 4 || page[0].Type != "run.queued" || page[3].Type != "run.finished" {
		t.Fatalf("json events for run2: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/runs/"+run2.ID, "t0k", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"status":"cancelled"`) {
		t.Fatalf("get run: %d %s", resp.StatusCode, body)
	}

	// Preview + ticket.
	resp, body = call(t, "PUT", api+"/v1/sandboxes/"+sb.ID+"/preview", "t0k", map[string]any{"port": 3000, "access": "members"}, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"host":"shop-alice.preview.test"`) {
		t.Fatalf("preview: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/preview/ticket", "t0k", map[string]string{"user": "alice"}, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "https://shop-alice.preview.test/__sandbox/auth?ticket=") {
		t.Fatalf("ticket: %d %s", resp.StatusCode, body)
	}

	// Sleep retires the identity: authz now refuses the still-valid certificate.
	if resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/sleep", "t0k", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("sleep: %d %s", resp.StatusCode, body)
	}
	h["X-Forwarded-Host"] = "api.anthropic.com"
	if resp, _ = call(t, "GET", gw+"/authz", "", nil, h); resp.StatusCode != 403 {
		t.Fatalf("retired identity must be denied, got %d", resp.StatusCode)
	}
	if resp, _ = call(t, "GET", gw+"/agent/runs/next?wait=1s", "", nil, certHdr); resp.StatusCode != 403 {
		t.Fatalf("retired identity on agent API must be denied, got %d", resp.StatusCode)
	}
	if resp, _ = call(t, "DELETE", api+"/v1/sandboxes/"+sb.ID, "t0k", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp, _ = call(t, "GET", api+"/openapi.yaml", "", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("openapi: %d", resp.StatusCode)
	}

	// Accounting survives the sandbox: cost parsed from the harness stream, egress decisions, pod time.
	resp, body = call(t, "GET", api+"/v1/usage?tenant=alice&group_by=slug", "t0k", nil, nil)
	var rep usage.Report
	_ = json.Unmarshal(body, &rep)
	if resp.StatusCode != 200 || len(rep.Rows) != 1 || rep.Rows[0].Key != "backend-dev" {
		t.Fatalf("usage: %d %s", resp.StatusCode, body)
	}
	tot := rep.Total
	if tot.Runs != 2 || tot.RunsDone != 1 || tot.RunsCancelled != 1 || tot.ModelUSD != 0.0421 || tot.OutputTokens != 640 ||
		tot.CacheRead != 22000 || tot.Turns != 4 || tot.EgressAllowed != 1 || tot.EgressDenied != 2 || tot.PodSeconds <= 0 {
		t.Fatalf("usage totals: %+v", tot)
	}
	resp, body = call(t, "GET", api+"/v1/usage?tenant=bob", "t0k", nil, nil)
	_ = json.Unmarshal(body, &rep)
	if resp.StatusCode != 200 || rep.Total.Runs != 0 || len(rep.Rows) != 0 {
		t.Fatalf("usage for another tenant must be empty: %s", body)
	}
	if resp, body = call(t, "GET", api+"/v1/usage?group_by=week", "t0k", nil, nil); resp.StatusCode != 400 {
		t.Fatalf("bad group_by: %d %s", resp.StatusCode, body)
	}
	// Trace: what the tenant's agents did, without the output noise unless asked.
	resp, body = call(t, "GET", api+"/v1/trace?tenant=alice", "t0k", nil, nil)
	var trace []model.Event
	_ = json.Unmarshal(body, &trace)
	var egress, outputs int
	for _, e := range trace {
		switch e.Type {
		case model.EventEgressOK:
			egress++
			if !strings.Contains(e.Data, `"host":"api.anthropic.com"`) || e.Tenant != "alice" || e.Slug != "backend-dev" {
				t.Fatalf("egress event: %+v", e)
			}
		case model.EventRunOutput:
			outputs++
		}
	}
	if resp.StatusCode != 200 || egress != 1 || outputs != 0 {
		t.Fatalf("trace: %d egress=%d outputs=%d %s", resp.StatusCode, egress, outputs, body)
	}
	resp, body = call(t, "GET", api+"/v1/trace?tenant=alice&type=all&run="+run.ID, "t0k", nil, nil)
	_ = json.Unmarshal(body, &trace)
	if resp.StatusCode != 200 || len(trace) != 7 || trace[0].Type != "run.queued" {
		t.Fatalf("trace run with output: %d %s", resp.StatusCode, body)
	}
}

// TestTenantsAndContracts covers the API contract around the happy path: tenant-scoped tokens,
// idempotent creation, paging, PATCH, strict parameters, input validation, quotas and the
// delete that the cluster refuses.
func TestTenantsAndContracts(t *testing.T) {
	s := newStack(t)
	api := s.platform.URL
	mk := func(token, name, owner string, extra map[string]any) (*http.Response, model.Sandbox) {
		req := map[string]any{"name": name, "slug": "backend-dev", "owner": owner}
		for k, v := range extra {
			req[k] = v
		}
		resp, body := call(t, "POST", api+"/v1/sandboxes", token, req, nil)
		var sb model.Sandbox
		_ = json.Unmarshal(body, &sb)
		return resp, sb
	}

	// Tenant token: tenant is forced, foreign tenant refused, whoami tells who you are.
	resp, a1 := mk("alice-tok", "one", "alice", map[string]any{"ttl": 3600})
	if resp.StatusCode != 201 || a1.Tenant != "alice" || a1.ExpiresAt == nil {
		t.Fatalf("alice create: %d %+v", resp.StatusCode, a1)
	}
	if resp, _ := mk("alice-tok", "two", "alice", map[string]any{"tenant": "bob"}); resp.StatusCode != 403 {
		t.Fatalf("foreign tenant on create must be 403, got %d", resp.StatusCode)
	}
	resp, body := call(t, "GET", api+"/v1/whoami", "alice-tok", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"tenant":"alice"`) {
		t.Fatalf("whoami: %d %s", resp.StatusCode, body)
	}
	resp, b1 := mk("bob-tok", "one", "bob", nil)
	if resp.StatusCode != 201 || b1.Tenant != "bob" {
		t.Fatalf("bob create: %d %+v", resp.StatusCode, b1)
	}
	// Quota: bob may hold one sandbox.
	resp, body = call(t, "POST", api+"/v1/sandboxes", "bob-tok", map[string]any{"name": "two", "slug": "backend-dev", "owner": "bob"}, nil)
	var eb ErrorBody
	_ = json.Unmarshal(body, &eb)
	if resp.StatusCode != 429 || eb.Code != CodeQuota || eb.RequestID == "" || eb.RequestID != resp.Header.Get("X-Request-Id") {
		t.Fatalf("quota: %d %s", resp.StatusCode, body)
	}
	// Cross-tenant access is refused; admin sees everything; list filters by tenant.
	for _, path := range []string{"", "/runs", "/events?stream=false"} {
		if resp, _ := call(t, "GET", api+"/v1/sandboxes/"+a1.ID+path, "bob-tok", nil, nil); resp.StatusCode != 403 {
			t.Fatalf("bob on alice's sandbox%s: %d", path, resp.StatusCode)
		}
	}
	if resp, _ := call(t, "DELETE", api+"/v1/sandboxes/"+a1.ID, "bob-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob deleting alice's sandbox: %d", resp.StatusCode)
	}
	var list []model.Sandbox
	_, body = call(t, "GET", api+"/v1/sandboxes", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &list)
	if len(list) != 1 || list[0].ID != a1.ID {
		t.Fatalf("alice list: %s", body)
	}
	if resp, _ := call(t, "GET", api+"/v1/sandboxes?tenant=bob", "alice-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("alice listing bob: %d", resp.StatusCode)
	}
	_, body = call(t, "GET", api+"/v1/sandboxes", "t0k", nil, nil)
	_ = json.Unmarshal(body, &list)
	if len(list) != 2 {
		t.Fatalf("admin list: %s", body)
	}
	if resp, _ := call(t, "GET", api+"/v1/usage?tenant=alice", "bob-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob reading alice usage: %d", resp.StatusCode)
	}

	// Paging: limit=1 gives a cursor; following it reaches the end.
	resp, body = call(t, "GET", api+"/v1/sandboxes?limit=1", "t0k", nil, nil)
	_ = json.Unmarshal(body, &list)
	cur := resp.Header.Get("X-Next-Cursor")
	if len(list) != 1 || cur != list[0].ID {
		t.Fatalf("page 1: %s cursor=%q", body, cur)
	}
	resp, body = call(t, "GET", api+"/v1/sandboxes?limit=1&after="+cur, "t0k", nil, nil)
	_ = json.Unmarshal(body, &list)
	if len(list) != 1 || list[0].ID == cur || resp.Header.Get("X-Next-Cursor") == "" {
		t.Fatalf("page 2: %s", body)
	}
	resp, body = call(t, "GET", api+"/v1/sandboxes?limit=1&after="+list[0].ID, "t0k", nil, nil)
	if string(bytes.TrimSpace(body)) != "[]" || resp.Header.Get("X-Next-Cursor") != "" {
		t.Fatalf("page 3 must be empty without cursor: %s %q", body, resp.Header.Get("X-Next-Cursor"))
	}
	// Strict parameters.
	for _, bad := range []string{"?limit=0", "?limit=abc", "?status=awake", "?limit=99999"} {
		if resp, body := call(t, "GET", api+"/v1/sandboxes"+bad, "t0k", nil, nil); resp.StatusCode != 400 {
			t.Fatalf("%s must be 400: %d %s", bad, resp.StatusCode, body)
		}
	}
	if resp, _ := call(t, "GET", api+"/v1/sandboxes/"+a1.ID+"/events?stream=false&after=x", "t0k", nil, nil); resp.StatusCode != 400 {
		t.Fatalf("bad after must be 400: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/trace?since=yesterday", "t0k", nil, nil); resp.StatusCode != 400 {
		t.Fatalf("bad since must be 400: %d", resp.StatusCode)
	}

	// Idempotency: the same key replays the same sandbox, a different key creates another.
	h := map[string]string{"Idempotency-Key": "ci-job-42"}
	resp, body = call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "idem", "slug": "backend-dev", "owner": "alice"}, h)
	var i1 model.Sandbox
	_ = json.Unmarshal(body, &i1)
	resp2, body2 := call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "idem", "slug": "backend-dev", "owner": "alice"}, h)
	var i2 model.Sandbox
	_ = json.Unmarshal(body2, &i2)
	if resp.StatusCode != 201 || resp2.StatusCode != 201 || i1.ID != i2.ID || resp2.Header.Get("Idempotency-Replayed") != "true" {
		t.Fatalf("idempotent create: %d %d %s / %s", resp.StatusCode, resp2.StatusCode, i1.ID, i2.ID)
	}
	// Same key, other tenant: not shared.
	if resp, _ := call(t, "POST", api+"/v1/sandboxes", "t0k", map[string]any{"name": "idem", "slug": "backend-dev", "owner": "carol"}, h); resp.StatusCode != 201 || resp.Header.Get("Idempotency-Replayed") != "" {
		t.Fatalf("idempotency keys must be per tenant: %d", resp.StatusCode)
	}
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+i1.ID+"/runs", "alice-tok", map[string]string{"task": "go"}, map[string]string{"Idempotency-Key": "r1"})
	var r1 model.Run
	_ = json.Unmarshal(body, &r1)
	_, body = call(t, "POST", api+"/v1/sandboxes/"+i1.ID+"/runs", "alice-tok", map[string]string{"task": "go"}, map[string]string{"Idempotency-Key": "r1"})
	var r2 model.Run
	_ = json.Unmarshal(body, &r2)
	if resp.StatusCode != 202 || r1.ID != r2.ID {
		t.Fatalf("idempotent run: %d %s %s", resp.StatusCode, r1.ID, r2.ID)
	}
	_, body = call(t, "GET", api+"/v1/sandboxes/"+i1.ID+"/runs?status=queued", "alice-tok", nil, nil)
	var runs []model.Run
	_ = json.Unmarshal(body, &runs)
	if len(runs) != 1 {
		t.Fatalf("one queued run expected: %s", body)
	}

	// Input validation: empty text, unknown run, finished run.
	if resp, _ := call(t, "POST", api+"/v1/sandboxes/"+i1.ID+"/runs/"+r1.ID+"/input", "alice-tok", map[string]string{"text": "  "}, nil); resp.StatusCode != 400 {
		t.Fatalf("empty input: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/sandboxes/"+i1.ID+"/runs/run_nope/input", "alice-tok", map[string]string{"text": "hi"}, nil); resp.StatusCode != 404 {
		t.Fatalf("unknown run: %d", resp.StatusCode)
	}
	call(t, "POST", api+"/v1/sandboxes/"+i1.ID+"/runs/"+r1.ID+"/cancel", "alice-tok", nil, nil)
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+i1.ID+"/runs/"+r1.ID+"/input", "alice-tok", map[string]string{"text": "hi"}, nil)
	_ = json.Unmarshal(body, &eb)
	if resp.StatusCode != 409 || eb.Code != CodeConflict {
		t.Fatalf("input to cancelled run: %d %s", resp.StatusCode, body)
	}

	// PATCH: idle timeout, wake_on_preview, ttl removal.
	resp, body = call(t, "PATCH", api+"/v1/sandboxes/"+a1.ID, "alice-tok", map[string]any{"idle_timeout": 42, "wake_on_preview": false, "ttl": 0}, nil)
	var upd model.Sandbox
	_ = json.Unmarshal(body, &upd)
	if resp.StatusCode != 200 || upd.IdleTimeout != 42 || upd.WakeOnPreview || upd.ExpiresAt != nil {
		t.Fatalf("patch: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "PATCH", api+"/v1/sandboxes/"+a1.ID, "alice-tok", map[string]any{"idle_timeout": -1}, nil); resp.StatusCode != 400 {
		t.Fatalf("patch negative idle: %d", resp.StatusCode)
	}

	// Delete the cluster refuses: 502, record stays `deleting` with the error; retry succeeds.
	s.rt.SetFailDelete(errors.New("apiserver timeout"))
	resp, body = call(t, "DELETE", api+"/v1/sandboxes/"+a1.ID, "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &eb)
	if resp.StatusCode != 502 || eb.Code != CodeUpstream {
		t.Fatalf("refused delete: %d %s", resp.StatusCode, body)
	}
	_, body = call(t, "GET", api+"/v1/sandboxes/"+a1.ID, "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &upd)
	if upd.Status != model.StatusDeleting || !strings.Contains(upd.Error, "apiserver timeout") {
		t.Fatalf("after refused delete: %+v", upd)
	}
	if resp, _ := call(t, "POST", api+"/v1/sandboxes/"+a1.ID+"/runs", "alice-tok", map[string]string{"task": "x"}, nil); resp.StatusCode != 409 {
		t.Fatalf("run on deleting sandbox: %d", resp.StatusCode)
	}
	s.rt.SetFailDelete(nil)
	if resp, _ := call(t, "DELETE", api+"/v1/sandboxes/"+a1.ID, "alice-tok", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("retry delete: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/sandboxes/"+a1.ID, "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("deleted sandbox still there: %d", resp.StatusCode)
	}
}
