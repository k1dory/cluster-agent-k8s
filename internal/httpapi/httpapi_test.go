package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
}

func newStack(t *testing.T) *stack {
	t.Helper()
	st := store.NewMemory()
	c, _ := ca.Generate("test", time.Hour)
	tokens := registrar.StaticResolver{}
	reg := &registrar.Registrar{CA: c, Store: st, Resolver: tokens, TTL: time.Hour, GatewayCA: []byte("GWROOT")}
	hub := events.New()
	orch := orchestrator.New(st, orchestrator.NewFakeRuntime(), reg, hub, orchestrator.Config{PreviewDomain: "preview.test"}, nil)
	pols := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Allow: []policy.Rule{
		{Host: "api.anthropic.com", Paths: []string{"/v1/**"}, Inject: map[string]string{"X-Api-Key": "secret:anthropic"}},
		{Host: "api.sandbox.internal", Paths: []string{"/agent/**"}},
	}})
	az := &authz.Handler{Policies: pols, Secrets: secrets.Static{"alice/anthropic": "sk-alice"}, Checker: reg, Toucher: orch,
		Recorder: orch, Quiet: map[string]bool{"api.sandbox.internal": true}}
	ing := &ingress.Handler{Store: st, Waker: orch, TicketKey: []byte("k")}
	p := &Platform{Orch: orch, Hub: hub, Policies: pols, Ingress: ing, Token: "t0k"}
	g := &Gateway{Orch: orch, Registrar: reg, Authz: az}
	s := &stack{platform: httptest.NewServer(p.Routes()), gateway: httptest.NewServer(g.Routes()), tokens: tokens}
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
	if resp, _ = call(t, "POST", gw+"/agent/runs/"+run.ID+"/events", "", "hello\nworld\n"+claudeResult+"\n", certHdr); resp.StatusCode != 204 {
		t.Fatalf("events: %d", resp.StatusCode)
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
