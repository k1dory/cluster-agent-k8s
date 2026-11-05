package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
)

// runOfflineInNetns keeps a model-call test's agent on the same loopback as the gateway bridge and
// the test gateway. sandbox-exec (macOS) cuts the agent's network but not its loopback; unshare
// -rn would give the agent a namespace, and a loopback, of its own. So on Linux the test runs
// again, whole, in a new network namespace (TestMain brings lo up; ACP_TEST_NETWORK=none), and the
// parent reports its verdict: true means the test ran there and the caller returns.
func runOfflineInNetns(t *testing.T) bool {
	t.Helper()
	if os.Getenv("ACP_TEST_NETWORK") == "none" {
		return false
	}
	if _, err := exec.LookPath("sandbox-exec"); err == nil {
		return false
	}
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		t.Skip("no way to run the test without network here (sandbox-exec, unshare -rn)")
	}
	cmd := exec.Command("unshare", "-rn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.count=1")
	// Inside: lo brought up by TestMain (ACP_TEST_NETNS), and noNetwork knows the network is cut.
	cmd.Env = append(os.Environ(), "ACP_TEST_NETWORK=none", "ACP_TEST_NETNS=1")
	out, err := cmd.CombinedOutput()
	switch {
	case strings.Contains(string(out), "--- SKIP: "+t.Name()):
		t.Skipf("skipped in the network namespace:\n%s", out)
	case err != nil || !strings.Contains(string(out), "--- PASS: "+t.Name()):
		t.Fatalf("in a new network namespace: %v\n%s", err, out)
	}
	return true
}

// gatewayRequest is what the test gateway saw of one request.
type gatewayRequest struct {
	ClientCN, SNI, Host, Method, Path, APIKey, Authorization, Upgrade string
}

// modelCallThroughGateway runs a shipped profile's real agent through the runner (execute) for a
// one-message conversation, with no network but loopback, against a test gateway that requires
// the pod's client certificate on every connection, as the real one does. The agent reaches it
// the way it would in a pod: through the gateway bridge, by the base URL its profile sets.
// handler answers what passes the client-certificate check. It returns the run's output and
// what the gateway saw. bin is the agent program; the profile's command must start with name.
// homeEnv adds variables that depend on the agent's (test) home, as the image would set them.
func modelCallThroughGateway(t *testing.T, example, name, bin string, host string, handler http.Handler, homeEnv ...func(home string) map[string]string) ([]string, []gatewayRequest) {
	t.Helper()
	isolate := noNetwork(t)
	var mu sync.Mutex
	var seen []gatewayRequest
	gw := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, gatewayRequest{ClientCN: r.TLS.PeerCertificates[0].Subject.CommonName, SNI: r.TLS.ServerName, Host: r.Host,
			Method: r.Method, Path: r.URL.Path, APIKey: r.Header.Get("x-api-key"), Authorization: r.Header.Get("Authorization"), Upgrade: r.Header.Get("Upgrade")})
		mu.Unlock()
		handler.ServeHTTP(w, r)
	}), host)
	gw.route(t)

	_, cp, cl := setupACP(t, "")
	t.Setenv("ACP_FAKE_AGENT", "")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("SANDBOX_INSTRUCTIONS", "")
	t.Setenv("CERT_DIR", gw.certDir)
	t.Setenv("SANDBOX_GATEWAY_BRIDGE", "http://"+gatewayBridgeAddr)
	raw, err := os.ReadFile(filepath.Join("../../examples/catalog", example))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := catalog.ParseYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	var profile catalog.EnvironmentSpec
	if err := json.Unmarshal(doc.Spec, &profile); err != nil {
		t.Fatal(err)
	}
	cmd, ok := strings.CutPrefix(profile.Harness.Command, name)
	if !ok {
		t.Fatalf("the example's command %q does not run %s", profile.Harness.Command, name)
	}
	home := os.Getenv("HOME")
	files, _ := json.Marshal(profile.Harness.Files)
	if _, err := writeHarnessFiles(string(files), home); err != nil {
		t.Fatal(err)
	}
	for k, v := range profile.Env {
		t.Setenv(k, v)
	}
	for _, f := range homeEnv {
		for k, v := range f(home) {
			t.Setenv(k, v)
		}
	}
	t.Setenv("HARNESS_PERMISSIONS", profile.Harness.Permissions)
	t.Setenv("HARNESS_AUTH_METHOD", profile.Harness.AuthMethod)
	quoted := make([]string, len(isolate))
	for i, a := range isolate {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	t.Setenv("HARNESS_CMD", strings.Join(quoted, " ")+` "`+bin+`"`+cmd)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go serveGatewayBridge(ctx, gw.certDir)
	for i := 0; ; i++ {
		if c, err := net.DialTimeout("tcp", gatewayBridgeAddr, 200*time.Millisecond); err == nil {
			c.Close()
			break
		}
		if i == 50 {
			t.Fatal("the gateway bridge did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	runCtx, stop := context.WithTimeout(ctx, 90*time.Second)
	defer stop()
	done := make(chan int, 1)
	go func() { done <- execute(runCtx, cl, &model.Run{ID: "run_model", Task: "Reply with one word."}) }()
	select {
	case <-done:
	case <-time.After(100 * time.Second):
		t.Fatal("the run did not end")
	}
	cp.mu.Lock()
	lines := append([]string(nil), cp.lines...)
	cp.mu.Unlock()
	mu.Lock()
	defer mu.Unlock()
	return lines, append([]gatewayRequest(nil), seen...)
}

// anthropicAnswer is a Messages API that always answers text: streamed (SSE) when asked to,
// as one JSON message otherwise; count_tokens is answered too.
func anthropicAnswer(text string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/v1/messages/count_tokens"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"input_tokens":5}`)
		case strings.HasSuffix(r.URL.Path, "/v1/messages"):
			var req struct {
				Model  string `json:"model"`
				Stream bool   `json:"stream"`
			}
			_ = json.Unmarshal(body, &req)
			t, _ := json.Marshal(text)
			if !req.Stream {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"msg_test","type":"message","role":"assistant","model":"`+req.Model+`","content":[{"type":"text","text":`+string(t)+`}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":5,"output_tokens":3}}`)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			for _, ev := range []string{
				`event: message_start` + "\n" + `data: {"type":"message_start","message":{"id":"msg_test","type":"message","role":"assistant","model":"` + req.Model + `","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":5,"output_tokens":1}}}`,
				`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
				`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":` + string(t) + `}}`,
				`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}`,
				`event: message_delta` + "\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":3}}`,
				`event: message_stop` + "\n" + `data: {"type":"message_stop"}`,
			} {
				_, _ = io.WriteString(w, ev+"\n\n")
				w.(http.Flusher).Flush()
			}
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"type":"error","error":{"type":"not_found_error","message":"not here"}}`)
		}
	})
}

// assertAnswered checks that the agent's answer, which only the test gateway knew, is in the
// run's transcript, and that every request the gateway saw came with the pod's certificate.
func assertAnswered(t *testing.T, lines []string, seen []gatewayRequest, answer, host string) {
	t.Helper()
	got := false
	for _, l := range lines {
		if role, text := harness.ParseMessage(l); role == "assistant" && strings.Contains(text, answer) {
			got = true
		}
	}
	if !got || len(seen) == 0 {
		t.Fatalf("the model's answer did not come back through the gateway (requests seen: %+v); output:\n%s", seen, strings.Join(lines, "\n"))
	}
	for _, r := range seen {
		if r.ClientCN != "sandbox-test/1" || r.SNI != host || r.Host != host {
			t.Fatalf("a request reached the gateway without the pod's identity or host: %+v", r)
		}
	}
}

// codex-acp's model calls go through the bridge with the pod's certificate: a request reaches
// the gateway's OpenAI host at /v1/responses carrying the profile's placeholder key. The test
// gateway does not play the Responses API, so only the arrival is checked. Runs in the agent
// image's check (hack/ci/images.sh) or with CODEX_ACP_TEST_BIN.
func TestACPCodexExampleReachesTheModelThroughTheGateway(t *testing.T) {
	bin := os.Getenv("CODEX_ACP_TEST_BIN")
	if bin == "" && os.Getenv("ACP_TEST_NETWORK") == "none" {
		bin, _ = exec.LookPath("codex-acp")
	}
	if bin == "" {
		t.Skip("set CODEX_ACP_TEST_BIN to run the Codex model-call test (it runs by itself in the agent image's check)")
	}
	if runOfflineInNetns(t) {
		return
	}
	lines, seen := modelCallThroughGateway(t, "environment-codex-acp.yaml", "codex-acp", bin, "api.openai.com",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error":{"message":"test gateway"}}`, http.StatusServiceUnavailable)
		}))
	for _, r := range seen {
		if strings.HasSuffix(r.Path, "/v1/responses") && r.ClientCN == "sandbox-test/1" && r.SNI == "api.openai.com" &&
			r.Authorization == "Bearer placeholder-the-gateway-injects-the-real-key" {
			return
		}
	}
	t.Fatalf("no Codex model call reached the gateway with the pod's certificate and the profile's key: %+v; output:\n%s", seen, strings.Join(lines, "\n"))
}
