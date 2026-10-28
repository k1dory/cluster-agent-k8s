// Package integration runs the gateway path end to end against a real Caddy: sandboxd renders
// the Caddyfile and pushes it through the admin API exactly like production, an agent
// bootstraps its identity through the registrar site, and then talks to policy hosts and the
// control plane through the mTLS sites. Nothing is mocked between the agent and sandboxd.
//
// It needs a caddy binary: CADDY_BIN=/path/to/caddy, or caddy on PATH; otherwise it skips.
// CI runs it for every supported Caddy version (see .github/workflows/ci.yaml).
package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/app"
	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/events"
	"agent-sandbox/internal/gateway"
	"agent-sandbox/internal/httpapi"
	"agent-sandbox/internal/mcpproxy"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/registrar"
	"agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

func caddyBin(t *testing.T) string {
	t.Helper()
	if b := os.Getenv("CADDY_BIN"); b != "" {
		return b
	}
	if b, err := exec.LookPath("caddy"); err == nil {
		return b
	}
	if os.Getenv("SANDBOX_TEST_REQUIRE_EXTERNAL") != "" {
		t.Fatal("SANDBOX_TEST_REQUIRE_EXTERNAL is set but no caddy binary was found")
	}
	t.Skip("no caddy binary: set CADDY_BIN or put caddy on PATH")
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// echo is the upstream behind the policy hosts: it answers with the headers it received.
func echo() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := map[string]string{"method": r.Method, "path": r.URL.Path, "host": r.Host}
		for k, v := range r.Header {
			out["h:"+k] = strings.Join(v, ",")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
}

type caddyProc struct {
	cmd *exec.Cmd
	out lockedBuffer
}

// lockedBuffer is Caddy's stdout and stderr. The process writes it from the goroutines exec
// copies its pipes with for as long as it runs, while a test reads it in the middle (a failed
// push, a site never issued), not only after Wait; a bare bytes.Buffer is a data race under
// -race there. Both writes and String go through the lock.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startCaddy launches caddy with only the admin endpoint configured (the bootstrap Caddyfile
// the containers ship with) in a private data directory, and waits for the admin API.
func startCaddy(t *testing.T, bin string, adminPort int) *caddyProc {
	t.Helper()
	dir := t.TempDir()
	boot := fmt.Sprintf("{\n\tskip_install_trust\n\tadmin 127.0.0.1:%d\n}\n", adminPort)
	path := filepath.Join(dir, "Caddyfile.bootstrap")
	if err := os.WriteFile(path, []byte(boot), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "--config", path, "--adapter", "caddyfile")
	cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_DATA_HOME="+dir+"/data", "XDG_CONFIG_HOME="+dir+"/config")
	p := &caddyProc{cmd: cmd}
	cmd.Stdout, cmd.Stderr = &p.out, &p.out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("caddy output:\n%s", p.out.String())
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/config/", adminPort))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return p
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("caddy admin API did not come up:\n%s", p.out.String())
	return nil
}

// waitForCertificates handshakes with every host on port until Caddy has a certificate for it.
// A policy host refuses a handshake without a client certificate; that is a different error
// from "internal error" and means the certificate is there.
func waitForCertificates(t *testing.T, proc *caddyProc, port int, pool *x509.CertPool, hosts ...string) {
	t.Helper()
	for _, host := range hosts {
		deadline := time.Now().Add(30 * time.Second)
		for {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
			if err == nil {
				tc := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: pool})
				err = tc.Handshake()
				tc.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "internal error") {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("caddy never issued a certificate for %s: %v\n%s", host, err, proc.out.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// dialer sends every connection to 127.0.0.1, keeping the port the URL asked for (443 is
// rewritten to Caddy's test https port). SNI and certificate names stay the real host names,
// exactly what the pods see behind the gateway's DNS.
func dialer(httpsPort int) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if port == "443" {
			port = strconv.Itoa(httpsPort)
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
	}
}

func TestRealCaddyGateway(t *testing.T) {
	bin := caddyBin(t)
	ctx := context.Background()
	adminPort, httpsPort, httpPort, regPort := freePort(t), freePort(t), freePort(t), freePort(t)

	// --- sandboxd side -------------------------------------------------------------------
	st := store.NewMemory()
	agentCA, err := ca.Generate("test agent CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tokens := registrar.StaticResolver{}
	reg := &registrar.Registrar{CA: agentCA, Store: st, Resolver: tokens, TTL: time.Hour}
	hub := events.New()
	orch := orchestrator.New(st, orchestrator.NewFakeRuntime(), reg, hub, orchestrator.Config{PreviewDomain: "preview.test"}, nil)
	up := echo()
	defer up.Close()
	pols := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Allow: []policy.Rule{
		{Host: "git.example.com", Upstream: up.URL, Paths: []string{"/*/*/info/refs", "/*/*/git-upload-pack"},
			Inject: map[string]string{"Authorization": "Basic secret:forgejo"}},
		{Host: "mcp.example.com", Upstream: up.URL, Paths: []string{"/mcp", "/mcp/**"}, MCP: &policy.MCPRule{ReadOnly: true, Tools: []string{"get_*"}}},
		// A Claude subscription token held by the gateway (examples/policies/llm-subscriptions.yaml).
		{Host: "api.anthropic.com", Upstream: up.URL, Paths: []string{"/v1/**"}, Inject: map[string]string{"Authorization": "Bearer secret:claude-oauth"}},
	}})
	// The real wiring: the guard adds the live bindings and the connections (headers and the
	// hosts tenants declare on their own) to the repository, for authz, the MCP proxy, the DNS
	// and the gateway config alike.
	secretStore := secrets.Static{"shared/forgejo": "forgejo-injected", "alice/tools": "tools-token", "alice/claude-oauth": "sk-ant-oat01-REAL"}
	services, err := app.Wire(ctx, app.Deps{Store: st, Policies: pols, Secrets: secretStore, Orch: orch})
	if err != nil {
		t.Fatal(err)
	}
	az := &authz.Handler{Policies: services.Guard, Secrets: secretStore, Checker: reg, Toucher: orch, Recorder: orch,
		Quiet: map[string]bool{"api.sandbox.internal": true}}
	gw := httptest.NewServer((&httpapi.Gateway{Orch: orch, Registrar: reg, Authz: az, MCP: &mcpproxy.Handler{Authz: az, Hosts: services.Guard}}).Routes())
	defer gw.Close()
	sandboxdAddr := strings.TrimPrefix(gw.URL, "http://")

	sb, err := orch.Create(ctx, orchestrator.CreateRequest{Name: "shop", Slug: "backend-dev", Owner: "alice", Admin: true})
	if err != nil {
		t.Fatal(err)
	}
	tokens["pod-token"] = registrar.PodInfo{Name: "agent-1", SandboxID: sb.ID, Slug: "backend-dev", Tenant: "alice"}

	// --- gateway: render, push, learn the root ----------------------------------------------
	proc := startCaddy(t, bin, adminPort)
	cfg := gateway.Config{IP: "127.0.0.1", Bind: "127.0.0.1", HTTPSPort: httpsPort, HTTPPort: httpPort,
		CaddyAdmin: fmt.Sprintf("http://127.0.0.1:%d", adminPort), SandboxdAddr: sandboxdAddr,
		APIHost: "api.sandbox.internal", RegistrarHost: "registrar.sandbox.internal", RegistrarPort: regPort,
		AccessLog: "stderr", StrictSNI: true}
	syncer := &gateway.Syncer{Cfg: cfg, Policies: services.Guard, Headers: services.Connections, AgentCA: agentCA.PEM()}
	if err := syncer.SyncOnce(ctx, true); err != nil {
		t.Fatalf("push config: %v\n%s", err, proc.out.String())
	}
	root, err := gateway.FetchRoot(ctx, cfg.CaddyAdmin)
	if err != nil {
		t.Fatal(err)
	}
	reg.SetGatewayCA(root)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		t.Fatal("gateway root is not a PEM certificate")
	}
	// Caddy issues the sites' certificates from its internal CA in the background right after
	// the config is loaded; until then every handshake fails with "internal error". The init
	// container retries bootstrap for that reason; the test waits for every site once so that no
	// request below can hit a site that is still being issued.
	waitForCertificates(t, proc, httpsPort, pool, "git.example.com", "mcp.example.com", "api.anthropic.com", "api.sandbox.internal")
	waitForCertificates(t, proc, regPort, pool, "registrar.sandbox.internal")

	// --- the pod: bootstrap without a client certificate ----------------------------------
	plain := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, DialContext: dialer(httpsPort)}, Timeout: 10 * time.Second}
	keyPEM, csrPEM, _ := ca.NewCSR("backend-dev")
	body, _ := json.Marshal(registrar.BootstrapRequest{CSR: string(csrPEM)})
	// Caddy issues the sites' certificates from its internal CA in the background right after
	// the config is loaded; until then a handshake fails. The init container retries bootstrap
	// for the same reason, so does the test.
	var resp *http.Response
	for deadline := time.Now().Add(30 * time.Second); ; {
		req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://registrar.sandbox.internal:%d/bootstrap", regPort), bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer pod-token")
		resp, err = plain.Do(req)
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("bootstrap through caddy: %v\n%s", err, proc.out.String())
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("bootstrap: %d %s", resp.StatusCode, data)
	}
	var boot registrar.BootstrapResponse
	_ = json.Unmarshal(data, &boot)
	if boot.Instance != 1 || !strings.Contains(boot.GatewayCA, "BEGIN CERTIFICATE") {
		t.Fatalf("bootstrap response: %+v", boot)
	}
	// Anything but POST /bootstrap on the registrar site is a 404.
	if resp, err := plain.Get(fmt.Sprintf("https://registrar.sandbox.internal:%d/crl.pem", regPort)); err != nil || resp.StatusCode != 404 {
		t.Fatalf("registrar site must only serve /bootstrap: %v %v", err, resp)
	}
	leaf, err := tls.X509KeyPair([]byte(boot.Cert), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	agent := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{leaf}},
		DialContext:     dialer(httpsPort)}, Timeout: 10 * time.Second}
	get := func(c *http.Client, method, url string, hdr map[string]string) (int, map[string]string, string) {
		t.Helper()
		var resp *http.Response
		var err error
		for deadline := time.Now().Add(30 * time.Second); ; {
			req, _ := http.NewRequest(method, url, nil)
			for k, v := range hdr {
				req.Header.Set(k, v)
			}
			resp, err = c.Do(req)
			// "internal error" is Caddy still issuing the site certificate (see bootstrap above).
			if err == nil || !strings.Contains(err.Error(), "internal error") || time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s %s: %v\n%s", method, url, err, proc.out.String())
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var m map[string]string
		_ = json.Unmarshal(raw, &m)
		return resp.StatusCode, m, string(raw)
	}

	// --- no client certificate: the handshake itself is refused -------------------------------
	for deadline := time.Now().Add(30 * time.Second); ; {
		_, err := plain.Get("https://git.example.com/org/repo.git/info/refs")
		if err == nil {
			t.Fatal("policy host must refuse a connection without a client certificate")
		}
		if !strings.Contains(err.Error(), "internal error") || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// --- policy host with secret injection -----------------------------------------------------
	// The agent sends its own Authorization and a forged identity; the upstream must see the
	// injected secret and the real identity, and must not see the certificate headers.
	code, seen, raw := get(agent, "GET", "https://git.example.com/org/repo.git/info/refs?service=git-upload-pack",
		map[string]string{"Authorization": "Bearer forged-by-agent", "X-Agent-Slug": "admin", "X-Agent-Cert": "garbage"})
	if code != 200 {
		t.Fatalf("allowed request: %d %s\n%s", code, raw, proc.out.String())
	}
	switch {
	case seen["h:Authorization"] != "Basic forgejo-injected":
		t.Fatalf("upstream must receive the injected secret, got %q (%s)", seen["h:Authorization"], raw)
	case seen["h:X-Agent-Slug"] != "backend-dev" || seen["h:X-Agent-Instance"] != "1" || seen["h:X-Agent-Sandbox"] != sb.ID || seen["h:X-Agent-Tenant"] != "alice":
		t.Fatalf("upstream must receive the verified identity: %s", raw)
	case seen["h:X-Agent-Cert"] != "" || seen["h:X-Agent-San"] != "":
		t.Fatalf("certificate headers must not leak upstream: %s", raw)
	case seen["path"] != "/org/repo.git/info/refs":
		t.Fatalf("path: %s", raw)
	}
	// --- a subscription token: Claude Code with a placeholder CLAUDE_CODE_OAUTH_TOKEN sends a
	// bearer placeholder and the OAuth beta; upstream sees the tenant's token in place of the
	// placeholder and the beta list exactly as the agent sent it.
	const betas = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14"
	code, seen, raw = get(agent, "POST", "https://api.anthropic.com/v1/messages?beta=true",
		map[string]string{"Authorization": "Bearer sk-ant-oat01-placeholder", "Anthropic-Beta": betas, "Anthropic-Version": "2023-06-01"})
	switch {
	case code != 200:
		t.Fatalf("subscription request: %d %s\n%s", code, raw, proc.out.String())
	case seen["h:Authorization"] != "Bearer sk-ant-oat01-REAL":
		t.Fatalf("upstream must receive the tenant's token instead of the placeholder, got %q (%s)", seen["h:Authorization"], raw)
	case seen["h:Anthropic-Beta"] != betas || seen["h:Anthropic-Version"] != "2023-06-01":
		t.Fatalf("the agent's anthropic headers must pass untouched: %s", raw)
	}
	// Denied by policy (push), with the gateway's own 403, before reaching the upstream.
	if code, _, raw := get(agent, "POST", "https://git.example.com/org/repo.git/git-receive-pack", nil); code != 403 {
		t.Fatalf("push must be denied by policy: %d %s", code, raw)
	}
	// Host that is not in the policy at all: not even a certificate for it (strict SNI → handshake or 4xx).
	if resp, err := agent.Get("https://evil.example.com/"); err == nil && resp.StatusCode < 400 {
		t.Fatalf("unknown host must not be served: %d", resp.StatusCode)
	}

	// --- MCP host: proxied through sandboxd, which reads the JSON-RPC body. The agent's own
	// Authorization passes, read-only is marked, forbidden tool calls never reach the upstream.
	post := func(url, body string, hdr map[string]string) (int, map[string]string, string) {
		t.Helper()
		var resp *http.Response
		var err error
		for deadline := time.Now().Add(30 * time.Second); ; {
			req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			for k, v := range hdr {
				req.Header.Set(k, v)
			}
			resp, err = agent.Do(req)
			// "internal error" is Caddy still issuing the site certificate (see get above).
			if err == nil || !strings.Contains(err.Error(), "internal error") || time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("POST %s: %v\n%s", url, err, proc.out.String())
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var m map[string]string
		_ = json.Unmarshal(raw, &m)
		return resp.StatusCode, m, string(raw)
	}
	code, seen, raw = post("https://mcp.example.com/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_item","arguments":{}}}`,
		map[string]string{"Authorization": "Bearer my-own-mcp-token", "X-Sandbox-Mcp-Upstream": "https://evil.example.com"})
	if code != 200 || seen["h:Authorization"] != "Bearer my-own-mcp-token" || seen["h:X-Agent-Access"] != "read-only" ||
		seen["h:X-Agent-Slug"] != "backend-dev" || seen["h:X-Sandbox-Mcp-Upstream"] != "" || seen["h:X-Agent-Cert"] != "" || seen["host"] != "mcp.example.com" {
		t.Fatalf("mcp allowed call: %d %s", code, raw)
	}
	if code, _, raw := post("https://mcp.example.com/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_item"}}`, nil); code != 403 || !strings.Contains(raw, "not allowed") {
		t.Fatalf("mcp forbidden tool must be refused by the proxy: %d %s", code, raw)
	}
	if code, _, _ := post("https://mcp.example.com/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, nil); code != 200 {
		t.Fatalf("mcp tools/list must pass: %d", code)
	}

	// --- control plane API through the gateway: identity from the certificate ------------------
	if code, _, raw := get(agent, "GET", "https://api.sandbox.internal/agent/runs/next?wait=1s", nil); code != 204 {
		t.Fatalf("agent API with no queued run must answer 204: %d %s\n%s", code, raw, proc.out.String())
	}
	run, err := orch.CreateRun(ctx, sb.ID, "write tests")
	if err != nil {
		t.Fatal(err)
	}
	code, got, raw := get(agent, "GET", "https://api.sandbox.internal/agent/runs/next?wait=2s", nil)
	if code != 200 || got["id"] != run.ID {
		t.Fatalf("agent API must hand out the queued run: %d %s", code, raw)
	}
	evReq, _ := http.NewRequest(http.MethodPost, "https://api.sandbox.internal/agent/runs/"+run.ID+"/events", strings.NewReader("hello\n"))
	if resp, err := agent.Do(evReq); err != nil || resp.StatusCode != 200 {
		t.Fatalf("agent output through the gateway: %v %v", err, resp)
	}
	// A forged certificate header on the API host is dropped: the real certificate wins.
	if code, _, _ := get(agent, "GET", "https://api.sandbox.internal/agent/runs/next?wait=1s", map[string]string{"X-Agent-Cert": "garbage"}); code != 204 {
		t.Fatalf("forged X-Agent-Cert must be ignored: %d", code)
	}

	// --- the trace knows what happened ---------------------------------------------------------
	evs, _ := st.QueryEvents(ctx, store.Filter{SandboxID: sb.ID, Types: []string{model.EventEgressOK, model.EventEgressDen}})
	var allow, deny int
	for _, e := range evs {
		if e.Type == model.EventEgressOK {
			allow++
		} else {
			deny++
		}
	}
	if allow != 5 || deny != 2 { // the subscription call is the fifth allow
		t.Fatalf("egress trace: allow=%d deny=%d", allow, deny)
	}

	// --- self-service MCP: a host nobody put in a policy file or a manifest ------------------
	// The admin allows alice the host (tenant settings), alice declares the MCP server as a
	// connection and a sandbox that uses it; the next gateway sync serves the host, the DNS
	// answers for it, the proxy enforces the connection's read-only rule, and a sandbox without
	// the connection is refused at forward_auth.
	t.Run("SelfServiceMCPHost", func(t *testing.T) {
		if _, err := services.Tenants.Put(ctx, "alice", &resource.Document{Spec: json.RawMessage(`{"hosts":["mcp.tools.example.com","ip-mcp.tools.example.com","ip-api.tools.example.com"]}`)}, "admin"); err != nil {
			t.Fatal(err)
		}
		conn := `{"type":"mcp","host":"mcp.tools.example.com","upstream":"` + up.URL + `","paths":["/mcp","/mcp/**"],"mcp":{"read_only":true,"tools":["get_*"]},"headers":{"Authorization":"Bearer secret:tools"}}`
		if _, err := services.Connections.Put(ctx, "alice", &resource.Document{Name: "tools", Spec: json.RawMessage(conn)}, false, "alice"); err != nil {
			t.Fatal(err)
		}
		// A server that answers only to its own address (an IP site): upstream_host sends the
		// upstream's host:port as Host, through the MCP proxy and through Caddy alike.
		for name, spec := range map[string]string{
			"ip-mcp": `{"type":"mcp","host":"ip-mcp.tools.example.com","upstream":"` + up.URL + `","upstream_host":true,"paths":["/"]}`,
			"ip-api": `{"type":"http","host":"ip-api.tools.example.com","upstream":"` + up.URL + `","upstream_host":true,"paths":["/api/**"]}`,
		} {
			if _, err := services.Connections.Put(ctx, "alice", &resource.Document{Name: name, Spec: json.RawMessage(spec)}, false, "alice"); err != nil {
				t.Fatal(err)
			}
		}
		sb2, err := orch.Create(ctx, orchestrator.CreateRequest{Name: "tools", Slug: "backend-dev", Owner: "alice", Tenant: "alice", Admin: true, Connections: []string{"tools", "ip-mcp", "ip-api"}})
		if err != nil {
			t.Fatal(err)
		}
		tokens["pod-token-2"] = registrar.PodInfo{Name: "agent-2", SandboxID: sb2.ID, Slug: "backend-dev", Tenant: "alice"}
		// The DNS answers for the new host before and without any Caddy change.
		d := &gateway.DNS{IP: net.ParseIP("127.0.0.1"), Policies: services.Guard}
		if !d.Allowed("mcp.tools.example.com") || d.Allowed("mcp.other.example.com") {
			t.Fatal("dns must answer exactly the connection's host")
		}
		// The gateway syncs on the changed fingerprint (what the syncer's loop does on its own).
		if err := syncer.SyncOnce(ctx, false); err != nil {
			t.Fatalf("re-sync: %v\n%s", err, proc.out.String())
		}
		waitForCertificates(t, proc, httpsPort, pool, "mcp.tools.example.com", "ip-mcp.tools.example.com", "ip-api.tools.example.com")
		// A second pod, bootstrapped for the sandbox that carries the connection.
		key2, csr2, _ := ca.NewCSR("backend-dev")
		body2, _ := json.Marshal(registrar.BootstrapRequest{CSR: string(csr2)})
		req2, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://registrar.sandbox.internal:%d/bootstrap", regPort), bytes.NewReader(body2))
		req2.Header.Set("Authorization", "Bearer pod-token-2")
		resp2, err := plain.Do(req2)
		if err != nil {
			t.Fatal(err)
		}
		data2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		var boot2 registrar.BootstrapResponse
		_ = json.Unmarshal(data2, &boot2)
		leaf2, err := tls.X509KeyPair([]byte(boot2.Cert), key2)
		if err != nil {
			t.Fatalf("bootstrap 2: %v %s", err, data2)
		}
		agent2 := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{leaf2}}, DialContext: dialer(httpsPort)}, Timeout: 10 * time.Second}
		do := func(c *http.Client, body string) (int, map[string]string, string) {
			req, _ := http.NewRequest(http.MethodPost, "https://mcp.tools.example.com/mcp", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("POST mcp.tools.example.com: %v\n%s", err, proc.out.String())
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			var m map[string]string
			_ = json.Unmarshal(raw, &m)
			return resp.StatusCode, m, string(raw)
		}
		code, seen, raw := do(agent2, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_item","arguments":{}}}`)
		if code != 200 || seen["h:Authorization"] != "Bearer tools-token" || seen["h:X-Agent-Access"] != "read-only" || seen["h:X-Agent-Sandbox"] != sb2.ID || seen["host"] != "mcp.tools.example.com" {
			t.Fatalf("allowed call through the connection host: %d %s\n%s", code, raw, proc.out.String())
		}
		if code, _, raw := do(agent2, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_item"}}`); code != 403 || !strings.Contains(raw, "not allowed") {
			t.Fatalf("the connection's read-only rule must hold: %d %s", code, raw)
		}
		// The first sandbox does not carry the connection: refused by forward_auth.
		if code, _, raw := do(agent, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`); code != 403 {
			t.Fatalf("sandbox without the connection: %d %s", code, raw)
		}
		upHost := strings.TrimPrefix(up.URL, "http://")
		for _, u := range []string{"https://ip-mcp.tools.example.com/", "https://ip-api.tools.example.com/api/x"} {
			req, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(`{"jsonrpc":"2.0","id":4,"method":"tools/list"}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := agent2.Do(req)
			if err != nil {
				t.Fatalf("POST %s: %v\n%s", u, err, proc.out.String())
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var seen map[string]string
			_ = json.Unmarshal(raw, &seen)
			if resp.StatusCode != 200 || seen["host"] != upHost {
				t.Fatalf("upstream_host: %s must reach the upstream as Host %s: %d %s", u, upHost, resp.StatusCode, raw)
			}
		}
	})

	// Review regressions: exercise the untrusted agent side of the real gateway, including
	// the API virtual host, which has a different Caddy route from policy virtual hosts.
	t.Run("ReviewAPIHostCannotChooseCredentialDestination", func(t *testing.T) {
		attacker := echo()
		defer attacker.Close()
		code, seen, raw := get(agent, "GET", "https://api.sandbox.internal/org/repo.git/info/refs", map[string]string{
			mcpproxy.HeaderHost:     "git.example.com",
			mcpproxy.HeaderUpstream: attacker.URL,
		})
		if code < 400 || seen["h:Authorization"] != "" {
			t.Errorf("agent-selected destination must be rejected without a credential: status=%d upstream_authorization=%q response=%s", code, seen["h:Authorization"], raw)
		}
	})
	for _, tc := range []struct{ name, body string }{
		{"MethodCaseCollision", `{"jsonrpc":"2.0","id":4,"method":"tools/call","Method":"ping","params":{"name":"delete_item"}}`},
		{"ToolNameCaseCollision", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"delete_item","Name":"get_item"}}`},
		{"ParamsCaseCollision", `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"delete_item"},"Params":{"name":"get_item"}}`},
	} {
		t.Run("ReviewMCP"+tc.name, func(t *testing.T) {
			code, _, raw := post("https://mcp.example.com/mcp", tc.body, nil)
			if code < 400 {
				t.Errorf("JSON-RPC lowercase method/params/name still select delete_item; request must not reach upstream: status=%d response=%s", code, raw)
			}
		})
	}

	// --- retired identity: still a valid certificate, refused everywhere -----------------------
	if err := reg.RetireSandbox(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if code, _, raw := get(agent, "GET", "https://git.example.com/org/repo.git/info/refs", nil); code != 403 {
		t.Fatalf("retired identity on a policy host: %d %s", code, raw)
	}
	if code, _, raw := get(agent, "GET", "https://api.sandbox.internal/agent/runs/next?wait=1s", nil); code != 403 {
		t.Fatalf("retired identity on the agent API: %d %s", code, raw)
	}

	// --- policy change: re-sync pushes a new config without restarting Caddy ------------------
	pols2 := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Allow: []policy.Rule{
		{Host: "git.example.com", Upstream: up.URL, Paths: []string{"/**"}},
	}})
	syncer.Policies = pols2
	if err := syncer.SyncOnce(ctx, true); err != nil {
		t.Fatalf("re-push: %v", err)
	}
	if _, err := agent.Get("https://mcp.example.com/mcp"); err == nil {
		// mcp.example.com is gone from the policy: no site, no certificate → handshake fails.
		t.Log("mcp host still answered after removal (Caddy may keep the listener briefly)")
	}
}
