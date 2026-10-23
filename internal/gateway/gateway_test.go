package gateway

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/policy"
)

func testSet() *policy.Set {
	return policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Allow: []policy.Rule{
		{Host: "git.example.com", Paths: []string{"/**"}, Inject: map[string]string{"Authorization": "Basic secret:x"}},
		{Host: "api.anthropic.com", Paths: []string{"/v1/**"}, Inject: map[string]string{"x-api-key": "secret:anthropic"}},
		{Host: "netbox.example.com", Paths: []string{"/api/**"}, Upstream: "https://10.0.0.9:8443"},
	}})
}

func TestRender(t *testing.T) {
	c, _ := ca.Generate("t", time.Hour)
	cfg := Config{IP: "10.77.77.1", CaddyAdmin: "http://127.0.0.1:2019", SandboxdAddr: "127.0.0.1:8081", IngressAddr: "127.0.0.1:8082",
		APIHost: "api.sandbox.internal", RegistrarHost: "registrar.sandbox.internal", PreviewDomain: "preview.example.com", StrictSNI: true}
	out, err := Render(cfg, testSet().Hosts(), c.PEM())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"trust_der ", "git.example.com {", "request_header -Authorization", "request_header -X-Api-Key",
		"reverse_proxy https://10.0.0.9:8443", "tls_server_name netbox.example.com", "registrar.sandbox.internal:8443", "*.preview.example.com", "strict_sni_host on"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered Caddyfile lacks %q", want)
		}
	}
	if path, err := exec.LookPath("caddy"); err == nil {
		cmd := exec.Command(path, "validate", "--adapter", "caddyfile", "--config", "/dev/stdin")
		cmd.Stdin = strings.NewReader(out)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("caddy validate failed: %v\n%s\n---\n%s", err, b, out)
		}
	} else {
		t.Log("caddy not installed, skipping caddy validate")
	}
}

func TestDNS(t *testing.T) {
	d := &DNS{IP: net.ParseIP("10.77.77.1"), Policies: testSet(), Extra: []string{"api.sandbox.internal"}}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.ListenAndServe(ctx, addr) }()
	time.Sleep(100 * time.Millisecond)
	cl := &dns.Client{Timeout: time.Second}
	ask := func(name string, qt uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qt)
		r, _, err := cl.Exchange(m, addr)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := ask("git.example.com", dns.TypeA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "10.77.77.1" {
		t.Fatalf("A git: %v", r)
	}
	if r := ask("api.sandbox.internal", dns.TypeA); len(r.Answer) != 1 {
		t.Fatalf("internal host must resolve: %v", r)
	}
	if r := ask("git.example.com", dns.TypeAAAA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatalf("AAAA must be NODATA: %v", r)
	}
	if r := ask("evil.example.com", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Fatalf("unknown name must be NXDOMAIN: %v", r)
	}
}
