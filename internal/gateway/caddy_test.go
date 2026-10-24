package gateway

import (
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/policy"
)

type fixedHeaders struct {
	m  map[string][]string
	fp string
}

func (f fixedHeaders) HostHeaders() (map[string][]string, string) { return f.m, f.fp }

// Connection header names join the policy's injected ones: stripped from the agent's request
// and copied from the decision, for the hosts the policies serve.
func TestSyncerMergesConnectionHeaderNames(t *testing.T) {
	pols := policy.FromPolicies(&policy.Policy{Slug: "dev", Allow: []policy.Rule{
		{Host: "api.github.com", Paths: []string{"/**"}, Inject: map[string]string{"X-Policy": "p"}},
	}})
	s := &Syncer{Policies: pols, Headers: fixedHeaders{map[string][]string{"api.github.com": {"Authorization", "X-Policy"}, "unknown.example.com": {"X-Other"}}, "fp1"}}
	hs, fp := s.hosts()
	if len(hs) != 1 || strings.Join(hs[0].Injected, ",") != "Authorization,X-Policy" || !strings.HasSuffix(fp, "+fp1") {
		t.Fatalf("hosts: %+v fp=%s", hs, fp)
	}
	c, _ := ca.Generate("t", time.Hour)
	cfg := Config{IP: "10.77.77.1", SandboxdAddr: "127.0.0.1:8081", IngressAddr: "127.0.0.1:8082",
		APIHost: "api.sandbox.internal", RegistrarHost: "registrar.sandbox.internal", PreviewDomain: "preview.example.com"}
	cf, err := Render(cfg, hs, c.PEM())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cf, "request_header -Authorization") || !strings.Contains(cf, "X-Policy Authorization") && !strings.Contains(cf, "Authorization X-Policy") {
		t.Fatalf("rendered config must strip and copy the connection header:\n%s", cf)
	}
	// Without a change on either side the syncer does nothing; a changed header list re-syncs.
	s.last = fp
	if err := s.SyncOnce(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	s.Headers = fixedHeaders{nil, "fp2"}
	if _, fp2 := s.hosts(); fp2 == fp {
		t.Fatal("fingerprint must follow the header list")
	}
}
