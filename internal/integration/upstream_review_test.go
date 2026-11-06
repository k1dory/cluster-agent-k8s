package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/gateway"
	"agent-sandbox/internal/policy"
)

func caddyAdapts(t *testing.T, bin, caddyfile string) (bool, string) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(f, []byte(caddyfile), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "adapt", "--config", f, "--adapter", "caddyfile").CombinedOutput()
	return err == nil, string(out)
}

// Every upstream the validator accepts must adapt in Caddy: one Caddy refuses would fail
// every tenant's /load, so the validator must refuse it and the renderer leave its host out.
func TestRealCaddyAgreesWithTheUpstreamValidator(t *testing.T) {
	bin := caddyBin(t)
	for _, up := range []string{
		"https://10.0.0.5:8443", "http://10.0.0.5", "https://netbox.example.com", "https://[fd00::5]:8443",
		"http://[::ffff:10.0.0.5]:8080", "https://[::ffff:a00:5]",
		"http://h.example.com:80", "https://h.example.com:443", "http://h.example.com:8080",
		"http://h.example.com:443", "https://h.example.com:80", "https://10.0.0.5:8443/api", "https://10.0.0.5/",
		"https://h.example.com?x=1", "https://user:pw@h.example.com",
	} {
		ok, out := caddyAdapts(t, bin, "http://localhost:18080 {\n\treverse_proxy "+up+"\n}\n")
		// One way: the validator may be stricter (it refuses userinfo Caddy would drop), never
		// looser.
		if valid := policy.ValidateUpstream(up) == nil; valid && !ok {
			t.Errorf("%s: the validator accepts what caddy refuses:\n%s", up, out)
		}
	}
	// The full rendered configuration with a bad host among good ones still adapts.
	c, _ := ca.Generate("t", time.Hour)
	cfg := gateway.Config{IP: "10.77.77.1", SandboxdAddr: "127.0.0.1:8081", IngressAddr: "127.0.0.1:8082",
		APIHost: "api.sandbox.internal", RegistrarHost: "registrar.sandbox.internal"}
	cf, err := gateway.Render(cfg, []policy.Host{
		{Name: "a.example.com", Upstream: "https://[fd00::9]:8443"},
		{Name: "b.example.com", Upstream: "http://10.0.0.5:443"},
		{Name: "c.example.com", Upstream: "https://c.example.com"},
	}, c.PEM())
	if err != nil {
		t.Fatal(err)
	}
	if ok, out := caddyAdapts(t, bin, cf); !ok {
		t.Fatalf("the rendered configuration must adapt with the bad host left out:\n%s", out)
	}
}
