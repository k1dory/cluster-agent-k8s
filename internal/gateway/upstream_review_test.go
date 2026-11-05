package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/policy"
)

type staticHosts struct {
	hs []policy.Host
	fp atomic.Value // string
}

func (h *staticHosts) Hosts() []policy.Host { return append([]policy.Host(nil), h.hs...) }
func (h *staticHosts) Fingerprint() string  { return h.fp.Load().(string) }

func reviewCfg() Config {
	return Config{IP: "10.77.77.1", SandboxdAddr: "127.0.0.1:8081", IngressAddr: "127.0.0.1:8082",
		APIHost: "api.sandbox.internal", RegistrarHost: "registrar.sandbox.internal"}
}

// One stored upstream Caddy would refuse must not take every other host down with it: the
// renderer leaves that host out and says so.
func TestReviewRenderLeavesOutAHostWithAnInvalidUpstream(t *testing.T) {
	c, _ := ca.Generate("t", time.Hour)
	hs := []policy.Host{
		{Name: "bad.example.com", Upstream: "https://10.0.0.5:8443/api"},
		{Name: "badport.example.com", Upstream: "http://10.0.0.5:443"},
		{Name: "badport2.example.com", Upstream: "https://10.0.0.5:80"},
		{Name: "good.example.com", Upstream: "https://good.example.com"},
	}
	out, skipped, err := render(reviewCfg(), hs, c.PEM())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "bad.example.com") || strings.Contains(out, "badport") || !strings.Contains(out, "good.example.com {") {
		t.Fatalf("the bad host must be left out and the good one kept:\n%s", out)
	}
	if len(skipped) != 3 || skipped[0].Host != "bad.example.com" {
		t.Fatalf("skipped: %+v", skipped)
	}
}

// An IPv6 upstream for a named host needs the name for SNI and verification, like IPv4 does.
func TestReviewRenderIPv6UpstreamGetsTLSServerName(t *testing.T) {
	c, _ := ca.Generate("t", time.Hour)
	out, err := Render(reviewCfg(), []policy.Host{{Name: "netbox.example.com", Upstream: "https://[fd00::9]:8443"}}, c.PEM())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "reverse_proxy https://[fd00::9]:8443") || !strings.Contains(out, "tls_server_name netbox.example.com") {
		t.Fatalf("IPv6 upstream must render with tls_server_name:\n%s", out)
	}
}

func TestReviewRejectedHostIsNamedFromCaddysLine(t *testing.T) {
	c, _ := ca.Generate("t", time.Hour)
	cf, err := Render(reviewCfg(), []policy.Host{{Name: "a.example.com", Upstream: "https://a.example.com"}, {Name: "b.example.com", Upstream: "https://b.example.com"}}, c.PEM())
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(cf, "\n")
	line := 0
	for i, l := range lines {
		if strings.Contains(l, "reverse_proxy https://b.example.com") {
			line = i + 1
		}
	}
	got := rejectedHost(cf, errString("caddy admin /load: 400 Bad Request: {\"error\":\"adapting config using caddyfile: Caddyfile:"+strconv.Itoa(line)+" - bad\"}"))
	if got != "b.example.com" {
		t.Fatalf("host at line %d = %q", line, got)
	}
	if got := rejectedHost(cf, errString("Caddyfile:2 - bad global")); got != "" {
		t.Fatalf("global options must not be attributed to a host: %q", got)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// A configuration Caddy refuses is retried with backoff (not every tick), reported in the
// syncer's status with the host it names, and a later change is tried at once.
func TestReviewSyncerBacksOffAndReportsARejectedLoad(t *testing.T) {
	var loads atomic.Int32
	var refuse atomic.Bool
	refuse.Store(true)
	caddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loads.Add(1)
		body, _ := io.ReadAll(r.Body)
		if refuse.Load() {
			n := 0
			for i, l := range strings.Split(string(body), "\n") {
				if strings.Contains(l, "reverse_proxy https://b.example.com") {
					n = i + 1
				}
			}
			http.Error(w, `{"error":"adapting config using caddyfile: Caddyfile:`+strconv.Itoa(n)+` - unrecognized"}`, http.StatusBadRequest)
			return
		}
	}))
	defer caddy.Close()
	c, _ := ca.Generate("t", time.Hour)
	cfg := reviewCfg()
	cfg.CaddyAdmin = caddy.URL
	hosts := &staticHosts{hs: []policy.Host{{Name: "b.example.com", Upstream: "https://b.example.com"}}}
	hosts.fp.Store("v1")
	s := &Syncer{Cfg: cfg, Policies: hosts, AgentCA: c.PEM()}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go s.Run(ctx, 20*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for s.Status().Failures == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // 15 ticks: without backoff, 15 more loads
	st := s.Status()
	if st.Healthy() || st.Host != "b.example.com" || st.FailingSince.IsZero() || !strings.Contains(st.LastError, "b.example.com") {
		t.Fatalf("status must report the rejected host: %+v", st)
	}
	if n := loads.Load(); n > 2 {
		t.Fatalf("an unchanged configuration Caddy refuses must back off, got %d loads in 300ms", n)
	}
	// The operator fixes it: the change is tried at the next tick, not after the backoff.
	refuse.Store(false)
	hosts.fp.Store("v2")
	deadline = time.Now().Add(time.Second)
	for !s.Status().Healthy() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := s.Status(); !st.Healthy() || st.LastSync.IsZero() {
		t.Fatalf("a changed configuration must be tried promptly: %+v", st)
	}
}

func TestReviewRetryAfterGrowsAndCaps(t *testing.T) {
	if retryAfter(1) != 5*time.Second || retryAfter(2) != 10*time.Second || retryAfter(50) != 5*time.Minute {
		t.Fatalf("retryAfter: %v %v %v", retryAfter(1), retryAfter(2), retryAfter(50))
	}
}

// A succeeds, B fails, A is restored: nothing needs loading, but the failure B left in the
// status must not stay there forever (Run reports recovery and stops retrying).
func TestReviewRevertingToTheAcceptedConfigClearsTheFailure(t *testing.T) {
	var refuse atomic.Bool
	caddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() {
			http.Error(w, `{"error":"Caddyfile:1 - no"}`, http.StatusBadRequest)
		}
	}))
	defer caddy.Close()
	c, _ := ca.Generate("t", time.Hour)
	cfg := reviewCfg()
	cfg.CaddyAdmin = caddy.URL
	hosts := &staticHosts{hs: []policy.Host{{Name: "a.example.com", Upstream: "https://a.example.com"}}}
	hosts.fp.Store("A")
	s := &Syncer{Cfg: cfg, Policies: hosts, AgentCA: c.PEM()}
	if err := s.SyncOnce(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	loaded := s.Status().LastSync
	refuse.Store(true)
	hosts.fp.Store("B")
	if err := s.SyncOnce(t.Context(), false); err == nil || s.Status().Healthy() {
		t.Fatal("B must fail")
	}
	hosts.fp.Store("A")
	if err := s.SyncOnce(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if !st.Healthy() || !st.FailingSince.IsZero() || st.LastError != "" || st.Host != "" || !st.LastSync.Equal(loaded) {
		t.Fatalf("restoring the accepted configuration must clear the failure and keep LastSync: %+v", st)
	}
}
