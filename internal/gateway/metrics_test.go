package gateway

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/telemetry"
	"agent-sandbox/internal/telemetry/telemetrytest"
)

// The sync gauge follows the last attempt (0 while Caddy refuses, 1 once it accepts), each
// failure is counted, and the sync is a span whose admin call is a child of it.
func TestSyncStatusGaugeAndFailures(t *testing.T) {
	sr := telemetrytest.Record(t)
	var refuse atomic.Bool
	refuse.Store(true)
	caddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refuse.Load() {
			http.Error(w, `{"error":"no"}`, http.StatusBadRequest)
		}
	}))
	defer caddy.Close()
	c, _ := ca.Generate("t", time.Hour)
	cfg := reviewCfg()
	cfg.CaddyAdmin = caddy.URL
	hosts := &staticHosts{hs: []policy.Host{{Name: "a.example.com", Upstream: "https://a.example.com"}}}
	hosts.fp.Store("v1")
	s := &Syncer{Cfg: cfg, Policies: hosts, AgentCA: c.PEM()}
	status := telemetry.GatewaySyncStatus.WithLabelValues()
	failures := testutil.ToFloat64(telemetry.GatewaySyncFailures)
	if err := s.SyncOnce(t.Context(), true); err == nil {
		t.Fatal("caddy refused, the sync succeeded")
	}
	if testutil.ToFloat64(status) != 0 || testutil.ToFloat64(telemetry.GatewaySyncFailures)-failures != 1 {
		t.Fatalf("after a refusal: status %v, failures +%v", testutil.ToFloat64(status), testutil.ToFloat64(telemetry.GatewaySyncFailures)-failures)
	}
	refuse.Store(false)
	if err := s.SyncOnce(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(status) != 1 {
		t.Fatal("after a sync Caddy accepted the gauge is not 1")
	}
	syncs := telemetrytest.Named(sr, "gateway.Sync")
	if len(syncs) != 2 {
		t.Fatalf("sync spans: %d", len(syncs))
	}
	var admin int
	for _, sp := range sr.Ended() {
		if sp.Parent().SpanID() == syncs[1].SpanContext().SpanID() {
			admin++
		}
	}
	if admin != 1 {
		t.Fatalf("admin calls under the sync span: %d", admin)
	}
}
