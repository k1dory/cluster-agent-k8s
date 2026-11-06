package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// A record logged with the context of a span carries its trace_id and span_id; one without a
// span (or without a context) is passed on unchanged.
func TestLogHandlerAddsTraceIDs(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewLogHandler(slog.NewJSONHandler(&buf, nil))).With("log", "api")
	tp := sdktrace.NewTracerProvider()
	ctx, span := tp.Tracer("t").Start(context.Background(), "op")
	log.InfoContext(ctx, "inside", "rid", "r1")
	span.End()
	log.InfoContext(context.Background(), "outside")
	log.Info("no context")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines: %q", lines)
	}
	var in map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &in)
	sc := span.SpanContext()
	if in["trace_id"] != sc.TraceID().String() || in["span_id"] != sc.SpanID().String() || in["rid"] != "r1" || in["log"] != "api" {
		t.Fatalf("the line inside the span: %s (span %s/%s)", lines[0], sc.TraceID(), sc.SpanID())
	}
	for _, l := range lines[1:] {
		if strings.Contains(l, "trace_id") || strings.Contains(l, "span_id") {
			t.Fatalf("a line outside any span carries trace ids: %s", l)
		}
	}
}

// Every family the operator docs list is on the registry, with labels that cannot carry an id.
func TestRegistryHasTheFamilies(t *testing.T) {
	SetBuild("v-test")
	ObserveHTTP("api", "/v1/sandboxes/{id}", "GET", 200, time.Millisecond)
	StoreQueryDuration.WithLabelValues("select sandboxes").Observe(0.001)
	StoreQueryErrors.WithLabelValues("select sandboxes").Inc()
	KubeRequests.WithLabelValues("get", "200").Inc()
	KubeDuration.WithLabelValues("get").Observe(0.01)
	GatewaySyncStatus.WithLabelValues().Set(1)
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewStateCollector(func(context.Context) (StateCounts, error) {
		return StateCounts{Sandboxes: map[string]int{"running": 2}, Runs: map[string]int{"queued": 3, "running": 1}}, nil
	}, time.Minute))
	got := map[string][]string{}
	for _, g := range []prometheus.Gatherer{Registry, reg} {
		mfs, err := g.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, mf := range mfs {
			var labels []string
			for _, m := range mf.GetMetric() {
				for _, l := range m.GetLabel() {
					if !slices.Contains(labels, l.GetName()) {
						labels = append(labels, l.GetName())
					}
				}
			}
			got[mf.GetName()] = labels
		}
	}
	for _, want := range []string{
		"sandboxd_http_requests_total", "sandboxd_http_request_duration_seconds",
		"sandboxd_store_query_duration_seconds", "sandboxd_store_query_errors_total",
		"sandboxd_sandboxes", "sandboxd_runs", "sandboxd_run_queue_depth",
		"sandboxd_reconcile_duration_seconds", "sandboxd_reconcile_errors_total",
		"sandboxd_kube_requests_total", "sandboxd_kube_request_duration_seconds",
		"sandboxd_gateway_sync_status", "sandboxd_gateway_sync_failures_total",
		"sandboxd_events_hub_dropped_total", "sandboxd_idempotency_takeovers_total", "sandboxd_auth_rate_limited_total",
		"sandboxd_build_info", "go_goroutines", "process_start_time_seconds",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("family %s is not exported", want)
		}
	}
	allowed := []string{"server", "route", "method", "code", "op", "verb", "status", "version", "go_version"}
	for name, labels := range got {
		if !strings.HasPrefix(name, "sandboxd_") {
			continue
		}
		for _, l := range labels {
			if !slices.Contains(allowed, l) {
				t.Errorf("%s has label %q: labels are bounded sets, never ids", name, l)
			}
		}
	}
}

// The route label is the pattern a request matched, never its path, and a request no
// pattern matches is "unmatched"; a made-up method is OTHER.
func TestRouteIsThePatternNotThePath(t *testing.T) {
	mux := http.NewServeMux()
	ok := func(http.ResponseWriter, *http.Request) {}
	mux.HandleFunc("GET /v1/sandboxes/{id}", ok)
	mux.HandleFunc("GET /agent/blobs/{name...}", ok)
	mux.HandleFunc("/", ok)
	for path, want := range map[string]string{
		"/v1/sandboxes/sb_123":  "/v1/sandboxes/{id}",
		"/agent/blobs/a/b/c":    "/agent/blobs/{name...}",
		"/tenant-acme/anything": "/",
	} {
		if got := Route(mux, httptest.NewRequest("GET", path, nil)); got != want {
			t.Errorf("%s: route %q, want %q", path, got, want)
		}
	}
	only := http.NewServeMux()
	only.HandleFunc("GET /v1/x", ok)
	if got := Route(only, httptest.NewRequest("GET", "/v1/sb_secret", nil)); got != Unmatched {
		t.Errorf("unmatched path: %q", got)
	}
	if Method("BREW") != "OTHER" || Method("PATCH") != "PATCH" {
		t.Error("method label is not bounded")
	}
}

// A sampled traceparent from the wire does not force a trace to be kept: at ratio 0 nothing
// is, whatever the caller says; a span under a local parent follows it.
func TestSamplerDoesNotTrustTheCallersFlag(t *testing.T) {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(Sampler(0)))
	remote := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{1}, SpanID: trace.SpanID{1}, TraceFlags: trace.FlagsSampled, Remote: true})
	_, span := tp.Tracer("t").Start(trace.ContextWithRemoteSpanContext(context.Background(), remote), "server")
	if span.SpanContext().IsSampled() {
		t.Fatal("ratio 0 kept a trace because the caller's traceparent said sampled")
	}
	all := sdktrace.NewTracerProvider(sdktrace.WithSampler(Sampler(1)))
	ctx, parent := all.Tracer("t").Start(context.Background(), "root")
	_, child := all.Tracer("t").Start(ctx, "child")
	if !parent.SpanContext().IsSampled() || !child.SpanContext().IsSampled() || child.SpanContext().TraceID() != parent.SpanContext().TraceID() {
		t.Fatal("ratio 1: the local child does not follow its parent")
	}
}

// The state gauges cost one read per interval however often they are scraped, and a failed
// read reports nothing rather than stale numbers.
func TestStateCollectorReadsOncePerInterval(t *testing.T) {
	var reads atomic.Int32
	fail := atomic.Bool{}
	c := NewStateCollector(func(context.Context) (StateCounts, error) {
		reads.Add(1)
		if fail.Load() {
			return StateCounts{}, errors.New("db down")
		}
		return StateCounts{Sandboxes: map[string]int{"running": 2, "sleeping": 0}, Runs: map[string]int{"queued": 3, "running": 1}}, nil
	}, time.Hour).(*stateCollector)
	for range 5 {
		if n := testutil.CollectAndCount(c); n != 5 { // 2 sandboxes + 2 runs + queue depth
			t.Fatalf("samples: %d", n)
		}
	}
	if reads.Load() != 1 {
		t.Fatalf("five scrapes read the store %d times", reads.Load())
	}
	want := "# HELP sandboxd_run_queue_depth Runs queued and not yet handed to an agent.\n# TYPE sandboxd_run_queue_depth gauge\nsandboxd_run_queue_depth 3\n"
	if err := testutil.CollectAndCompare(c, strings.NewReader(want), "sandboxd_run_queue_depth"); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	c.mu.Lock()
	c.at = time.Time{} // the interval is over
	c.mu.Unlock()
	if n := testutil.CollectAndCount(c); n != 0 {
		t.Fatalf("a failed read reported %d samples", n)
	}
}
