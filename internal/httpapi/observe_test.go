package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/trace"

	"agent-sandbox/internal/telemetry"
	"agent-sandbox/internal/telemetry/telemetrytest"
)

// A request through the platform listener is a span named after the route pattern and a
// metrics sample under the pattern; the sandbox id in its path appears in neither.
func TestObservedRequestIsNamedAndCountedByRoute(t *testing.T) {
	sr := telemetrytest.Record(t)
	p := newRound2Pod(t) // the listeners are built after the recorder is installed
	counter := telemetry.HTTPRequests.WithLabelValues("api", "/v1/sandboxes/{id}", "GET", "200")
	before := testutil.ToFloat64(counter)
	resp, body := call(t, "GET", p.s.platform.URL+"/v1/sandboxes/"+p.sb.ID, "t0k", nil, map[string]string{"X-Request-Id": "rid-observed-1"})
	if resp.StatusCode != 200 {
		t.Fatalf("get: %d %s", resp.StatusCode, body)
	}
	if got := testutil.ToFloat64(counter) - before; got != 1 {
		t.Fatalf("sandboxd_http_requests_total{route=/v1/sandboxes/{id}} grew by %v, want 1", got)
	}
	var span trace.SpanContext
	for _, s := range telemetrytest.Named(sr, "GET /v1/sandboxes/{id}") {
		if telemetrytest.Attr(s, "request_id") == "rid-observed-1" {
			span = s.SpanContext()
			if telemetrytest.Attr(s, "http.route") != "/v1/sandboxes/{id}" || s.SpanKind() != trace.SpanKindServer {
				t.Fatalf("server span: kind %v route %q", s.SpanKind(), telemetrytest.Attr(s, "http.route"))
			}
		}
	}
	if !span.IsValid() {
		t.Fatalf("no server span named after the route carries the request id: %v", spanNames(sr.Ended()))
	}
	for _, s := range sr.Ended() {
		if strings.Contains(s.Name(), p.sb.ID) {
			t.Fatalf("a span name carries the sandbox id: %q", s.Name())
		}
	}
	mfs, err := telemetry.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if strings.Contains(l.GetValue(), p.sb.ID) {
					t.Fatalf("%s has a label value with the sandbox id: %s=%s", mf.GetName(), l.GetName(), l.GetValue())
				}
			}
		}
	}
	// A path no route matches is counted as unmatched, not under its path.
	unmatched := telemetry.HTTPRequests.WithLabelValues("api", telemetry.Unmatched, "GET", "404")
	before = testutil.ToFloat64(unmatched)
	if resp, _ := call(t, "GET", p.s.platform.URL+"/v1/no-such/"+p.sb.ID, "t0k", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("unmatched: %d", resp.StatusCode)
	}
	if testutil.ToFloat64(unmatched)-before != 1 {
		t.Fatal("a 404 is not counted under route=unmatched")
	}
}

// The gateway takes up the runner's traceparent: its span for a call about a run is a child of
// the run's span, in the run's trace, and carries the run and sandbox ids, as does the
// orchestrator's span under it.
func TestGatewaySpanJoinsTheRunnersTrace(t *testing.T) {
	sr := telemetrytest.Record(t)
	p := newRound2Pod(t)
	if code, run := p.next(t); code != 200 || run["id"] != p.runID {
		t.Fatalf("next: %d %v", code, run)
	}
	runSpan := trace.NewSpanContext(trace.SpanContextConfig{TraceID: trace.TraceID{0xab, 1}, SpanID: trace.SpanID{0xcd, 2}, TraceFlags: trace.FlagsSampled})
	traceparent := "00-" + runSpan.TraceID().String() + "-" + runSpan.SpanID().String() + "-01"
	if code, body := p.post(t, "b1", "hello\n", "traceparent", traceparent); code >= 300 {
		t.Fatalf("events: %d %s", code, body)
	}
	servers := telemetrytest.Named(sr, "POST /agent/runs/{run}/events")
	if len(servers) != 1 {
		t.Fatalf("gateway spans for the events call: %d (%v)", len(servers), spanNames(sr.Ended()))
	}
	s := servers[0]
	if s.SpanContext().TraceID() != runSpan.TraceID() || s.Parent().SpanID() != runSpan.SpanID() {
		t.Fatalf("the gateway span is not in the run's trace: trace %s parent %s", s.SpanContext().TraceID(), s.Parent().SpanID())
	}
	if telemetrytest.Attr(s, "run_id") != p.runID || telemetrytest.Attr(s, "sandbox_id") != p.sb.ID {
		t.Fatalf("gateway span attributes: run_id %q sandbox_id %q", telemetrytest.Attr(s, "run_id"), telemetrytest.Attr(s, "sandbox_id"))
	}
	var joined bool
	for _, o := range telemetrytest.Named(sr, "orchestrator.Output") {
		if o.SpanContext().TraceID() == runSpan.TraceID() && telemetrytest.Attr(o, "run_id") == p.runID {
			joined = true
		}
	}
	if !joined {
		t.Fatalf("no orchestrator.Output span in the run's trace: %v", spanNames(sr.Ended()))
	}
}

// The request log line is written with the request's context: under the server span it
// carries trace_id and span_id next to the request id.
func TestRequestLogCarriesTheTraceID(t *testing.T) {
	sr := telemetrytest.Record(t)
	var buf bytes.Buffer
	log := slog.New(telemetry.NewLogHandler(slog.NewJSONHandler(&buf, nil)))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/things/{id}", func(w http.ResponseWriter, r *http.Request) {})
	srv := httptest.NewServer(observed("api", mux, log, mux))
	defer srv.Close()
	resp, _ := call(t, "GET", srv.URL+"/v1/things/t_1", "", nil, map[string]string{"X-Request-Id": "rid-log-1"})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil {
		t.Fatalf("log: %q: %v", buf.String(), err)
	}
	spans := telemetrytest.Named(sr, "GET /v1/things/{id}")
	if len(spans) != 1 {
		t.Fatalf("spans: %v", spanNames(sr.Ended()))
	}
	if line["rid"] != "rid-log-1" || line["trace_id"] != spans[0].SpanContext().TraceID().String() || line["span_id"] != spans[0].SpanContext().SpanID().String() {
		t.Fatalf("the request line does not lead to its span: %v (span %s)", line, spans[0].SpanContext().TraceID())
	}
}

func spanNames[S interface{ Name() string }](spans []S) []string {
	out := make([]string, len(spans))
	for i, s := range spans {
		out[i] = s.Name()
	}
	return out
}
