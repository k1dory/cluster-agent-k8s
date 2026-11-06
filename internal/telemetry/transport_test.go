package telemetry_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"agent-sandbox/internal/telemetry"
	"agent-sandbox/internal/telemetry/telemetrytest"
)

// A third party's call is a span with method, host and status only: no URL (a key in its
// query, a token in its path) and no trace context sent to it. A peer's call carries the
// trace context on. Outside any trace neither makes a span.
func TestTransportKeepsThirdPartyURLsOutOfSpans(t *testing.T) {
	sr := telemetrytest.Record(t)
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer srv.Close()
	ctx, parent := telemetry.Tracer().Start(t.Context(), "request")
	do := func(rt http.RoundTripper, path string) {
		req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+path, nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	do(telemetry.Transport(nil, false), "/bot123:SECRET/send?key=SECRET")
	if got.Get("traceparent") != "" {
		t.Fatal("a third party was sent our trace context")
	}
	do(telemetry.Transport(nil, true), "/api/v1/pods")
	if got.Get("traceparent") == "" {
		t.Fatal("a peer was not sent the trace context")
	}
	parent.End()
	spans := telemetrytest.Named(sr, "HTTP GET")
	if len(spans) != 2 {
		t.Fatalf("client spans: %d", len(spans))
	}
	third := spans[0]
	for _, a := range third.Attributes() {
		if strings.Contains(a.Value.Emit(), "SECRET") {
			t.Fatalf("the third party's URL is on its span: %s=%s", a.Key, a.Value.Emit())
		}
	}
	if telemetrytest.Attr(third, "http.response.status_code") != "200" || telemetrytest.Attr(third, "server.address") != "127.0.0.1" {
		t.Fatalf("third-party span attributes: %v", third.Attributes())
	}
	n := len(sr.Ended())
	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := telemetry.Transport(nil, false).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(sr.Ended()) != n {
		t.Fatal("a call outside any trace made a span")
	}
}
