package httpapi

import (
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"agent-sandbox/internal/telemetry"
)

// observed is how both listeners serve: a server span per request (W3C trace context in from
// the caller, named after the matched route), then the request log and the request metrics
// (logObserved), then next. The route is the mux pattern the request matches, never its
// path: paths carry tenant, sandbox and run ids, which must not become metric series or span
// names. server ("api", "gateway") tells the listeners apart in the metrics.
func observed(server string, mux *http.ServeMux, log *slog.Logger, next http.Handler) http.Handler {
	h := logObserved(log, func(r *http.Request, code int, took time.Duration) {
		route := telemetry.Route(mux, r)
		trace.SpanFromContext(r.Context()).SetAttributes(attribute.String("http.route", route))
		telemetry.ObserveHTTP(server, route, r.Method, code, took)
	}, next)
	return otelhttp.NewHandler(h, server,
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string { return spanName(mux, r) }),
		// The probes are counted, not traced: the kubelet asks every few seconds.
		otelhttp.WithFilter(func(r *http.Request) bool {
			route := telemetry.Route(mux, r)
			return route != "/healthz" && route != "/readyz"
		}),
		// The propagators are the global ones (telemetry.Install); with tracing off there are
		// none, and a caller's traceparent is not taken up.
	)
}

// spanName is "METHOD route" (semantic conventions), the method alone when no route matched.
func spanName(mux *http.ServeMux, r *http.Request) string {
	m := telemetry.Method(r.Method)
	if route := telemetry.Route(mux, r); route != telemetry.Unmatched {
		return m + " " + route
	}
	return m
}

// agentSpan puts the calling sandbox and, on a route about a run, the run's id on the request's
// span: the runner's calls about one run share its trace, and these attributes are how that
// trace is found from a run id.
func agentSpan(r *http.Request, sandboxID string) {
	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(attribute.String("sandbox_id", sandboxID))
	if run := r.PathValue("run"); run != "" {
		span.SetAttributes(attribute.String("run_id", run))
	}
}
