// Package telemetry is sandboxd's observation of itself: the Prometheus metrics every package
// records into, the OpenTelemetry tracer provider, and the slog handler that ties a log line to
// its trace.
//
// The metric families live here, in one registry, so the set an operator can scrape is
// written down in one place and a test can hold it. Label values are bounded by construction:
// a route is the mux pattern, never the path; a store operation is a verb and a table from
// the schema; nothing carries a tenant, sandbox, run or key id (those go on spans, which are
// sampled and expire, not on series that live as long as the process).
package telemetry

import (
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Registry holds every sandboxd family plus the Go and process collectors. Not the default
// registry: a library that registers on that one does not end up on /metrics unannounced.
var Registry = prometheus.NewRegistry()

// Buckets for request-shaped latencies: 5ms to 60s. Long polls and SSE streams land in the
// top bucket; their routes say what they are.
var latencyBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60}

// Buckets for queries: 0.5ms to 10s.
var queryBuckets = []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 10}

var (
	// HTTPRequests counts requests per server (api, gateway), route pattern, method and code.
	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sandboxd_http_requests_total", Help: "HTTP requests served, by server, route pattern, method and status code.",
	}, []string{"server", "route", "method", "code"})
	// HTTPDuration is the time to the end of the handler (a stream's whole life).
	HTTPDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "sandboxd_http_request_duration_seconds", Help: "Time spent serving an HTTP request, by server, route pattern and method.",
		Buckets: latencyBuckets,
	}, []string{"server", "route", "method"})

	// StoreQueryDuration and StoreQueryErrors are per store operation (Op).
	StoreQueryDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "sandboxd_store_query_duration_seconds", Help: "Postgres query time, by operation (verb and table).",
		Buckets: queryBuckets,
	}, []string{"op"})
	StoreQueryErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sandboxd_store_query_errors_total", Help: "Postgres queries that failed, by operation (verb and table).",
	}, []string{"op"})

	// ReconcileDuration and ReconcileErrors: the reconciler's passes on the leading replica.
	ReconcileDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "sandboxd_reconcile_duration_seconds", Help: "Duration of one reconciler pass (on the replica holding the lease).",
		Buckets: latencyBuckets,
	})
	ReconcileErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sandboxd_reconcile_errors_total", Help: "Reconciler passes that could not list the sandboxes.",
	})

	// KubeRequests and KubeDuration: calls to the Kubernetes API, by verb and code.
	KubeRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sandboxd_kube_requests_total", Help: "Kubernetes API requests, by verb and status code (\"error\": no response).",
	}, []string{"verb", "code"})
	KubeDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "sandboxd_kube_request_duration_seconds", Help: "Kubernetes API request latency, by verb.",
		Buckets: latencyBuckets,
	}, []string{"verb"})

	// GatewaySyncStatus is 1 while the last Caddy sync succeeded, 0 while it fails. A vector
	// without labels so the series appears with the first attempt: a replica that drives no
	// Caddy does not report a gateway that looks broken.
	GatewaySyncStatus = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sandboxd_gateway_sync_status", Help: "1 while the last gateway (Caddy) configuration sync succeeded, 0 while it fails.",
	}, nil)
	GatewaySyncFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sandboxd_gateway_sync_failures_total", Help: "Gateway (Caddy) configuration syncs that failed.",
	})

	EventsHubDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sandboxd_events_hub_dropped_total", Help: "Events the in-process hub dropped for a slow subscriber (it recovers from the store).",
	})
	IdempotencyTakeovers = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sandboxd_idempotency_takeovers_total", Help: "Idempotency-Key reservations taken over from an abandoned or released attempt.",
	})
	AuthRateLimited = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "sandboxd_auth_rate_limited_total", Help: "Requests refused with 429 by the per-address authentication limit.",
	})

	buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "sandboxd_build_info", Help: "Always 1; the labels say which build is running.",
	}, []string{"version", "go_version"})
)

func init() {
	Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		HTTPRequests, HTTPDuration, StoreQueryDuration, StoreQueryErrors,
		ReconcileDuration, ReconcileErrors, KubeRequests, KubeDuration,
		GatewaySyncStatus, GatewaySyncFailures, EventsHubDropped, IdempotencyTakeovers, AuthRateLimited,
		buildInfo,
	)
}

// SetBuild records the running version in sandboxd_build_info.
func SetBuild(version string) {
	buildInfo.Reset()
	buildInfo.WithLabelValues(version, runtime.Version()).Set(1)
}

// Handler serves the registry in the Prometheus exposition format.
func Handler() http.Handler {
	return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{Registry: Registry})
}

// ObserveHTTP records one served request. route must be a pattern (Route), not a path.
func ObserveHTTP(server, route, method string, code int, took time.Duration) {
	m := Method(method)
	HTTPRequests.WithLabelValues(server, route, m, strconv.Itoa(code)).Inc()
	HTTPDuration.WithLabelValues(server, route, m).Observe(took.Seconds())
}

// Method is the label for an HTTP method: one of the standard ones, else OTHER, so a client
// cannot mint series with made-up methods.
func Method(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return m
	}
	return "OTHER"
}

// Unmatched is the route label of a request no pattern matched (404, 405).
const Unmatched = "unmatched"

// Route is the label for r on mux: the matching pattern without its method ("/v1/sandboxes/{id}"),
// or Unmatched. Never the path, which carries tenant and sandbox ids.
func Route(mux *http.ServeMux, r *http.Request) string {
	_, pattern := mux.Handler(r)
	if pattern == "" {
		return Unmatched
	}
	// "GET /v1/x" → "/v1/x"; a pattern without a method ("/") starts with the path.
	if method, path, ok := strings.Cut(pattern, " "); ok && !strings.Contains(method, "/") {
		pattern = path
	}
	return pattern
}
