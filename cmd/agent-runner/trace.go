package main

import (
	"crypto/rand"
	"net/http"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Each run is one trace. The runner opens the run's span (its identity: a new trace id and
// span id, sampled) when it takes the run, and every call it makes about the run carries it
// as a W3C traceparent, so the control plane's spans for the run's output, input polls and
// finish (which carry the run_id) join one trace instead of one each. The span is not
// exported from here: the pod's egress reaches the gateway only, never a collector, and the
// control plane records the run id on its side of every call. Whether the trace is kept is
// the control plane's choice (its sampler decides on the trace id, not on this flag).
func newRunTrace() trace.SpanContext {
	var tid trace.TraceID
	var sid trace.SpanID
	_, _ = rand.Read(tid[:])
	_, _ = rand.Read(sid[:])
	return trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
}

// injectTrace sets traceparent on req for the run's span.
func injectTrace(req *http.Request, sc trace.SpanContext) {
	propagation.TraceContext{}.Inject(trace.ContextWithSpanContext(req.Context(), sc), propagation.HeaderCarrier(req.Header))
}
