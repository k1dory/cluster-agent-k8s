// Package telemetrytest installs an in-memory tracer provider for tests.
package telemetrytest

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"agent-sandbox/internal/telemetry"
)

// Record makes an in-memory provider the global one (with the W3C propagators, as
// telemetry.StartTracing does) until the test ends, and returns what it records. Handlers and
// clients that trace must be built after the call. Every span is sampled.
func Record(t testing.TB) *tracetest.SpanRecorder {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr), sdktrace.WithSampler(sdktrace.AlwaysSample()))
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	telemetry.Install(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
		_ = tp.Shutdown(context.Background()) // t.Context() is already done in a cleanup
	})
	return sr
}

// Named returns the ended spans called name.
func Named(sr *tracetest.SpanRecorder, name string) []sdktrace.ReadOnlySpan {
	var out []sdktrace.ReadOnlySpan
	for _, s := range sr.Ended() {
		if s.Name() == name {
			out = append(out, s)
		}
	}
	return out
}

// Attr is the string value of key on s ("" when absent).
func Attr(s sdktrace.ReadOnlySpan, key string) string {
	for _, a := range s.Attributes() {
		if string(a.Key) == key {
			return a.Value.Emit()
		}
	}
	return ""
}

// Has reports whether s carries key.
func Has(s sdktrace.ReadOnlySpan, key string) bool {
	for _, a := range s.Attributes() {
		if string(a.Key) == key {
			return true
		}
	}
	return false
}
