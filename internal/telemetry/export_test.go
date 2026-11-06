package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
)

// tracing.endpoint names the collector; spans reach its /v1/traces (the path the exporter
// would otherwise leave at "/"), and a URL with a path of its own is kept.
func TestStartTracingExportsToTheCollector(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer collector.Close()
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	defer func() { otel.SetTracerProvider(prevTP); otel.SetTextMapPropagator(prevProp) }()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	shutdown, err := StartTracing(t.Context(), TracingConfig{Endpoint: collector.URL, Protocol: "http", SamplerRatio: 1}, "v-test")
	if err != nil {
		t.Fatal(err)
	}
	_, span := Tracer().Start(context.Background(), "op")
	span.End()
	if err := shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown (flush to the collector): %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) == 0 || paths[0] != "POST /v1/traces" {
		t.Fatalf("the collector got %v, want POST /v1/traces", paths)
	}
	for in, want := range map[string]string{
		"http://tempo:4318":              "http://tempo:4318/v1/traces",
		"http://tempo:4318/":             "http://tempo:4318/v1/traces",
		"https://otel.example/custom/v1": "https://otel.example/custom/v1",
	} {
		if got := HTTPTracesURL(in); got != want {
			t.Errorf("HTTPTracesURL(%q) = %q, want %q", in, got, want)
		}
	}
}
