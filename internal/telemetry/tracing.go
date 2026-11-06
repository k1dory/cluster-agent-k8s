package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TracerName is the instrumentation scope of sandboxd's own spans.
const TracerName = "agent-sandbox/sandboxd"

// Tracer is sandboxd's tracer, from the global provider: a no-op until StartTracing installs
// a real one, so instrumented code costs next to nothing with tracing off.
func Tracer() trace.Tracer { return otel.Tracer(TracerName) }

// TracingConfig is the tracing: block of sandboxd.yaml (see internal/config).
type TracingConfig struct {
	// Endpoint is the OTLP collector URL (http://tempo:4318, http://collector:4317). Empty:
	// the exporter's own OTEL_EXPORTER_OTLP_(TRACES_)ENDPOINT, else its default (localhost).
	Endpoint string
	// Protocol is http (OTLP/HTTP protobuf) or grpc. Empty: OTEL_EXPORTER_OTLP_(TRACES_)PROTOCOL,
	// else http.
	Protocol string
	// SamplerRatio is the share of new traces kept, 0..1.
	SamplerRatio float64
}

// Sampler keeps ratio of the traces that start here and follows the decision of a parent in
// this process. A parent from the wire (a client's or an agent's traceparent) does not decide
// alone: the agent pod is not trusted, and sampled=1 on every request would force every trace
// to be kept. Its trace id is sampled with the same ratio instead, which keeps the decision
// the same for every request of one trace (a run's calls all land in it or none do).
func Sampler(ratio float64) sdktrace.Sampler {
	r := sdktrace.TraceIDRatioBased(ratio)
	return sdktrace.ParentBased(r, sdktrace.WithRemoteParentSampled(r), sdktrace.WithRemoteParentNotSampled(r))
}

// Protocol resolves the exporter protocol: the configured one, else the standard environment
// variables, else http.
func Protocol(configured string) string {
	for _, p := range []string{configured, os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"), os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")} {
		switch {
		case p == "":
			continue
		case p == "grpc":
			return "grpc"
		case strings.HasPrefix(p, "http"): // http, http/protobuf
			return "http"
		}
	}
	return "http"
}

// HTTPTracesURL is the OTLP/HTTP URL spans are posted to: the configured one when it names a
// path, else the collector's standard /v1/traces under it. The exporter takes a URL as given
// and would post to "/" of a bare http://tempo:4318, which no collector answers.
func HTTPTracesURL(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || strings.Trim(u.Path, "/") != "" {
		return endpoint
	}
	u.Path = "/v1/traces"
	return u.String()
}

// StartTracing installs the global tracer provider and the W3C propagators (traceparent and
// baggage) and returns the function that flushes and stops it.
func StartTracing(ctx context.Context, cfg TracingConfig, version string) (shutdown func(context.Context) error, err error) {
	var exp *otlptrace.Exporter
	switch Protocol(cfg.Protocol) {
	case "grpc":
		var opts []otlptracegrpc.Option
		if cfg.Endpoint != "" {
			opts = append(opts, otlptracegrpc.WithEndpointURL(cfg.Endpoint))
		}
		exp, err = otlptracegrpc.New(ctx, opts...)
	default:
		var opts []otlptracehttp.Option
		if cfg.Endpoint != "" {
			opts = append(opts, otlptracehttp.WithEndpointURL(HTTPTracesURL(cfg.Endpoint)))
		}
		exp, err = otlptracehttp.New(ctx, opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("tracing exporter: %w", err)
	}
	res, err := Resource(ctx, version)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res), sdktrace.WithSampler(Sampler(cfg.SamplerRatio)))
	Install(tp)
	return tp.Shutdown, nil
}

// Install makes tp the global tracer provider and sets the W3C propagators (tests install an
// in-memory one).
func Install(tp trace.TracerProvider) {
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
}

// Resource describes this process: service.name sandboxd, its version, and the pod it runs
// in when the downward API tells (POD_NAME, POD_NAMESPACE). OTEL_SERVICE_NAME and
// OTEL_RESOURCE_ATTRIBUTES override.
func Resource(ctx context.Context, version string) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{attribute.String("service.name", "sandboxd"), attribute.String("service.version", version)}
	if pod := os.Getenv("POD_NAME"); pod != "" {
		attrs = append(attrs, attribute.String("k8s.pod.name", pod))
	} else if h, err := os.Hostname(); err == nil {
		attrs = append(attrs, attribute.String("host.name", h))
	}
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		attrs = append(attrs, attribute.String("k8s.namespace.name", ns))
	}
	res, err := resource.New(ctx, resource.WithAttributes(attrs...), resource.WithTelemetrySDK(), resource.WithFromEnv())
	if err != nil && !errors.Is(err, resource.ErrPartialResource) {
		return nil, fmt.Errorf("tracing resource: %w", err)
	}
	return res, nil
}

// Transport wraps base (nil: http.DefaultTransport) with a client span per request made
// under a span of ours (a request, an orchestrator operation, a reconciler pass); a call from
// a background loop with no trace to join goes straight to base rather than start a trace of
// its own every few seconds.
//
// peer says who is called. A peer of ours (the Kubernetes API, Caddy) gets the full client
// span (otelhttp: the URL, the trace context sent on, so it can join). A third party (Git
// providers, IdPs, OAuth providers, Vault, Infisical, MCP upstreams) gets a span with the
// method, host and status only and no trace context: their URLs can carry what is not ours
// to export (a key in a query, a token in a path), and our trace ids are of no use to them.
func Transport(base http.RoundTripper, peer bool) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if t, ok := base.(*joinTransport); ok {
		base = t.base // wrapped once
	}
	var traced http.RoundTripper = &opaqueTransport{base: base}
	if peer {
		traced = otelhttp.NewTransport(base, otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string { return "HTTP " + Method(r.Method) }))
	}
	return &joinTransport{base: base, traced: traced}
}

type joinTransport struct{ base, traced http.RoundTripper }

func (t *joinTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if trace.SpanContextFromContext(r.Context()).IsValid() {
		return t.traced.RoundTrip(r)
	}
	return t.base.RoundTrip(r)
}

// opaqueTransport is the third-party client span: no URL, no headers, nothing sent on. It
// ends when the response headers arrive.
type opaqueTransport struct{ base http.RoundTripper }

func (t *opaqueTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	_, span := Tracer().Start(r.Context(), "HTTP "+Method(r.Method), trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("http.request.method", Method(r.Method)), attribute.String("server.address", r.URL.Hostname())))
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return resp, End(span, err)
	}
	span.SetAttributes(attribute.Int("http.response.status_code", resp.StatusCode))
	if resp.StatusCode >= 500 {
		span.SetStatus(codes.Error, resp.Status)
	}
	span.End()
	return resp, nil
}

// End ends span, recording err (nil: success) as its status. Returns err for the caller's return.
func End(span trace.Span, err error) error {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
	return err
}
