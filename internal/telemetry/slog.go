package telemetry

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// LogHandler adds trace_id and span_id to a record whose context carries a span (logged with
// InfoContext and friends), so a log line leads to its trace and a trace to its lines. A
// record logged without a context, or outside a span, is passed on as it is.
type LogHandler struct{ slog.Handler }

// NewLogHandler wraps h.
func NewLogHandler(h slog.Handler) *LogHandler { return &LogHandler{Handler: h} }

func (h *LogHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r = r.Clone()
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return h.Handler.Handle(ctx, r)
}

func (h *LogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &LogHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *LogHandler) WithGroup(name string) slog.Handler {
	return &LogHandler{Handler: h.Handler.WithGroup(name)}
}
