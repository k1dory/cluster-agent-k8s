package store

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"agent-sandbox/internal/telemetry"
)

// PostgresOption tunes OpenPostgres.
type PostgresOption func(*pgTracer)

// WithStatements records each query's SQL text on its span (db.statement). Off by default:
// the text names no values (they are bind parameters), but a statement built with an
// identifier or a literal in it would carry that into the tracing backend.
func WithStatements(on bool) PostgresOption { return func(t *pgTracer) { t.statements = on } }

// pgTracer is the pool's pgx tracer: a client span per query, its duration and failures in
// the store metrics under a bounded operation name (pgOp). Observation only: it never changes
// a query or its result.
type pgTracer struct {
	statements bool
}

type pgSpanKey struct{}

type pgSpan struct {
	span  trace.Span
	op    string
	start time.Time
}

// start opens the query's span only under a span of the caller's (a request, an orchestrator
// operation): the background loops (leases, listeners, pollers) query every few seconds, and a
// root trace for each would bury the traces worth reading. The metrics count every query.
func (t *pgTracer) start(ctx context.Context, name, op, sql string) context.Context {
	s := &pgSpan{op: op, start: time.Now()}
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return context.WithValue(ctx, pgSpanKey{}, s)
	}
	attrs := []attribute.KeyValue{attribute.String("db.system", "postgresql"), attribute.String("db.operation", op)}
	if t.statements && sql != "" {
		attrs = append(attrs, attribute.String("db.statement", sql))
	}
	ctx, s.span = telemetry.Tracer().Start(ctx, name, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attrs...))
	return context.WithValue(ctx, pgSpanKey{}, s)
}

func (t *pgTracer) end(ctx context.Context, err error) {
	s, ok := ctx.Value(pgSpanKey{}).(*pgSpan)
	if !ok {
		return
	}
	telemetry.StoreQueryDuration.WithLabelValues(s.op).Observe(time.Since(s.start).Seconds())
	if failed(err) {
		telemetry.StoreQueryErrors.WithLabelValues(s.op).Inc()
	}
	if s.span == nil {
		return
	}
	if failed(err) {
		s.span.RecordError(err)
		s.span.SetStatus(codes.Error, err.Error())
	}
	s.span.End()
}

// failed: an error that is the query's, not "no row" (an answer) or the caller giving up.
func failed(err error) bool {
	return err != nil && !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, context.Canceled)
}

func (t *pgTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	op := pgOp(d.SQL)
	return t.start(ctx, "postgres "+op, op, d.SQL)
}

func (t *pgTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	t.end(ctx, d.Err)
}

// A batch is one round trip: one span and one sample under op "batch"; a query of it that
// fails counts under its own operation too.
func (t *pgTracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceBatchStartData) context.Context {
	return t.start(ctx, "postgres batch", "batch", "")
}

func (t *pgTracer) TraceBatchQuery(_ context.Context, _ *pgx.Conn, d pgx.TraceBatchQueryData) {
	if failed(d.Err) {
		telemetry.StoreQueryErrors.WithLabelValues(pgOp(d.SQL)).Inc()
	}
}

func (t *pgTracer) TraceBatchEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceBatchEndData) {
	t.end(ctx, d.Err)
}

// pgTables are the tables of migrations.sql: the only names an operation label may carry.
var pgTables = func() map[string]bool {
	m := map[string]bool{}
	for _, g := range regexp.MustCompile(`(?i)CREATE TABLE IF NOT EXISTS ([a-z_]+)`).FindAllStringSubmatch(migrations, -1) {
		m[strings.ToLower(g[1])] = true
	}
	return m
}()

var pgVerbs = map[string]bool{"select": true, "insert": true, "update": true, "delete": true, "with": true,
	"begin": true, "commit": true, "rollback": true, "listen": true, "unlisten": true, "notify": true}

var (
	pgTableRe = regexp.MustCompile(`(?i)\b(?:from|into|update|join)\s+([a-z_]+)`)
	pgWordRe  = regexp.MustCompile(`^[A-Za-z]+`)
)

// pgOp names a query for the metrics: its verb and the first schema table it names
// ("select sandboxes", "update runs"), "select" for one that names none (a function, a lock),
// "other" for a verb outside the usual ones. Built only from fixed sets, so the label has
// at most verbs × tables values whatever SQL reaches the pool.
func pgOp(sql string) string {
	verb := strings.ToLower(pgWordRe.FindString(strings.TrimLeft(sql, " \t\r\n(")))
	if !pgVerbs[verb] {
		return "other"
	}
	for _, m := range pgTableRe.FindAllStringSubmatch(sql, -1) {
		if tbl := strings.ToLower(m[1]); pgTables[tbl] {
			return verb + " " + tbl
		}
	}
	return verb
}
