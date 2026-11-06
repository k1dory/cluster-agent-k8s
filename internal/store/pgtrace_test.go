package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/telemetry"
	"agent-sandbox/internal/telemetry/telemetrytest"
)

// The operation label is a verb and a table from the schema, whatever the SQL: no literal,
// identifier or comment of a query can widen it.
func TestPgOpIsBounded(t *testing.T) {
	for sql, want := range map[string]string{
		`SELECT id FROM sandboxes WHERE id=$1`:                "select sandboxes",
		"\n\t  UPDATE runs SET status=$2 WHERE id=$1":         "update runs",
		`INSERT INTO events (sandbox_id) VALUES ($1)`:         "insert events",
		`DELETE FROM blobs WHERE name=$1`:                     "delete blobs",
		`WITH x AS (SELECT 1) UPDATE api_keys SET a=1`:        "with api_keys",
		`SELECT pg_try_advisory_lock($1)`:                     "select",
		`SELECT * FROM "sb_1234"`:                             "select",
		`SELECT * FROM tenant_acme_secrets JOIN runs ON true`: "select runs",
		`CREATE TABLE IF NOT EXISTS x (a int)`:                "other",
		`'; DROP TABLE sandboxes; --`:                         "other",
		`select count(*) from git_jobs`:                       "select git_jobs",
		`(SELECT 1 FROM run_output_batches) UNION (SELECT 2)`: "select run_output_batches",
		`LISTEN events`:        "listen",
		`selectfrom sandboxes`: "other",
		`SELECT a FROM sandboxes_with_a_longer_name_nobody_wrote`: "select",
	} {
		if got := pgOp(sql); got != want {
			t.Errorf("pgOp(%q) = %q, want %q", sql, got, want)
		}
	}
	if !pgTables["sandboxes"] || !pgTables["run_output_batches"] || len(pgTables) < 10 {
		t.Fatalf("schema tables: %v", pgTables)
	}
}

// histCount is the number of samples in sandboxd_store_query_duration_seconds{op}.
func histCount(t *testing.T, op string) uint64 {
	t.Helper()
	var m dto.Metric
	if err := telemetry.StoreQueryDuration.WithLabelValues(op).(interface{ Write(*dto.Metric) error }).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetHistogram().GetSampleCount()
}

// On a real database: a query under a span of the caller's is one client span (db.system,
// db.operation, no statement unless asked) and one histogram sample under its operation; a
// query with no span to join is counted but not traced.
func TestPostgresTracerSpanAndSamplePerQuery(t *testing.T) {
	dsn := reviewPostgresURL(t, false)
	sr := telemetrytest.Record(t)
	p := reviewOpenPostgres(t, dsn)
	ctx, parent := telemetry.Tracer().Start(t.Context(), "caller")
	before := histCount(t, "select sandboxes")
	if _, err := p.GetSandbox(ctx, "sb_missing_one"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get: %v", err)
	}
	parent.End()
	if got := histCount(t, "select sandboxes") - before; got != 1 {
		t.Fatalf("histogram samples for one query: %d", got)
	}
	var mine int
	for _, s := range telemetrytest.Named(sr, "postgres select sandboxes") {
		if s.Parent().SpanID() != parent.SpanContext().SpanID() {
			continue
		}
		mine++
		if telemetrytest.Attr(s, "db.system") != "postgresql" || telemetrytest.Attr(s, "db.operation") != "select sandboxes" {
			t.Fatalf("attributes: %v", s.Attributes())
		}
		if telemetrytest.Has(s, "db.statement") {
			t.Fatal("the statement is recorded without record_statements")
		}
		if s.Status().Code != 0 {
			t.Fatalf("no row is an answer, not a failed query: %v", s.Status())
		}
	}
	if mine != 1 {
		t.Fatalf("spans under the caller for one query: %d (%v)", mine, sr.Ended())
	}

	// No span to join: counted, not traced.
	n := len(sr.Ended())
	before = histCount(t, "select sandboxes")
	_, _ = p.GetSandbox(context.Background(), "sb_missing_two")
	if histCount(t, "select sandboxes")-before != 1 || len(sr.Ended()) != n {
		t.Fatalf("a query outside any trace: %d new spans", len(sr.Ended())-n)
	}

	// With statements on, the SQL goes on the span.
	ctx2, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	ps, err := OpenPostgres(ctx2, dsn, WithStatements(true))
	if err != nil {
		t.Fatal(err)
	}
	defer ps.Close()
	ctx, parent = telemetry.Tracer().Start(t.Context(), "caller-statements")
	_, _ = ps.GetSandbox(ctx, "sb_missing_three")
	parent.End()
	var stmt string
	for _, s := range telemetrytest.Named(sr, "postgres select sandboxes") {
		if s.Parent().SpanID() == parent.SpanContext().SpanID() {
			stmt = telemetrytest.Attr(s, "db.statement")
		}
	}
	if !strings.Contains(strings.ToLower(stmt), "from sandboxes") || strings.Contains(stmt, "sb_missing_three") {
		t.Fatalf("db.statement with record_statements: %q (the SQL, never the arguments)", stmt)
	}
}

// CountByStatus on both stores: every sandbox status with zeros, and only the unfinished runs.
func TestCountByStatusContract(t *testing.T) {
	run := func(t *testing.T, st Store) {
		ctx := t.Context()
		sc, ok := st.(StatusCounter)
		if !ok {
			t.Fatal("the store does not count by status")
		}
		sbs, runs, err := sc.CountByStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		base := map[string]int{}
		for k, v := range sbs {
			base["sb "+k] = v
		}
		for k, v := range runs {
			base["run "+k] = v
		}
		if _, ok := sbs["error"]; !ok || len(runs) != 2 {
			t.Fatalf("zeros missing: %v %v", sbs, runs)
		}
		suffix := time.Now().Format("150405.000000")
		for i, status := range []model.SandboxStatus{model.StatusRunning, model.StatusRunning, model.StatusSleeping} {
			sb := &model.Sandbox{ID: "sb_cnt_" + suffix + string(rune('a'+i)), Name: "c" + string(rune('a'+i)), Slug: "s", Owner: "o", Tenant: "t-count", Status: status, CreatedAt: time.Now(), LastActivity: time.Now()}
			if err := st.CreateSandbox(ctx, sb); err != nil {
				t.Fatal(err)
			}
			for j, rs := range []model.RunStatus{model.RunQueued, model.RunDone, model.RunFailed} {
				r := &model.Run{ID: sb.ID + "_r" + string(rune('0'+j)), SandboxID: sb.ID, Tenant: sb.Tenant, Slug: sb.Slug, Task: "x", Status: rs, CreatedAt: time.Now()}
				if err := st.CreateRun(ctx, r); err != nil {
					t.Fatal(err)
				}
			}
		}
		sbs, runs, err = sc.CountByStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if sbs["running"]-base["sb running"] != 2 || sbs["sleeping"]-base["sb sleeping"] != 1 || runs["queued"]-base["run queued"] != 3 || runs["running"] != base["run running"] {
			t.Fatalf("counts: %v %v (before %v)", sbs, runs, base)
		}
		if _, ok := runs["done"]; ok {
			t.Fatalf("finished runs are counted: %v", runs)
		}
	}
	t.Run("memory", func(t *testing.T) { run(t, NewMemory()) })
	t.Run("postgres", func(t *testing.T) { run(t, reviewOpenPostgres(t, reviewPostgresURL(t, false))) })
}
