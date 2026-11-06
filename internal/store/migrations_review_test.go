package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The schema file is a list of steps numbered 1..N in order; a malformed one fails to parse
// rather than skipping or reordering steps.
func TestMigrationStepsAreOrdered(t *testing.T) {
	steps, always, err := parseMigrations(migrations)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(always, "UPDATE git_syncs") || strings.Contains(strings.ToUpper(always), "ALTER TABLE") || strings.Contains(strings.ToUpper(always), "CREATE ") {
		t.Fatalf("every-start section must hold the row repairs and no DDL:\n%s", always)
	}
	if len(steps) < 7 {
		t.Fatalf("%d steps, want at least the 7 of the baseline", len(steps))
	}
	for i, st := range steps {
		if st.version != i+1 || st.name == "" || st.sql == "" {
			t.Fatalf("step %d: %+v", i+1, st)
		}
	}
	for _, bad := range []string{
		"CREATE TABLE x ();",
		"-- step 1: a\nSELECT 1;\n-- step 3: c\nSELECT 1;",
		"-- step 1: a\nSELECT 1;\n-- step 1: again\nSELECT 1;",
		"-- step 1: a\nSELECT 1;\n-- every start: r\nSELECT 1;\n-- step 2: late\nSELECT 1;",
	} {
		if _, _, err := parseMigrations(bad); err == nil {
			t.Errorf("parsed %q", bad)
		}
	}
}

// Steps run once each: a fresh database records every step, a restart runs none of them again
// (no ACCESS EXCLUSIVE no-op ALTERs on every start), and a database migrated before the version
// table existed (the 5cdff6d schema) is brought up by running the idempotent baseline steps.
func TestPostgresMigrationsApplyOnce(t *testing.T) {
	steps, _, err := parseMigrations(migrations)
	if err != nil {
		t.Fatal(err)
	}
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "upgrade_from_5cdff6d"}[upgrade], func(t *testing.T) {
			dsn := reviewPostgresURL(t, upgrade)
			ctx := context.Background()
			p := reviewOpenPostgres(t, dsn)
			applied := func() map[int]time.Time {
				rows, err := p.pool.Query(ctx, `SELECT version, applied_at FROM schema_migrations`)
				if err != nil {
					t.Fatal(err)
				}
				defer rows.Close()
				out := map[int]time.Time{}
				for rows.Next() {
					var v int
					var at time.Time
					if err := rows.Scan(&v, &at); err != nil {
						t.Fatal(err)
					}
					out[v] = at
				}
				return out
			}
			first := applied()
			if len(first) != len(steps) {
				t.Fatalf("%d steps recorded, want %d", len(first), len(steps))
			}
			if err := migrate(ctx, p.pool); err != nil {
				t.Fatal(err)
			}
			second := applied()
			for v, at := range first {
				if !second[v].Equal(at) {
					t.Fatalf("step %d ran again", v)
				}
			}
			// A step this binary does not know (written by a newer release) does not stop it.
			if _, err := p.pool.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES (9999, 'from the future')`); err != nil {
				t.Fatal(err)
			}
			if err := migrate(ctx, p.pool); err != nil {
				t.Fatalf("migrate next to a newer step: %v", err)
			}
		})
	}
}
