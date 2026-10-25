package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// The GitSync record: one per (tenant, name), two halves written independently, each
// replaced whole and never touching the other; absent until written; the same contract in
// memory and in PostgreSQL.
func TestGitSyncRecordContract(t *testing.T) {
	stores := map[string]Store{"memory": NewMemory()}
	if dsn := postgresDSNForGitSync(t); dsn != "" {
		stores["postgres"] = reviewOpenPostgres(t, dsn)
	}
	for name, st := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if _, err := st.GetGitSync(ctx, "acme", "config"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("before any write: %v", err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			if err := st.RecordGitCheck(ctx, "acme", "config", model.GitCheck{Head: "aaaa", At: now}); err != nil {
				t.Fatal(err)
			}
			got, err := st.GetGitSync(ctx, "acme", "config")
			if err != nil || got.Tenant != "acme" || got.Name != "config" || got.Check == nil || got.Check.Head != "aaaa" || !got.Check.At.Equal(now) || got.Sync != nil || got.UpdatedAt.IsZero() {
				t.Fatalf("after a check: %v %+v", err, got)
			}
			// The sync half arrives; the check half stays as written.
			sync := model.GitSyncResult{Commit: "bbbb", Status: model.GitSyncDone, At: now,
				Bundles: []model.GitSyncBundle{{Path: "bundles/a.yaml", Apply: "apply_1", Status: "done", Changes: 2}, {Path: "bundles/b.yaml", Status: "invalid", Errors: []string{"x", "y"}}}}
			if err := st.RecordGitSync(ctx, "acme", "config", sync); err != nil {
				t.Fatal(err)
			}
			got, err = st.GetGitSync(ctx, "acme", "config")
			if err != nil || got.Check.Head != "aaaa" || got.Sync == nil || got.Sync.Commit != "bbbb" || len(got.Sync.Bundles) != 2 || got.Sync.Bundles[1].Errors[1] != "y" || got.Sync.Bundles[0].Changes != 2 {
				t.Fatalf("after a sync: %v %+v", err, got)
			}
			// A later check (a failed one) replaces the check half whole and leaves the sync
			// half, commit and apply ids included, exactly as it was.
			if err := st.RecordGitCheck(ctx, "acme", "config", model.GitCheck{At: now.Add(time.Minute), Error: "unreachable"}); err != nil {
				t.Fatal(err)
			}
			got, _ = st.GetGitSync(ctx, "acme", "config")
			if got.Check.Head != "" || got.Check.Error != "unreachable" || got.Sync == nil || got.Sync.Commit != "bbbb" || got.Sync.Bundles[0].Apply != "apply_1" {
				t.Fatalf("a check erased the sync half: %+v", got)
			}
			// And a later sync replaces the sync half whole (no stale bundles) and leaves the check.
			if err := st.RecordGitSync(ctx, "acme", "config", model.GitSyncResult{Commit: "cccc", Status: model.GitSyncError, Error: "down", At: now}); err != nil {
				t.Fatal(err)
			}
			got, _ = st.GetGitSync(ctx, "acme", "config")
			if got.Check.Error != "unreachable" || got.Sync.Commit != "cccc" || len(got.Sync.Bundles) != 0 || got.Sync.Error != "down" {
				t.Fatalf("a sync did not replace its half whole, or touched the check: %+v", got)
			}
			// The third half, the webhook, is written on its own too.
			if err := st.RecordGitHook(ctx, "acme", "config", model.GitHook{Provider: "github", Event: "push", Action: "sync", Commit: "cccc", Outcome: "done", At: now}); err != nil {
				t.Fatal(err)
			}
			got, _ = st.GetGitSync(ctx, "acme", "config")
			if got.Hook == nil || got.Hook.Action != "sync" || got.Check.Error != "unreachable" || got.Sync.Commit != "cccc" {
				t.Fatalf("the hook half: %+v", got)
			}
			// The record is a copy: mutating what came back changes nothing stored.
			got.Sync.Commit = "mutated"
			if again, _ := st.GetGitSync(ctx, "acme", "config"); again.Sync.Commit != "cccc" {
				t.Fatal("the stored record was mutated through a returned copy")
			}
			// Scoped by tenant and name; the shared scope is a tenant of its own.
			if _, err := st.GetGitSync(ctx, "other", "config"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("another tenant: %v", err)
			}
			if err := st.RecordGitCheck(ctx, "", "config", model.GitCheck{Head: "dddd", At: now}); err != nil {
				t.Fatal(err)
			}
			if shared, err := st.GetGitSync(ctx, "", "config"); err != nil || shared.Check.Head != "dddd" || shared.Sync != nil {
				t.Fatalf("shared scope: %v %+v", err, shared)
			}
			if own, _ := st.GetGitSync(ctx, "acme", "config"); own.Check.Error != "unreachable" {
				t.Fatal("the shared record replaced the tenant's")
			}
		})
	}
}

func postgresDSNForGitSync(t *testing.T) string {
	t.Helper()
	if os.Getenv("SANDBOX_TEST_POSTGRES_URL") == "" {
		if os.Getenv("SANDBOX_TEST_REQUIRE_EXTERNAL") != "" {
			t.Fatal("SANDBOX_TEST_REQUIRE_EXTERNAL is set but SANDBOX_TEST_POSTGRES_URL is empty")
		}
		return ""
	}
	return reviewPostgresURL(t, false)
}

// Records written before the two halves (PR #25: check and sync fields at the root) are read
// as the two halves, and the migration rewrites them: a half already written in the new form
// (an older replica's flat sync next to a new replica's check) is kept, the other taken from
// the root fields, and nothing is lost.
func TestGitSyncLegacyFlatRecordsAreReadAndMigrated(t *testing.T) {
	dsn := postgresDSNForGitSync(t)
	if dsn == "" {
		t.Skip("PostgreSQL only: the flat form never existed in memory")
	}
	st := reviewOpenPostgres(t, dsn)
	ctx := context.Background()
	flat := `{"tenant":"acme","name":"old","head":"aaaa","checked_at":"2026-10-25T08:00:00Z","commit":"bbbb","bundles":[{"path":"bundles/a.yaml","apply":"apply_1","status":"done","changes":2}],"status":"done","synced_at":"2026-10-25T08:01:00Z","updated_at":"2026-10-25T08:01:00Z"}`
	mixed := `{"tenant":"acme","name":"mixed","commit":"bbbb","bundles":[{"path":"bundles/a.yaml","apply":"apply_1","status":"done"}],"status":"done","synced_at":"2026-10-25T08:01:00Z","check":{"head":"cccc","at":"2026-10-25T09:00:00Z"}}`
	checkOnly := `{"tenant":"acme","name":"checked","head":"","checked_at":"2026-10-25T08:00:00Z","check_error":"unreachable","updated_at":"2026-10-25T08:00:00Z"}`
	for name, doc := range map[string]string{"old": flat, "mixed": mixed, "checked": checkOnly} {
		if _, err := st.pool.Exec(ctx, `INSERT INTO git_syncs (tenant, name, doc) VALUES ('acme', $1, $2::jsonb)`, name, doc); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(when string) {
		t.Helper()
		got, err := st.GetGitSync(ctx, "acme", "old")
		if err != nil || got.Check == nil || got.Check.Head != "aaaa" || got.Sync == nil || got.Sync.Commit != "bbbb" || got.Sync.Status != model.GitSyncDone || len(got.Sync.Bundles) != 1 || got.Sync.Bundles[0].Apply != "apply_1" || got.Sync.Bundles[0].Changes != 2 || got.Sync.At.IsZero() {
			t.Fatalf("%s: flat record: %v %+v", when, err, got)
		}
		got, err = st.GetGitSync(ctx, "acme", "mixed")
		if err != nil || got.Check == nil || got.Check.Head != "cccc" || got.Sync == nil || got.Sync.Commit != "bbbb" || got.Sync.Bundles[0].Apply != "apply_1" {
			t.Fatalf("%s: mixed record (new check next to a flat sync): %v %+v", when, err, got)
		}
		got, err = st.GetGitSync(ctx, "acme", "checked")
		if err != nil || got.Check == nil || got.Check.Error != "unreachable" || got.Sync != nil {
			t.Fatalf("%s: flat check-only record: %v %+v", when, err, got)
		}
	}
	// Read compatibly before any migration touched them (a replica of the new version next to
	// an older one still writing the flat form).
	expect("before the migration")
	// Opening the store runs the migration: the rows are in the two-half form, no root field left.
	st = reviewOpenPostgres(t, dsn)
	var remaining int
	if err := st.pool.QueryRow(ctx, `SELECT count(*) FROM git_syncs WHERE doc ?| array['checked_at','synced_at','head','commit','status','bundles','check_error','tenant','name','updated_at']`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("root fields left after the migration: %d %v", remaining, err)
	}
	expect("after the migration")
	// The halves keep working on a migrated record: a new check leaves the migrated sync.
	if err := st.RecordGitCheck(ctx, "acme", "old", model.GitCheck{Head: "dddd", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetGitSync(ctx, "acme", "old"); got.Check.Head != "dddd" || got.Sync == nil || got.Sync.Bundles[0].Apply != "apply_1" {
		t.Fatalf("a check after the migration: %+v", got)
	}
}

// Webhook jobs: one job per delivery, claimed oldest first by one owner under a lease, taken
// over once the lease lapsed, finished by its holder only; the same contract in memory and in
// PostgreSQL.
func TestGitJobContract(t *testing.T) {
	stores := map[string]Store{"memory": NewMemory()}
	if dsn := postgresDSNForGitSync(t); dsn != "" {
		stores["postgres"] = reviewOpenPostgres(t, dsn)
	}
	for name, st := range stores {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Microsecond)
			if _, err := st.ClaimGitJob(ctx, "one", now, time.Minute); !errors.Is(err, ErrNotFound) {
				t.Fatalf("claim with no job: %v", err)
			}
			a := &model.GitJob{ID: "gitjob_a", Tenant: "acme", Name: "config", Action: "sync", Delivery: "github:d-1", Payload: []byte(`{"after":"aaaa"}`)}
			if err := st.EnqueueGitJob(ctx, a); err != nil || a.Status != model.GitJobPending {
				t.Fatalf("enqueue: %v %+v", err, a)
			}
			time.Sleep(2 * time.Millisecond)
			b := &model.GitJob{ID: "gitjob_b", Tenant: "acme", Name: "config", Action: "plan", Delivery: "github:d-2", Payload: []byte(`{}`)}
			if err := st.EnqueueGitJob(ctx, b); err != nil {
				t.Fatal(err)
			}
			// The same delivery again is a conflict, and findable.
			dup := &model.GitJob{ID: "gitjob_dup", Tenant: "acme", Name: "config", Action: "sync", Delivery: "github:d-1", Payload: []byte(`{}`)}
			if err := st.EnqueueGitJob(ctx, dup); !errors.Is(err, ErrConflict) {
				t.Fatalf("duplicate delivery: %v", err)
			}
			if j, err := st.GetGitJobByDelivery(ctx, "acme", "config", "github:d-1"); err != nil || j.ID != "gitjob_a" {
				t.Fatalf("by delivery: %v %+v", err, j)
			}
			// Another repository may carry the same delivery id.
			if err := st.EnqueueGitJob(ctx, &model.GitJob{ID: "gitjob_c", Tenant: "acme", Name: "other", Action: "sync", Delivery: "github:d-1", Payload: []byte(`{}`)}); err != nil {
				t.Fatalf("same delivery, other repository: %v", err)
			}
			// Claims: oldest first, one owner each, with a lease.
			j1, err := st.ClaimGitJob(ctx, "one", now, time.Minute)
			if err != nil || j1.ID != "gitjob_a" || j1.Status != model.GitJobRunning || j1.Owner != "one" || j1.Attempts != 1 || j1.LeaseUntil == nil || !j1.LeaseUntil.Equal(now.Add(time.Minute)) || string(j1.Payload) != `{"after":"aaaa"}` {
				t.Fatalf("first claim: %v %+v", err, j1)
			}
			j2, err := st.ClaimGitJob(ctx, "two", now, time.Minute)
			if err != nil || j2.ID == j1.ID || j2.Owner != "two" {
				t.Fatalf("second claim: %v %+v", err, j2)
			}
			j3, err := st.ClaimGitJob(ctx, "two", now, time.Minute)
			if err != nil || j3.ID != "gitjob_c" {
				t.Fatalf("third claim: %v %+v", err, j3)
			}
			if _, err := st.ClaimGitJob(ctx, "three", now, time.Minute); !errors.Is(err, ErrNotFound) {
				t.Fatalf("every job leased: %v", err)
			}
			// A lapsed lease is claimable again (attempt 2); the former holder can no longer finish.
			j1b, err := st.ClaimGitJob(ctx, "three", now.Add(2*time.Minute), time.Minute)
			if err != nil || j1b.ID != "gitjob_a" || j1b.Owner != "three" || j1b.Attempts != 2 {
				t.Fatalf("takeover: %v %+v", err, j1b)
			}
			if err := st.FinishGitJob(ctx, "gitjob_a", "one", model.GitJobDone, "done", ""); !errors.Is(err, ErrConflict) {
				t.Fatalf("the former holder finishing: %v", err)
			}
			if err := st.FinishGitJob(ctx, "gitjob_a", "three", model.GitJobDone, "done", ""); err != nil {
				t.Fatalf("the holder finishing: %v", err)
			}
			got, err := st.GetGitJob(ctx, "gitjob_a")
			if err != nil || got.Status != model.GitJobDone || got.Outcome != "done" || got.LeaseUntil != nil || got.Attempts != 2 {
				t.Fatalf("finished job: %v %+v", err, got)
			}
			// Done jobs are never claimed again; a failed one neither.
			if err := st.FinishGitJob(ctx, "gitjob_b", "two", model.GitJobFailed, "error", "boom"); err != nil {
				t.Fatal(err)
			}
			if err := st.FinishGitJob(ctx, "gitjob_c", "two", model.GitJobDone, "done", ""); err != nil {
				t.Fatal(err)
			}
			if _, err := st.ClaimGitJob(ctx, "four", now.Add(time.Hour), time.Minute); !errors.Is(err, ErrNotFound) {
				t.Fatalf("finished jobs claimed: %v", err)
			}
			if _, err := st.GetGitJob(ctx, "nope"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("unknown job: %v", err)
			}
		})
	}
}
