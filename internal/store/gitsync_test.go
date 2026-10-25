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
