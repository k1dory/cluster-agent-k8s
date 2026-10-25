package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// The GitSync record: one per (tenant, name), replaced whole, absent until written; the same
// contract in memory and in PostgreSQL.
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
			g := &model.GitSync{Tenant: "acme", Name: "config", Head: "aaaa", CheckedAt: &now}
			if err := st.PutGitSync(ctx, g); err != nil {
				t.Fatal(err)
			}
			got, err := st.GetGitSync(ctx, "acme", "config")
			if err != nil || got.Head != "aaaa" || got.CheckedAt == nil || !got.CheckedAt.Equal(now) || got.UpdatedAt.IsZero() {
				t.Fatalf("after check: %v %+v", err, got)
			}
			// Replaced whole: the sync fields come, the check fields stay as written.
			g.Commit, g.Status = "bbbb", model.GitSyncDone
			g.Bundles = []model.GitSyncBundle{{Path: "bundles/a.yaml", Apply: "apply_1", Status: "done", Changes: 2}, {Path: "bundles/b.yaml", Status: "invalid", Errors: []string{"x", "y"}}}
			if err := st.PutGitSync(ctx, g); err != nil {
				t.Fatal(err)
			}
			got, err = st.GetGitSync(ctx, "acme", "config")
			if err != nil || got.Commit != "bbbb" || got.Head != "aaaa" || len(got.Bundles) != 2 || got.Bundles[1].Errors[1] != "y" || got.Bundles[0].Changes != 2 {
				t.Fatalf("after sync: %v %+v", err, got)
			}
			// The record is a copy: mutating what came back changes nothing stored.
			got.Bundles[0].Apply = "mutated"
			if again, _ := st.GetGitSync(ctx, "acme", "config"); again.Bundles[0].Apply != "apply_1" {
				t.Fatal("the stored record was mutated through a returned copy")
			}
			// Scoped by tenant and name; the shared scope is a tenant of its own.
			if _, err := st.GetGitSync(ctx, "other", "config"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("another tenant: %v", err)
			}
			if err := st.PutGitSync(ctx, &model.GitSync{Tenant: "", Name: "config", Head: "cccc"}); err != nil {
				t.Fatal(err)
			}
			if shared, err := st.GetGitSync(ctx, "", "config"); err != nil || shared.Head != "cccc" {
				t.Fatalf("shared scope: %v %+v", err, shared)
			}
			if own, _ := st.GetGitSync(ctx, "acme", "config"); own.Head != "aaaa" {
				t.Fatal("the shared record replaced the tenant's")
			}
		})
	}
}

// postgresDSNForGitSync is reviewPostgresURL without the skip: the memory contract runs
// everywhere, the PostgreSQL one where a database is configured (required in CI's postgres job).
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
