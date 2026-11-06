package store_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/store"
)

// lifecycleRound2Postgres opens a store on a schema of its own, dropped after the test.
func lifecycleRound2Postgres(t *testing.T) *store.Postgres {
	t.Helper()
	dsn := os.Getenv("SANDBOX_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("set SANDBOX_TEST_POSTGRES_URL to run the PostgreSQL lifecycle regressions")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("round2_lifecycle_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("cleanup schema: %v", err)
		}
		admin.Close(ctx)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	pg, err := store.OpenPostgres(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Close() })
	return pg
}

// The preview access generation is a column: it survives the round trip, every update keeps
// it, and SetPreview bumps it when the preview is closed or its access level changes.
func TestRound2PostgresPreviewGenerationPersists(t *testing.T) {
	pg := lifecycleRound2Postgres(t)
	ctx := t.Context()
	o := orchestrator.New(pg, orchestrator.NewFakeRuntime(), nil, events.New(), orchestrator.Config{PreviewDomain: "pv.test"}, nil)
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_pvgen", Name: "shop", Slug: "dev", Tenant: "acme", Owner: "alice", Status: model.StatusSleeping, CreatedAt: now, LastActivity: now}
	if err := pg.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	gen := func() int64 {
		t.Helper()
		got, err := pg.GetSandbox(ctx, sb.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.PreviewGen
	}
	if _, err := o.SetPreview(ctx, sb.ID, 3000, model.AccessMembers); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SetPreview(ctx, sb.ID, 3001, model.AccessMembers); err != nil {
		t.Fatal(err)
	}
	if g := gen(); g != 0 {
		t.Fatalf("opening a preview and moving its port revoke nothing: gen %d", g)
	}
	if _, err := o.SetPreview(ctx, sb.ID, 3001, model.AccessSSO); err != nil {
		t.Fatal(err)
	}
	if g := gen(); g != 1 {
		t.Fatalf("access level changed: gen %d, want 1", g)
	}
	if _, err := o.Update(ctx, sb.ID, orchestrator.UpdateRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SetPreview(ctx, sb.ID, 0, ""); err != nil {
		t.Fatal(err)
	}
	if g := gen(); g != 2 {
		t.Fatalf("preview closed (after an unrelated update): gen %d, want 2", g)
	}
	if _, err := o.SetPreview(ctx, sb.ID, 3001, model.AccessSSO); err != nil {
		t.Fatal(err)
	}
	byHost, err := pg.SandboxByPreviewHost(ctx, "shop-alice.pv.test")
	if err != nil || byHost.PreviewGen != 2 {
		t.Fatalf("by preview host: %v %+v", err, byHost)
	}
}
