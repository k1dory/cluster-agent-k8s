package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"agent-sandbox/internal/model"
)

// A catalogue written before deleted_at existed (the table as first shipped) keeps its rows
// usable after the migration, and deletion on it marks instead of removing.
func TestReviewPostgresCatalogUpgradeFromFirstCatalogSchema(t *testing.T) {
	dsn := reviewPostgresURL(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `CREATE TABLE catalog_items (
		kind text NOT NULL, tenant text NOT NULL DEFAULT '', name text NOT NULL, revision integer NOT NULL,
		description text NOT NULL DEFAULT '', spec jsonb NOT NULL, created_by text NOT NULL DEFAULT '',
		created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (kind, tenant, name, revision));
		INSERT INTO catalog_items (kind, tenant, name, revision, spec) VALUES
		('EnvironmentProfile', 'acme', 'base', 1, '{"image":"stable"}'), ('EnvironmentProfile', 'acme', 'base', 2, '{"image":"canary"}')`); err != nil {
		t.Fatal(err)
	}
	p := reviewOpenPostgres(t, dsn)
	it, err := p.GetItem(ctx, model.KindEnvironment, "acme", "base", 0)
	if err != nil || it.Revision != 2 || it.DeletedAt != nil {
		t.Fatalf("latest after migration: %v %+v", err, it)
	}
	if err := p.DeleteItem(ctx, model.KindEnvironment, "acme", "base"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetItem(ctx, model.KindEnvironment, "acme", "base", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted revision: %v", err)
	}
	history, err := p.ListRevisions(ctx, model.KindEnvironment, "acme", "base")
	if err != nil || len(history) != 2 || history[0].DeletedAt == nil || history[1].DeletedAt == nil {
		t.Fatalf("history kept and marked: %v %+v", err, history)
	}
	list, err := p.ListItems(ctx, model.KindEnvironment, "acme")
	if err != nil || len(list) != 0 {
		t.Fatalf("deleted item listed: %v %+v", err, list)
	}
	next := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "base", Spec: json.RawMessage(`{"image":"stable"}`)}
	if err := p.PutItem(ctx, next, 0); err != nil || next.Revision != 3 {
		t.Fatalf("recreate continues numbering: %v %+v", err, next)
	}
	if err := p.PutItem(ctx, next, 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("a deleted revision is not a valid base: %v", err)
	}
	if err := p.PutItem(ctx, next, 3); err != nil || next.Revision != 4 {
		t.Fatalf("update on the recreated item: %v %+v", err, next)
	}
}

// ListKind and per-slug counting on a real PostgreSQL.
func TestReviewPostgresListKindAndSlugCounts(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := t.Context()
	for _, it := range []struct{ tenant, name, spec string }{{"acme", "backend-dev", `{"max_sandboxes":1}`}, {"bob", "backend-dev", `{}`}, {"bob", "netops", `{}`}} {
		if err := p.PutItem(ctx, &model.CatalogItem{Kind: model.KindBinding, Tenant: it.tenant, Name: it.name, Spec: json.RawMessage(it.spec)}, -1); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.PutItem(ctx, &model.CatalogItem{Kind: model.KindBinding, Tenant: "acme", Name: "backend-dev", Spec: json.RawMessage(`{"max_sandboxes":2}`)}, 1); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteItem(ctx, model.KindBinding, "bob", "netops"); err != nil {
		t.Fatal(err)
	}
	all, err := p.ListKind(ctx, model.KindBinding)
	if err != nil || len(all) != 2 || all[0].Tenant != "acme" || all[0].Revision != 2 || all[1].Tenant != "bob" || all[1].Name != "backend-dev" {
		t.Fatalf("ListKind: %v %+v", err, all)
	}
	now := time.Now()
	for i, slug := range []string{"backend-dev", "backend-dev", "netops"} {
		sb := &model.Sandbox{ID: fmt.Sprintf("c%d", i), Name: "n", Slug: slug, Owner: "bob", Tenant: "bob", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
		if err := p.CreateSandbox(ctx, sb); err != nil {
			t.Fatal(err)
		}
	}
	if c, err := p.CountSandboxes(ctx, "bob", ""); err != nil || c.Total != 3 || c.Awake != 3 {
		t.Fatalf("all slugs: %v %+v", err, c)
	}
	if c, err := p.CountSandboxes(ctx, "bob", "backend-dev"); err != nil || c.Total != 2 {
		t.Fatalf("one slug: %v %+v", err, c)
	}
}

// A sandbox's connections survive the round trip through PostgreSQL (and are absent for
// sandboxes created before the column existed).
func TestReviewPostgresSandboxConnections(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, true))
	ctx := t.Context()
	legacy, err := p.GetSandbox(ctx, "legacy-sandbox")
	if err != nil || legacy.Connections != nil {
		t.Fatalf("legacy sandbox: %v %+v", err, legacy)
	}
	now := time.Now()
	sb := &model.Sandbox{ID: "conn-sandbox", Name: "n", Slug: "dev", Owner: "alice", Tenant: "acme", Status: model.StatusSleeping,
		CreatedAt: now, LastActivity: now, Connections: []string{"github", "shared/registry"}}
	if err := p.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	got, err := p.GetSandbox(ctx, sb.ID)
	if err != nil || len(got.Connections) != 2 || got.Connections[1] != "shared/registry" {
		t.Fatalf("connections after create: %v %+v", err, got)
	}
	got.Connections = nil
	if err := p.UpdateSandbox(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, err := p.GetSandbox(ctx, sb.ID); err != nil || again.Connections != nil {
		t.Fatalf("connections after update: %v %+v", err, again)
	}
}
