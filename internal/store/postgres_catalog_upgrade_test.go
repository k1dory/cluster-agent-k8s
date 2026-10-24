package store

import (
	"context"
	"encoding/json"
	"errors"
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
