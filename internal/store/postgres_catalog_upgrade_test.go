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

// Run mode and transfer blobs round-trip through PostgreSQL.
func TestReviewPostgresRunModeAndBlobs(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, true))
	ctx := t.Context()
	if legacy, err := p.GetRun(ctx, "legacy-run"); err != nil || legacy.Mode != "" {
		t.Fatalf("legacy run: %v %+v", err, legacy)
	}
	now := time.Now()
	r := &model.Run{ID: "chat-run", SandboxID: "legacy-sandbox", Task: "next message", Status: model.RunQueued, CreatedAt: now,
		ResumeOf: "legacy-run", Session: "sess-1", Mode: model.RunMessage}
	if err := p.CreateRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, err := p.GetRun(ctx, r.ID); err != nil || got.Mode != model.RunMessage || got.Session != "sess-1" || got.ResumeOf != "legacy-run" {
		t.Fatalf("run mode: %v %+v", err, got)
	}
	if err := p.PutBlob(ctx, "fs/sb/one", []byte("content")); err != nil {
		t.Fatal(err)
	}
	if err := p.PutBlob(ctx, "fs/sb/one", []byte("replaced")); err != nil {
		t.Fatal(err)
	}
	if b, err := p.GetBlob(ctx, "fs/sb/one"); err != nil || string(b) != "replaced" {
		t.Fatalf("blob: %v %q", err, b)
	}
	if err := p.PutBlob(ctx, "other/keep", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if n, err := p.DeleteBlobsBefore(ctx, "fs/", time.Now().Add(time.Minute)); err != nil || n != 1 {
		t.Fatalf("purge by prefix: %v %d", err, n)
	}
	if _, err := p.GetBlob(ctx, "fs/sb/one"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purged blob: %v", err)
	}
	if b, err := p.GetBlob(ctx, "other/keep"); err != nil || string(b) != "x" {
		t.Fatalf("other prefix kept: %v", err)
	}
	if err := p.DeleteBlob(ctx, "other/keep"); err != nil {
		t.Fatal(err)
	}
}

// Applies on a real PostgreSQL: unique keys, the step transaction, version guards.
func TestReviewPostgresApplies(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := t.Context()
	a := &model.Apply{ID: "apply_1", Key: "k1", Tenant: "acme", Status: model.ApplyRunning, Documents: json.RawMessage(`[]`),
		Steps: []model.ApplyStep{
			{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Action: "create", Status: model.StepPending},
			{Kind: model.KindAgent, Tenant: "acme", Name: "backend", Action: "create", Status: model.StepPending},
		}}
	if err := p.CreateApply(ctx, a); err != nil || a.Version != 1 {
		t.Fatalf("create: %v %+v", err, a)
	}
	if err := p.CreateApply(ctx, &model.Apply{ID: "apply_2", Key: "k1", Tenant: "acme", Status: model.ApplyRunning, Documents: json.RawMessage(`[]`)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate key in the tenant: %v", err)
	}
	if err := p.CreateApply(ctx, &model.Apply{ID: "apply_3", Key: "k1", Tenant: "other", Status: model.ApplyRunning, Documents: json.RawMessage(`[]`)}); err != nil {
		t.Fatalf("same key in another tenant: %v", err)
	}
	got, err := p.GetApplyByKey(ctx, "acme", "k1")
	if err != nil || got.ID != "apply_1" || len(got.Steps) != 2 {
		t.Fatalf("by key: %v %+v", err, got)
	}
	// A step writes its item and its completion together.
	it := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Spec: json.RawMessage(`{"image":"stable"}`)}
	a.Steps[0].Status = model.StepDone
	if err := p.ApplyStep(ctx, a, 0, it, 0); err != nil || it.Revision != 1 || a.Steps[0].Revision != 1 || a.Version != 2 {
		t.Fatalf("step: %v item=%+v apply=%+v", err, it, a)
	}
	stored, _ := p.GetApply(ctx, a.ID)
	if stored.Version != 2 || stored.Steps[0].Status != model.StepDone || stored.Steps[0].Revision != 1 {
		t.Fatalf("stored after step: %+v", stored)
	}
	// A stale record cannot commit a step, and a stale write leaves the item untouched too.
	stale := *stored
	stale.Version = 1
	stale.Steps = append([]model.ApplyStep(nil), stored.Steps...)
	stale.Steps[1].Status = model.StepDone
	it2 := &model.CatalogItem{Kind: model.KindAgent, Tenant: "acme", Name: "backend", Spec: json.RawMessage(`{"policy":"p","environment":"py"}`)}
	if err := p.ApplyStep(ctx, &stale, 1, it2, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale apply: %v", err)
	}
	if _, err := p.GetItem(ctx, model.KindAgent, "acme", "backend", 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("the item write must roll back with the refused step")
	}
	// An item that moved refuses the step, and the progress is not recorded either.
	fresh, _ := p.GetApply(ctx, a.ID)
	fresh.Steps[1].Status = model.StepDone
	if err := p.ApplyStep(ctx, fresh, 1, it2, 5); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong expected revision: %v", err)
	}
	if again, _ := p.GetApply(ctx, a.ID); again.Steps[1].Status != model.StepPending || again.Version != 2 {
		t.Fatalf("progress recorded despite the refused write: %+v", again)
	}
	// A noop step records progress without an item.
	fresh, _ = p.GetApply(ctx, a.ID)
	fresh.Steps[1].Status, fresh.Steps[1].Revision = model.StepSkipped, 0
	if err := p.ApplyStep(ctx, fresh, 1, nil, 0); err != nil {
		t.Fatal(err)
	}
	fresh.Status = model.ApplyDone
	if err := p.UpdateApply(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	list, err := p.ListApplies(ctx, "acme", 10)
	if err != nil || len(list) != 1 || list[0].Status != model.ApplyDone || list[0].Version != 4 {
		t.Fatalf("list: %v %+v", err, list)
	}
	if all, _ := p.ListApplies(ctx, "", 10); len(all) != 2 {
		t.Fatalf("all tenants: %d", len(all))
	}
}
