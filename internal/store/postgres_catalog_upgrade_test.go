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

// The step transaction's revision checks on a real PostgreSQL: a noop confirms its revision
// atomically, and a write whose number differs from the promised one is refused as a whole.
func TestReviewPostgresApplyStepRevisionChecks(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := t.Context()
	put := func(name, spec string) {
		t.Helper()
		if err := p.PutItem(ctx, &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: name, Spec: json.RawMessage(spec)}, -1); err != nil {
			t.Fatal(err)
		}
	}
	// noop: the item moved after the plan.
	put("live", `{"image":"stable"}`)
	a := &model.Apply{ID: "apply_noop", Key: "n", Tenant: "acme", Status: model.ApplyRunning, Documents: json.RawMessage(`[]`),
		Steps: []model.ApplyStep{{Kind: model.KindEnvironment, Tenant: "acme", Name: "live", Action: "noop", ExpectedRevision: 1, NextRevision: 1, Status: model.StepSkipped}}}
	if err := p.CreateApply(ctx, a); err != nil {
		t.Fatal(err)
	}
	put("live", `{"image":"canary"}`)
	if err := p.ApplyStep(ctx, a, 0, nil, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale noop: %v", err)
	}
	if got, _ := p.GetApply(ctx, a.ID); got.Version != 1 {
		t.Fatalf("refused noop recorded progress: %+v", got)
	}
	if err := p.ApplyStep(ctx, a, 0, nil, 2); err != nil || a.Steps[0].Revision != 2 {
		t.Fatalf("noop at the current revision: %v %+v", err, a.Steps[0])
	}
	// create: history changed (created and deleted) so the next number is 2, the plan promised 1.
	put("gone", `{"image":"stable"}`)
	if err := p.DeleteItem(ctx, model.KindEnvironment, "acme", "gone"); err != nil {
		t.Fatal(err)
	}
	b := &model.Apply{ID: "apply_hist", Key: "h", Tenant: "acme", Status: model.ApplyRunning, Documents: json.RawMessage(`[]`),
		Steps: []model.ApplyStep{{Kind: model.KindEnvironment, Tenant: "acme", Name: "gone", Action: "create", ExpectedRevision: 0, NextRevision: 1, Status: model.StepDone}}}
	if err := p.CreateApply(ctx, b); err != nil {
		t.Fatal(err)
	}
	it := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "gone", Spec: json.RawMessage(`{"image":"stable"}`)}
	if err := p.ApplyStep(ctx, b, 0, it, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("promised revision 1, would write 2: %v", err)
	}
	if revs, _ := p.ListRevisions(ctx, model.KindEnvironment, "acme", "gone"); len(revs) != 1 {
		t.Fatalf("refused step wrote: %d revisions", len(revs))
	}
	if got, _ := p.GetApply(ctx, b.ID); got.Version != 1 || got.Steps[0].Revision != 0 {
		t.Fatalf("refused step recorded progress: %+v", got)
	}
}

// Provenance on a real PostgreSQL: the source column round-trips through every read path, an
// apply step writes it, a plain write leaves it NULL, and deleted items are listed for drift.
func TestReviewPostgresSourceAndDeletedItems(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := t.Context()
	src := &model.Source{Apply: "apply_1", Bundle: "b1", Repo: "git@example.com:acme/platform.git", Ref: "main", Commit: "0123456789abcdef0123456789abcdef01234567", Path: "bundles/acme.yaml"}
	it := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Spec: json.RawMessage(`{"image":"stable"}`), CreatedBy: "ci", Source: src}
	if err := p.PutItem(ctx, it, 0); err != nil {
		t.Fatal(err)
	}
	got, err := p.GetItem(ctx, model.KindEnvironment, "acme", "py", 0)
	if err != nil || got.Source == nil || *got.Source != *src {
		t.Fatalf("source round trip: %v %+v", err, got)
	}
	// A plain write carries no source; the history keeps both.
	if err := p.PutItem(ctx, &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Spec: json.RawMessage(`{"image":"canary"}`), CreatedBy: "mallory"}, 1); err != nil {
		t.Fatal(err)
	}
	revs, err := p.ListRevisions(ctx, model.KindEnvironment, "acme", "py")
	if err != nil || len(revs) != 2 || !revs[0].Managed() || revs[1].Managed() {
		t.Fatalf("revisions: %v %+v", err, revs)
	}
	list, _ := p.ListItems(ctx, model.KindEnvironment, "acme")
	if len(list) != 1 || list[0].Managed() {
		t.Fatalf("list: %+v", list)
	}
	// An apply step writes the source inside its transaction.
	a := &model.Apply{ID: "apply_2", Key: "k2", Tenant: "acme", Status: model.ApplyRunning, Documents: json.RawMessage(`[]`),
		Steps: []model.ApplyStep{{Kind: model.KindEnvironment, Tenant: "acme", Name: "go", Action: "create", NextRevision: 1, Status: model.StepDone}}}
	if err := p.CreateApply(ctx, a); err != nil {
		t.Fatal(err)
	}
	stepped := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "go", Spec: json.RawMessage(`{"image":"stable"}`), Source: &model.Source{Apply: a.ID, Bundle: "b2", Rollback: "apply_1"}}
	if err := p.ApplyStep(ctx, a, 0, stepped, 0); err != nil {
		t.Fatal(err)
	}
	if got, err := p.GetItem(ctx, model.KindEnvironment, "acme", "go", 0); err != nil || got.Source == nil || got.Source.Apply != a.ID || got.Source.Rollback != "apply_1" {
		t.Fatalf("stepped source: %v %+v", err, got)
	}
	// Deleted items are listed with their last revision; live ones are not.
	if err := p.DeleteItem(ctx, model.KindEnvironment, "acme", "go"); err != nil {
		t.Fatal(err)
	}
	gone, err := p.ListDeleted(ctx, model.KindEnvironment, "acme")
	if err != nil || len(gone) != 1 || gone[0].Name != "go" || gone[0].DeletedAt == nil || !gone[0].Managed() {
		t.Fatalf("deleted: %v %+v", err, gone)
	}
	if other, _ := p.ListDeleted(ctx, model.KindEnvironment, "other"); len(other) != 0 {
		t.Fatalf("another tenant's deleted items: %+v", other)
	}
}

// Tenant API keys on a real PostgreSQL: unique ids, round trip of every nullable field, the
// mutable-field update, per-tenant listing newest first.
func TestReviewPostgresAPIKeys(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := t.Context()
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	k := &model.APIKey{ID: "key_1", Tenant: "acme", Name: "ci", Hash: "h1", CreatedBy: "admin-token", ExpiresAt: &exp}
	if err := p.CreateAPIKey(ctx, k); err != nil || k.CreatedAt.IsZero() {
		t.Fatalf("create: %v %+v", err, k)
	}
	if err := p.CreateAPIKey(ctx, &model.APIKey{ID: "key_1", Tenant: "other", Hash: "h"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate id: %v", err)
	}
	got, err := p.GetAPIKey(ctx, "key_1")
	if err != nil || got.Tenant != "acme" || got.Hash != "h1" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || got.RevokedAt != nil || got.LastUsedAt != nil {
		t.Fatalf("get: %v %+v", err, got)
	}
	// Narrow, atomic changes: a use touches last_used_at only; a revocation keeps the earliest
	// time; a retirement never clears a revocation.
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := p.TouchAPIKey(ctx, "key_1", now); err != nil {
		t.Fatal(err)
	}
	if err := p.RevokeAPIKey(ctx, "key_1", now); err != nil {
		t.Fatal(err)
	}
	if err := p.RevokeAPIKey(ctx, "key_1", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	again, _ := p.GetAPIKey(ctx, "key_1")
	if again.RevokedAt == nil || !again.RevokedAt.Equal(now) || again.LastUsedAt == nil || !again.LastUsedAt.Equal(now) || again.Hash != "h1" || !again.ExpiresAt.Equal(exp) {
		t.Fatalf("after touch and revoke: %+v", again)
	}
	if err := p.RetireAPIKey(ctx, "key_1", "key_2", now.Add(2*time.Hour), time.Hour); err != nil {
		t.Fatal(err)
	}
	retired, _ := p.GetAPIKey(ctx, "key_1")
	if retired.RotatedTo != "key_2" || !retired.RevokedAt.Equal(now) || !retired.ExpiresAt.Equal(exp) {
		t.Fatalf("retire after revoke: %+v", retired)
	}
	// Retirement with grace shortens the expiry (never lengthens it); without grace it revokes.
	if err := p.CreateAPIKey(ctx, &model.APIKey{ID: "key_g", Tenant: "acme", Name: "g", Hash: "hg", ExpiresAt: &exp}); err != nil {
		t.Fatal(err)
	}
	if err := p.RetireAPIKey(ctx, "key_g", "key_h", now, 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	g, _ := p.GetAPIKey(ctx, "key_g")
	if g.RevokedAt != nil || !g.ExpiresAt.Equal(now.Add(10*time.Minute)) || g.RotatedTo != "key_h" {
		t.Fatalf("retire with grace: %+v", g)
	}
	if err := p.RetireAPIKey(ctx, "key_g", "key_h", now, 5*time.Hour); err != nil {
		t.Fatal(err)
	}
	if g, _ = p.GetAPIKey(ctx, "key_g"); !g.ExpiresAt.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("a longer grace lengthened the expiry: %+v", g)
	}
	if err := p.RetireAPIKey(ctx, "key_g", "key_h", now, 0); err != nil {
		t.Fatal(err)
	}
	if g, _ = p.GetAPIKey(ctx, "key_g"); g.RevokedAt == nil || !g.RevokedAt.Equal(now) {
		t.Fatalf("retire without grace: %+v", g)
	}
	for _, err := range []error{p.TouchAPIKey(ctx, "key_none", now), p.RevokeAPIKey(ctx, "key_none", now), p.RetireAPIKey(ctx, "key_none", "x", now, 0)} {
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing key: %v", err)
		}
	}
	if _, err := p.GetAPIKey(ctx, "key_none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	if err := p.CreateAPIKey(ctx, &model.APIKey{ID: "key_2", Tenant: "acme", Name: "deploy", Hash: "h2", CreatedAt: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateAPIKey(ctx, &model.APIKey{ID: "key_3", Tenant: "other", Name: "x", Hash: "h3"}); err != nil {
		t.Fatal(err)
	}
	list, err := p.ListAPIKeys(ctx, "acme")
	if err != nil || len(list) != 3 || list[0].ID != "key_2" || list[2].ID != "key_1" {
		t.Fatalf("list: %v %+v", err, list)
	}
	if all, _ := p.ListAPIKeys(ctx, ""); len(all) != 4 {
		t.Fatalf("every tenant: %d", len(all))
	}
}

// Tenant credentials on a real PostgreSQL: insert versus replace in one statement, the
// creation record kept, ciphertext round trip, per-scope listing and deletion.
func TestReviewPostgresCredentials(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := t.Context()
	c := &model.Credential{Tenant: "acme", Name: "anthropic", Fingerprint: "f1", CreatedBy: "key:k1"}
	created, err := p.PutCredential(ctx, c, []byte("ct1"))
	if err != nil || !created || c.Version != 1 || c.CreatedAt.IsZero() || !c.UpdatedAt.Equal(c.CreatedAt) {
		t.Fatalf("insert: %v %v %+v", err, created, c)
	}
	first := c.CreatedAt
	c2 := &model.Credential{Tenant: "acme", Name: "anthropic", Fingerprint: "f2", CreatedBy: "key:k2"}
	created, err = p.PutCredential(ctx, c2, []byte("ct2"))
	if err != nil || created || c2.Version != 2 || c2.CreatedBy != "key:k1" || !c2.CreatedAt.Equal(first) || c2.UpdatedAt.Before(first) {
		t.Fatalf("replace: %v %v %+v", err, created, c2)
	}
	got, ct, err := p.GetCredential(ctx, "acme", "anthropic")
	if err != nil || got.Version != 2 || got.Fingerprint != "f2" || string(ct) != "ct2" {
		t.Fatalf("get: %v %+v %q", err, got, ct)
	}
	if _, _, err := p.GetCredential(ctx, "other", "anthropic"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another scope: %v", err)
	}
	if _, err := p.PutCredential(ctx, &model.Credential{Tenant: "", Name: "anthropic", Fingerprint: "s"}, []byte("shared")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.PutCredential(ctx, &model.Credential{Tenant: "acme", Name: "github", Fingerprint: "g"}, []byte("gh")); err != nil {
		t.Fatal(err)
	}
	list, err := p.ListCredentials(ctx, "acme")
	if err != nil || len(list) != 2 || list[0].Name != "anthropic" || list[1].Name != "github" {
		t.Fatalf("list: %v %+v", err, list)
	}
	if shared, _ := p.ListCredentials(ctx, ""); len(shared) != 1 {
		t.Fatalf("shared scope: %+v", shared)
	}
	if err := p.DeleteCredential(ctx, "acme", "anthropic"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteCredential(ctx, "acme", "anthropic"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if _, _, err := p.GetCredential(ctx, "", "anthropic"); err != nil {
		t.Fatalf("the shared one stays: %v", err)
	}
}
