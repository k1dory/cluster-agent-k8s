package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"agent-sandbox/internal/model"
)

// SANDBOX_TEST_POSTGRES_URL must identify a test database. Each invocation creates its
// own schema and drops only that schema; the production migration runs inside it.
func reviewPostgresURL(t *testing.T, upgrade bool) string {
	t.Helper()
	dsn := os.Getenv("SANDBOX_TEST_POSTGRES_URL")
	if dsn == "" {
		t.Skip("set SANDBOX_TEST_POSTGRES_URL to run the real PostgreSQL contract tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	schema := "catalog_review_" + hex.EncodeToString(nonce[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
		admin.Close(ctx)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	if upgrade {
		conn, err := pgx.Connect(ctx, u.String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		old, err := os.ReadFile("testdata/schema_5cdff6d.sql")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, string(old)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `INSERT INTO sandboxes (id,name,slug,owner,tenant,status,last_activity,created_at,admin_grant)
			VALUES ('legacy-sandbox','legacy','dev','alice','acme','sleeping',now(),now(),true);
			INSERT INTO runs (id,sandbox_id,task,status,created_at) VALUES ('legacy-run','legacy-sandbox','old task','done',now())`); err != nil {
			t.Fatal(err)
		}
	}
	return u.String()
}

func reviewOpenPostgres(t *testing.T, dsn string) *Postgres {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestReviewPostgresCatalogMigrationAndSnapshots(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "upgrade_from_5cdff6d"}[upgrade], func(t *testing.T) {
			dsn := reviewPostgresURL(t, upgrade)
			p := reviewOpenPostgres(t, dsn)
			ctx := t.Context()
			if upgrade {
				sb, err := p.GetSandbox(ctx, "legacy-sandbox")
				if err != nil || sb.Launch != nil || sb.AgentRevision != 0 || !sb.AdminGrant {
					t.Fatalf("legacy sandbox changed during migration: %v %+v", err, sb)
				}
				r, err := p.GetRun(ctx, "legacy-run")
				if err != nil || r.Task != "old task" || r.AgentRef != "" {
					t.Fatalf("legacy run: %v %+v", err, r)
				}
			}
			item := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "base", CreatedBy: "alice", Spec: json.RawMessage(`{"image":"stable"}`)}
			if err := p.PutItem(ctx, item, 0); err != nil {
				t.Fatal(err)
			}
			if item.Revision != 1 || item.CreatedAt.IsZero() {
				t.Fatalf("first revision: %+v", item)
			}
			second := *item
			second.Spec = json.RawMessage(`{"image":"canary"}`)
			if err := p.PutItem(ctx, &second, 1); err != nil {
				t.Fatal(err)
			}
			if second.Revision != 2 {
				t.Fatalf("revision=%d", second.Revision)
			}
			if err := p.PutItem(ctx, &second, 1); !errors.Is(err, ErrConflict) {
				t.Fatalf("stale writer: %v", err)
			}
			if _, err := p.GetItem(ctx, model.KindEnvironment, "other", "base", 1); !errors.Is(err, ErrNotFound) {
				t.Fatalf("tenant isolation: %v", err)
			}
			list, err := p.ListItems(ctx, model.KindEnvironment, "acme")
			if err != nil || len(list) != 1 || list[0].Revision != 2 {
				t.Fatalf("latest list: %v %+v", err, list)
			}
			history, err := p.ListRevisions(ctx, model.KindEnvironment, "acme", "base")
			if err != nil || len(history) != 2 {
				t.Fatalf("history: %v %+v", err, history)
			}
			var original map[string]any
			if err := json.Unmarshal(history[0].Spec, &original); err != nil || original["image"] != "stable" {
				t.Fatalf("old revision mutated: %v %s", err, history[0].Spec)
			}

			now := time.Now().UTC().Truncate(time.Microsecond)
			launch := &model.Launch{Image: "registry/agent:1", HarnessCommand: "test-harness", Model: "review-model", Instructions: "review instructions", Env: map[string]string{"APP_SETTING": "frozen"}, CPULimit: "2", MemoryLimit: "4Gi", VolumeSize: "10Gi", RuntimeClass: "review-runtime"}
			sb := &model.Sandbox{ID: "catalog-sandbox", Name: "review", Slug: "dev", Owner: "alice", Tenant: "acme", Status: model.StatusSleeping, CreatedAt: now, LastActivity: now,
				AgentRef: "worker", AgentRevision: 3, EnvironmentRef: "base", EnvironmentRevision: 1, AgentVersion: launch.Image, Launch: launch, AdminGrant: true}
			if err := p.CreateSandbox(ctx, sb); err != nil {
				t.Fatal(err)
			}
			sb.IdleTimeout = 123
			if err := p.UpdateSandbox(ctx, sb); err != nil {
				t.Fatal(err)
			}
			run := &model.Run{ID: "catalog-run", SandboxID: sb.ID, Tenant: sb.Tenant, Slug: sb.Slug, Task: "review", Status: model.RunQueued, CreatedAt: now}
			if err := p.CreateRun(ctx, run); err != nil {
				t.Fatal(err)
			}
			claimed, err := p.ClaimQueuedRun(ctx, sb.ID, now)
			if err != nil {
				t.Fatal(err)
			}
			claimed.AgentRef, claimed.AgentRevision = sb.AgentRef, sb.AgentRevision
			claimed.EnvironmentRef, claimed.EnvironmentRevision = sb.EnvironmentRef, sb.EnvironmentRevision
			claimed.AgentVersion = sb.AgentVersion
			if err := p.UpdateRun(ctx, claimed); err != nil {
				t.Fatal(err)
			}
			// Close all original connections and rerun the migration on a fresh pool.
			p.Close()
			reopened := reviewOpenPostgres(t, dsn)
			got, err := reopened.GetSandbox(ctx, sb.ID)
			if err != nil || got.IdleTimeout != 123 || got.AgentRevision != 3 || got.EnvironmentRevision != 1 || !reflect.DeepEqual(got.Launch, launch) {
				t.Fatalf("sandbox launch after reopen: %v %+v", err, got)
			}
			stored, err := reopened.GetRun(ctx, run.ID)
			if err != nil || stored.Status != model.RunRunning || stored.AgentRef != "worker" || stored.AgentRevision != 3 || stored.EnvironmentRevision != 1 {
				t.Fatalf("run snapshot after reopen: %v %+v", err, stored)
			}
			if _, err := reopened.GetItem(ctx, item.Kind, item.Tenant, item.Name, 1); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReviewPostgresCatalogConcurrentWriters(t *testing.T) {
	dsn := reviewPostgresURL(t, false)
	first, second := reviewOpenPostgres(t, dsn), reviewOpenPostgres(t, dsn)
	ctx := t.Context()
	if err := first.PutItem(ctx, &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "base", Spec: json.RawMessage(`{"image":"stable"}`)}, 0); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 8)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			p := first
			if i%2 != 0 {
				p = second
			}
			it := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "base", Spec: json.RawMessage(fmt.Sprintf(`{"image":"version-%d"}`, i))}
			results <- p.PutItem(ctx, it, 1)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	won, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			won++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Errorf("writer: %v", err)
		}
	}
	if won != 1 || conflicts != 7 {
		t.Fatalf("CAS must have one winner across two pools: won=%d conflicts=%d", won, conflicts)
	}
	history, err := first.ListRevisions(ctx, model.KindEnvironment, "acme", "base")
	if err != nil || len(history) != 2 {
		t.Fatalf("history after concurrent writes: %v %+v", err, history)
	}
}

func TestReviewPostgresCatalogDoesNotReuseDeletedRevision(t *testing.T) {
	p := reviewOpenPostgres(t, reviewPostgresURL(t, false))
	ctx := t.Context()
	old := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "base", Spec: json.RawMessage(`{"image":"stable"}`)}
	if err := p.PutItem(ctx, old, 0); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteItem(ctx, old.Kind, old.Tenant, old.Name); err != nil {
		if errors.Is(err, ErrConflict) {
			return
		}
		t.Fatal(err)
	}
	next := &model.CatalogItem{Kind: old.Kind, Tenant: old.Tenant, Name: old.Name, Spec: json.RawMessage(`{"image":"canary"}`)}
	if err := p.PutItem(ctx, next, -1); err != nil {
		if errors.Is(err, ErrConflict) {
			return
		}
		t.Fatal(err)
	}
	if next.Revision <= old.Revision {
		t.Fatalf("delete/recreate reused immutable revision %d for different content", next.Revision)
	}
}
