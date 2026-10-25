package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"github.com/jackc/pgx/v5"
)

// Rows written by PR #25 must remain visible after the check/sync split.
// Seed the old table before OpenPostgres runs the current migrations. Also cover
// a row whose check half was already updated by the newer binary.
func TestReviewGitSyncUpgradeFromFlatStatus(t *testing.T) {
	dsn := reviewPostgresURL(t, false)
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `CREATE TABLE git_syncs (
		tenant text NOT NULL DEFAULT '', name text NOT NULL, doc jsonb NOT NULL,
		updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tenant, name))`); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	commit := strings.Repeat("a", 40)
	newHead := strings.Repeat("b", 40)
	for _, name := range []string{"legacy", "check_already_updated"} {
		legacy := map[string]any{
			"tenant": "acme", "name": name,
			"head": commit, "checked_at": at,
			"commit": commit, "synced_at": at, "status": model.GitSyncStopped,
			"error": "a bundle needs retry", "updated_at": at,
			"bundles": []model.GitSyncBundle{{Path: "bundle.yaml", Apply: "apply_legacy", Status: model.ApplyFailed}},
		}
		if name == "check_already_updated" {
			legacy["check"] = model.GitCheck{Head: newHead, At: at.Add(time.Minute)}
		}
		raw, err := json.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `INSERT INTO git_syncs (tenant, name, doc, updated_at) VALUES ('acme', $1, $2::jsonb, $3)`, name, raw, at); err != nil {
			t.Fatal(err)
		}
	}
	p := reviewOpenPostgres(t, dsn)
	for _, name := range []string{"legacy", "check_already_updated"} {
		t.Run(name, func(t *testing.T) {
			got, err := p.GetGitSync(ctx, "acme", name)
			if err != nil {
				t.Fatal(err)
			}
			wantHead, wantCheckAt := commit, at
			if name == "check_already_updated" {
				wantHead, wantCheckAt = newHead, at.Add(time.Minute)
			}
			if got.Check == nil || got.Check.Head != wantHead || !got.Check.At.Equal(wantCheckAt) {
				t.Errorf("upgrade lost or replaced the last check: %+v", got)
			}
			assertSync := func(g *model.GitSync) {
				t.Helper()
				if g.Sync == nil || g.Sync.Commit != commit || g.Sync.Status != model.GitSyncStopped || !g.Sync.At.Equal(at) || g.Sync.Error != "a bundle needs retry" || len(g.Sync.Bundles) != 1 || g.Sync.Bundles[0].Apply != "apply_legacy" {
					t.Errorf("upgrade lost the stopped sync and its apply id: %+v", g)
				}
			}
			assertSync(got)
			if err := p.RecordGitCheck(ctx, "acme", name, model.GitCheck{Head: newHead, At: at.Add(2 * time.Minute)}); err != nil {
				t.Fatal(err)
			}
			got, err = p.GetGitSync(ctx, "acme", name)
			if err != nil {
				t.Fatal(err)
			}
			assertSync(got)
		})
	}
}
