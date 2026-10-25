package store

import (
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"github.com/jackc/pgx/v5"
)

// Upgrading a persisted job must establish its execution identity once and keep
// it across a fresh retry budget and a second platform startup.
func TestReviewGitJobRunSurvivesUpgradeRequeueAndReopen(t *testing.T) {
	dsn := reviewPostgresURL(t, false)
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `CREATE TABLE git_jobs (
		id text PRIMARY KEY, tenant text NOT NULL DEFAULT '', name text NOT NULL,
		action text NOT NULL, delivery text NOT NULL, payload bytea NOT NULL,
		status text NOT NULL, attempts integer NOT NULL DEFAULT 0,
		owner text NOT NULL DEFAULT '', lease_until timestamptz,
		outcome text NOT NULL DEFAULT '', error text NOT NULL DEFAULT '',
		created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
		UNIQUE (tenant, name, delivery));
		INSERT INTO git_jobs (id, tenant, name, action, delivery, payload, status, attempts, owner)
		VALUES ('review-legacy-job', 'acme', 'config', 'sync', 'review-delivery', '', 'failed', 3, 'review-worker')`); err != nil {
		t.Fatal(err)
	}
	st := reviewOpenPostgres(t, dsn)
	legacy, err := st.GetGitJob(ctx, "review-legacy-job")
	if err != nil || legacy.Run != 3 || legacy.Attempts != 3 || legacy.Status != model.GitJobFailed {
		t.Fatalf("migration did not preserve the legacy execution: job=%+v err=%v", legacy, err)
	}
	if err := st.RequeueGitJob(ctx, legacy.ID); err != nil {
		t.Fatal(err)
	}
	queued, err := st.GetGitJob(ctx, legacy.ID)
	if err != nil || queued.Run != 3 || queued.Attempts != 0 {
		t.Fatalf("requeue reset the durable execution identity: job=%+v err=%v", queued, err)
	}
	current, err := st.ClaimGitJob(ctx, "review-worker", time.Now(), time.Minute)
	if err != nil || current.ID != legacy.ID || current.Run != 4 || current.Attempts != 1 {
		t.Fatalf("new budget must advance the execution: job=%+v err=%v", current, err)
	}
	if err := st.FinishGitJob(ctx, legacy.ID, "review-worker", legacy.Run, model.GitJobDone, model.GitSyncDone, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("the legacy execution could finish the new claim: %v", err)
	}
	if err := st.FinishGitJob(ctx, current.ID, "review-worker", current.Run, model.GitJobDone, model.GitSyncDone, ""); err != nil {
		t.Fatal(err)
	}
	st.Close()
	reopened := reviewOpenPostgres(t, dsn)
	got, err := reopened.GetGitJob(ctx, current.ID)
	if err != nil || got.Run != 4 || got.Attempts != 1 || got.Status != model.GitJobDone || got.Outcome != model.GitSyncDone {
		t.Fatalf("reopening the store changed the completed execution: job=%+v err=%v", got, err)
	}
}
