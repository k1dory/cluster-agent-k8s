package store

import (
	"encoding/json"
	"errors"
	"testing"

	"agent-sandbox/internal/model"
)

func TestReviewMemoryApplyNoopChecksRevisionAtCommit(t *testing.T) {
	reviewApplyNoopChecksRevisionAtCommit(t, NewMemory())
}

func TestReviewPostgresApplyNoopChecksRevisionAtCommit(t *testing.T) {
	reviewApplyNoopChecksRevisionAtCommit(t, reviewOpenPostgres(t, reviewPostgresURL(t, false)))
}

func reviewApplyNoopChecksRevisionAtCommit(t *testing.T, st Store) {
	t.Helper()
	ctx := t.Context()
	it := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Spec: json.RawMessage(`{"image":"stable"}`)}
	if err := st.PutItem(ctx, it, 0); err != nil {
		t.Fatal(err)
	}
	a := &model.Apply{ID: "review_noop", Key: "review-noop", Tenant: "acme", Status: model.ApplyRunning, Documents: json.RawMessage(`[]`),
		Steps: []model.ApplyStep{{Kind: it.Kind, Tenant: it.Tenant, Name: it.Name, Action: "noop", ExpectedRevision: 1, NextRevision: 1, Status: model.StepPending}}}
	if err := st.CreateApply(ctx, a); err != nil {
		t.Fatal(err)
	}
	// Another writer updates the item after planning, before the noop is checkpointed.
	it.Spec = json.RawMessage(`{"image":"canary"}`)
	if err := st.PutItem(ctx, it, 1); err != nil {
		t.Fatal(err)
	}
	a.Steps[0].Status, a.Steps[0].Revision = model.StepSkipped, 1
	if err := st.ApplyStep(ctx, a, 0, nil, 1); !errors.Is(err, ErrConflict) {
		t.Errorf("noop must refuse a changed resource at commit: got %v", err)
	}
	got, err := st.GetApply(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 1 || got.Steps[0].Status != model.StepPending {
		t.Errorf("stale noop must leave progress unchanged: version=%d status=%s", got.Version, got.Steps[0].Status)
	}
}
