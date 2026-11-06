package orchestrator

import (
	"context"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// SetPreview bumps the access generation when the preview is closed or its access level
// changes (the preview proxy refuses sign-ins of an earlier generation); moving the port or
// setting the same access again keeps them.
func TestRound2SetPreviewBumpsTheAccessGeneration(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	o := New(st, NewFakeRuntime(), nil, events.New(), Config{PreviewDomain: "pv.test"}, nil)
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_pv", Name: "shop", Slug: "dev", Tenant: "acme", Owner: "alice", Status: model.StatusSleeping, CreatedAt: now, LastActivity: now}
	if err := st.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		port   int
		access string
		gen    int64
	}{
		{3000, model.AccessMembers, 0},
		{3001, model.AccessMembers, 0},
		{3001, model.AccessMembers, 0},
		{3001, model.AccessSSO, 1},
		{0, "", 2},
		{3001, model.AccessSSO, 2},
	}
	for i, s := range steps {
		got, err := o.SetPreview(ctx, sb.ID, s.port, s.access)
		if err != nil {
			t.Fatal(err)
		}
		if got.PreviewGen != s.gen {
			t.Fatalf("step %d (port %d, access %q): gen %d, want %d", i, s.port, s.access, got.PreviewGen, s.gen)
		}
	}
}
