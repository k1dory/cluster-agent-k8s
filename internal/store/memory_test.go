package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

func TestRunScopeAndCursor(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	for i := 0; i < 300; i++ {
		_ = m.AppendEvent(ctx, &model.Event{SandboxID: "sb", RunID: "other", Type: model.EventInput, Data: "x"})
	}
	_ = m.AppendEvent(ctx, &model.Event{SandboxID: "sb", RunID: "", Type: model.EventRunCancel})
	_ = m.AppendEvent(ctx, &model.Event{SandboxID: "sb", RunID: "mine", Type: model.EventInput, Data: "hi"})
	evs, _ := m.QueryEvents(ctx, Filter{SandboxID: "sb", Types: []string{model.EventInput, model.EventRunCancel}, RunScope: "mine", Limit: 200})
	if len(evs) != 2 || evs[0].Type != model.EventRunCancel || evs[1].Data != "hi" {
		t.Fatalf("run scope must be applied before the limit: %d events", len(evs))
	}

	t0 := time.Now()
	for i, id := range []string{"r1", "r2", "r3"} {
		_ = m.CreateRun(ctx, &model.Run{ID: id, SandboxID: "sb", Status: model.RunQueued, CreatedAt: t0.Add(time.Duration(i) * time.Second)})
	}
	page, _ := m.QueryRuns(ctx, Filter{SandboxID: "sb", Limit: 1})
	c := Cursor{At: page[0].CreatedAt, ID: page[0].ID}
	parsed, err := ParseCursor(c.Encode())
	if err != nil || !parsed.At.Equal(c.At) || parsed.ID != c.ID {
		t.Fatalf("cursor round trip: %v %+v", err, parsed)
	}
	// Claim (and thereby change) the anchor, then page after it: the cursor still works.
	if r, err := m.ClaimQueuedRun(ctx, "sb", t0); err != nil || r.ID != "r1" || r.Status != model.RunRunning {
		t.Fatalf("claim: %v %+v", err, r)
	}
	if _, err := m.ClaimQueuedRun(ctx, "sb", t0); err != nil {
		t.Fatalf("second claim: %v", err)
	}
	next, _ := m.QueryRuns(ctx, Filter{SandboxID: "sb", Status: string(model.RunQueued), Cursor: parsed, Limit: 10})
	if len(next) != 1 || next[0].ID != "r3" {
		t.Fatalf("page after cursor: %+v", next)
	}
	if _, err := ParseCursor("not-a-cursor!"); err == nil {
		t.Fatal("malformed cursor must fail")
	}
}

func TestRevisionConflictAndTouch(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	sb := &model.Sandbox{ID: "sb1", Status: model.StatusRunning, CreatedAt: time.Now(), LastActivity: time.Now().Add(-time.Hour)}
	if err := m.CreateSandbox(ctx, sb); err != nil || sb.Revision != 1 {
		t.Fatalf("create: %v rev=%d", err, sb.Revision)
	}
	a, _ := m.GetSandbox(ctx, "sb1")
	b, _ := m.GetSandbox(ctx, "sb1")
	a.Status = model.StatusSleeping
	if err := m.UpdateSandbox(ctx, a); err != nil || a.Revision != 2 {
		t.Fatalf("first writer: %v rev=%d", err, a.Revision)
	}
	b.Status = model.StatusError
	if err := m.UpdateSandbox(ctx, b); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale writer must get ErrConflict, got %v", err)
	}
	// Touch never bumps the revision, so a writer holding the current record still succeeds.
	now := time.Now()
	if err := m.TouchSandbox(ctx, "sb1", now); err != nil {
		t.Fatal(err)
	}
	cur, _ := m.GetSandbox(ctx, "sb1")
	if cur.Revision != 2 || !cur.LastActivity.Equal(now) || cur.Status != model.StatusSleeping {
		t.Fatalf("after touch: %+v", cur)
	}
	a.IdleTimeout = 7
	if err := m.UpdateSandbox(ctx, a); err != nil {
		t.Fatalf("writer with the current revision after a touch: %v", err)
	}
	if _, err := m.GetOrCreateBlob(ctx, "k", func() ([]byte, error) { return []byte("v1"), nil }); err != nil {
		t.Fatal(err)
	}
	if v, _ := m.GetOrCreateBlob(ctx, "k", func() ([]byte, error) { return []byte("v2"), nil }); string(v) != "v1" {
		t.Fatalf("blob must be created once, got %s", v)
	}
	if lease, held, err := m.TryLead(ctx, "x"); err != nil || !held || lease.Ping(ctx) != nil {
		t.Fatal("memory store always leads")
	}
}
