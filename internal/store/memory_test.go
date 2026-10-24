package store

import (
	"context"
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
