package orchestrator

import (
	"context"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

func waitStatus(t *testing.T, o *Orchestrator, id string, want model.SandboxStatus) *model.Sandbox {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sb, _ := o.Get(context.Background(), id)
		if sb != nil && sb.Status == want {
			return sb
		}
		time.Sleep(20 * time.Millisecond)
	}
	sb, _ := o.Get(context.Background(), id)
	t.Fatalf("sandbox %s status %s, want %s", id, sb.Status, want)
	return nil
}

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	o := New(store.NewMemory(), NewFakeRuntime(), nil, events.New(), Config{PreviewDomain: "preview.test", IdleCheckEvery: 10 * time.Millisecond}, nil)
	one := 1
	sb, err := o.Create(ctx, CreateRequest{Name: "shop", Slug: "backend-dev", Owner: "alice", IdleTimeout: &one})
	if err != nil {
		t.Fatal(err)
	}
	sb = waitStatus(t, o, sb.ID, model.StatusRunning)
	if sb.IP == "" {
		t.Fatal("running sandbox must have an IP")
	}

	run, err := o.CreateRun(ctx, sb.ID, "add tests")
	if err != nil {
		t.Fatal(err)
	}
	got, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil || got.ID != run.ID || got.Status != model.RunRunning {
		t.Fatalf("NextRun: %v %+v", err, got)
	}
	// Idle timer must not kill a sandbox with a run in progress.
	sb, _ = o.Get(ctx, sb.ID)
	sb.LastActivity = time.Now().Add(-time.Hour)
	_ = o.Store.UpdateSandbox(ctx, sb)
	o.sweepIdle(ctx)
	if sb, _ = o.Get(ctx, sb.ID); sb.Status != model.StatusRunning {
		t.Fatalf("sandbox with running run must stay up, got %s", sb.Status)
	}
	if err := o.FinishRun(ctx, sb.ID, run.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	o.sweepIdle(ctx)
	sb = waitStatus(t, o, sb.ID, model.StatusSleeping)
	if sb.PodName != "" || sb.IP != "" {
		t.Fatal("sleeping sandbox must have no pod")
	}

	// A new run wakes it.
	if _, err := o.CreateRun(ctx, sb.ID, "next task"); err != nil {
		t.Fatal(err)
	}
	waitStatus(t, o, sb.ID, model.StatusRunning)

	sb, err = o.SetPreview(ctx, sb.ID, 3000, "")
	if err != nil || sb.Preview == nil || sb.Preview.Host != "shop-alice.preview.test" || sb.Preview.Access != model.AccessMembers {
		t.Fatalf("preview: %v %+v", err, sb.Preview)
	}
	if _, err := o.Store.SandboxByPreviewHost(ctx, "shop-alice.preview.test"); err != nil {
		t.Fatal("preview host lookup failed")
	}
	evs, _ := o.Store.ListEvents(ctx, sb.ID, 0, 0)
	if len(evs) < 5 {
		t.Fatalf("expected an event trail, got %d events", len(evs))
	}
	if err := o.Delete(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Get(ctx, sb.ID); err == nil {
		t.Fatal("deleted sandbox must be gone")
	}
}
