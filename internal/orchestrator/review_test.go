package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

type reviewStatusRuntime struct {
	*FakeRuntime
	statusError error
}

func (r *reviewStatusRuntime) PodStatus(ctx context.Context, sb *model.Sandbox) (bool, string, error) {
	if r.statusError != nil {
		return false, "", r.statusError
	}
	return r.FakeRuntime.PodStatus(ctx, sb)
}

func reviewRunningSandbox(t *testing.T) (*Orchestrator, *reviewStatusRuntime, *model.Sandbox) {
	t.Helper()
	ctx := context.Background()
	rt := &reviewStatusRuntime{FakeRuntime: NewFakeRuntime()}
	st := store.NewMemory()
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_review", Slug: "dev", Tenant: "acme", Name: "review", Owner: "alice", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := rt.EnsureVolume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	var err error
	sb.PodName, err = rt.CreatePod(ctx, sb)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	return New(st, rt, nil, events.New(), Config{}, nil), rt, sb
}

func TestReviewTransientPodStatusFailurePreservesWork(t *testing.T) {
	o, rt, sb := reviewRunningSandbox(t)
	ctx := context.Background()
	if _, err := o.CreateRun(ctx, sb.ID, "running task"); err != nil {
		t.Fatal(err)
	}
	run, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	rt.statusError = errors.New("temporary Kubernetes API connection failure")
	o.Reconcile(ctx)
	current, err := o.Store.GetRun(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := o.Get(ctx, sb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Status != model.StatusRunning || current.Status != model.RunRunning {
		t.Fatalf("transient observation failure destroyed live work: sandbox=%s run=%s", actual.Status, current.Status)
	}
}

func TestReviewEgressAttributionAcrossReplicas(t *testing.T) {
	first, rt, sb := reviewRunningSandbox(t)
	second := New(first.Store, rt, nil, events.New(), Config{}, nil)
	ctx := context.Background()
	second.RecordEgress(ctx, sb.ID, true, model.Egress{Host: "service.test", Path: "/before"})
	if _, err := first.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	run, err := first.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	second.RecordEgress(ctx, sb.ID, true, model.Egress{Host: "service.test", Path: "/during"})
	evs, err := first.Store.QueryEvents(ctx, store.Filter{SandboxID: sb.ID, Types: []string{model.EventEgressOK}})
	if err != nil {
		t.Fatal(err)
	}
	if last := evs[len(evs)-1]; last.RunID != run.ID {
		t.Fatalf("event was permanently recorded under run %q, expected current run %q", last.RunID, run.ID)
	}
}
