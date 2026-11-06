package app

import (
	"context"
	"testing"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// sandboxd used to start the reconciler before Wire set the orchestrator's guard and quotas: a
// write to fields a running goroutine reads, and a first pass on the lease winner without the
// guard. Wire now refuses a running reconciler, so that order fails at startup.
func TestWireRefusesARunningReconciler(t *testing.T) {
	newOrch := func() *orchestrator.Orchestrator {
		return orchestrator.New(store.NewMemory(), orchestrator.NewFakeRuntime(), nil, events.New(), orchestrator.Config{}, nil)
	}
	deps := func(o *orchestrator.Orchestrator) Deps {
		return Deps{Store: o.Store, Policies: policy.FromPolicies(), Secrets: secrets.Static{}, Orch: o, Replica: "sandboxd-0"}
	}
	o := newOrch()
	svc, err := Wire(context.Background(), deps(o))
	if err != nil {
		t.Fatal(err)
	}
	if o.Policies == nil || o.Quotas == nil {
		t.Fatal("Wire did not install the guard and the quotas")
	}
	if svc.Applier.Replica != "sandboxd-0" {
		t.Fatalf("apply lease owner %q, want the replica name", svc.Applier.Replica)
	}

	o = newOrch()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o.Run(ctx) // returns at once, the reconciler counts as started
	if _, err := Wire(context.Background(), deps(o)); err == nil {
		t.Fatal("Wire accepted an orchestrator whose reconciler already runs")
	}
}
