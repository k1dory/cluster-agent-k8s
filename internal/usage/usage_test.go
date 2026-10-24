package usage

import (
	"context"
	"math"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

func TestPodSecondsAndGrouping(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	t0 := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	ev := func(sb, tenant, slug, typ, data string, at time.Time) {
		_ = st.AppendEvent(ctx, &model.Event{SandboxID: sb, Tenant: tenant, Slug: slug, Type: typ, Data: data, At: at})
	}
	// alice/sb1: up 10 minutes, then sleeps. bob/sb2: woke at +5m and is still up at "now" (+20m).
	ev("sb1", "alice", "backend-dev", model.EventStatus, "waking", t0)
	ev("sb1", "alice", "backend-dev", model.EventStatus, "running", t0.Add(30*time.Second))
	ev("sb1", "alice", "backend-dev", model.EventStatus, "stopping", t0.Add(10*time.Minute))
	ev("sb1", "alice", "backend-dev", model.EventStatus, "sleeping", t0.Add(10*time.Minute+time.Second))
	ev("sb2", "bob", "netops", model.EventStatus, "waking", t0.Add(5*time.Minute))
	ev("sb2", "bob", "netops", model.EventEgressDen, `{"host":"evil"}`, t0.Add(6*time.Minute))
	now := t0.Add(20 * time.Minute)
	started := t0.Add(time.Minute)
	finished := t0.Add(3 * time.Minute)
	_ = st.CreateRun(ctx, &model.Run{ID: "r1", SandboxID: "sb1", Tenant: "alice", Slug: "backend-dev", Status: model.RunDone,
		CreatedAt: t0, StartedAt: &started, FinishedAt: &finished, Usage: model.Usage{CostUSD: 1.5, OutputTokens: 100}})

	rep, err := Build(ctx, st, Query{From: t0, To: now, GroupBy: ByTenant}, Pricing{PodHourUSD: 3.6}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Rows) != 2 {
		t.Fatalf("rows: %+v", rep.Rows)
	}
	alice, bob := rep.Rows[0], rep.Rows[1]
	if alice.Key != "alice" || math.Abs(alice.PodSeconds-600) > 0.01 || alice.RunSeconds != 120 || alice.ModelUSD != 1.5 || math.Abs(alice.ComputeUSD-0.6) > 1e-9 {
		t.Fatalf("alice: %+v", alice)
	}
	if bob.Key != "bob" || math.Abs(bob.PodSeconds-900) > 0.01 || bob.EgressDenied != 1 || bob.Runs != 0 {
		t.Fatalf("bob: %+v", bob)
	}
	if math.Abs(rep.Total.TotalUSD-(1.5+0.6+0.9)) > 1e-9 {
		t.Fatalf("total: %+v", rep.Total)
	}
	// A window that starts mid-way clips the pod time.
	rep, _ = Build(ctx, st, Query{Tenant: "alice", From: t0.Add(5 * time.Minute), To: now, GroupBy: BySandbox}, Pricing{}, now)
	if len(rep.Rows) != 1 || math.Abs(rep.Rows[0].PodSeconds-300) > 0.01 || rep.Rows[0].Runs != 0 {
		t.Fatalf("clipped: %+v", rep.Rows)
	}
	if _, err := Build(ctx, st, Query{GroupBy: "week"}, Pricing{}, now); err == nil {
		t.Fatal("bad group_by must fail")
	}
	// Deleting a sandbox closes its compute interval: no pod time accrues after `deleting`.
	ev("sb3", "carol", "netops", model.EventStatus, "waking", t0)
	ev("sb3", "carol", "netops", model.EventStatus, "deleting", t0.Add(10*time.Second))
	rep, _ = Build(ctx, st, Query{Tenant: "carol", From: t0, To: now}, Pricing{}, now)
	if math.Abs(rep.Total.PodSeconds-10) > 0.01 {
		t.Fatalf("deleted sandbox must stop accruing: %+v", rep.Total)
	}
	// More status events than one store page: the walk is paginated.
	for i := 0; i < 2500; i++ {
		ev("sb4", "dave", "netops", model.EventStatus, "waking", t0.Add(time.Duration(i)*time.Second))
		ev("sb4", "dave", "netops", model.EventStatus, "sleeping", t0.Add(time.Duration(i)*time.Second+500*time.Millisecond))
	}
	rep, _ = Build(ctx, st, Query{Tenant: "dave", From: t0, To: now}, Pricing{}, now)
	// 1200 pairs fall inside the 20-minute window (2400 status events, three store pages).
	if math.Abs(rep.Total.PodSeconds-600) > 0.01 {
		t.Fatalf("paginated status walk: %+v", rep.Total)
	}
}
