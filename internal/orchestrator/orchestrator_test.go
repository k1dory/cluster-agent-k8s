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
	// Idle timer must not kill a sandbox with a run in progress (last activity never moves
	// backwards in the store, so the one-second idle timeout is simply waited out).
	time.Sleep(1100 * time.Millisecond)
	o.Reconcile(ctx)
	if sb, _ = o.Get(ctx, sb.ID); sb.Status != model.StatusRunning {
		t.Fatalf("sandbox with running run must stay up, got %s", sb.Status)
	}
	if err := o.FinishRun(ctx, sb.ID, run.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	o.Reconcile(ctx)
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

type allowAll struct{}

func (allowAll) AllowedFor(string, string) bool { return true }

type onlyAcme struct{}

func (onlyAcme) AllowedFor(slug, tenant string) bool {
	return slug != "backend-dev" || tenant == "acme"
}

func TestVersionsAndRollouts(t *testing.T) {
	ctx := context.Background()
	o := New(store.NewMemory(), NewFakeRuntime(), nil, events.New(), Config{
		PreviewDomain: "preview.test", IdleCheckEvery: 10 * time.Millisecond,
		DefaultAgentVersion: "registry/agent:1.0", Versions: map[string]string{"stable": "registry/agent:1.0", "canary": "registry/agent:1.1"},
		EnvVersion: func(sb *model.Sandbox) string { return "env-" + sb.AgentVersion },
	}, nil)
	o.Policies = onlyAcme{}
	rctx, stop := context.WithCancel(ctx)
	defer stop()
	go o.Run(rctx) // the reconciler applies deferred rollouts; the memory store always leads
	deadline0 := time.Now().Add(2 * time.Second)
	for !o.Leading() && time.Now().Before(deadline0) {
		time.Sleep(5 * time.Millisecond)
	}

	// Ownership: backend-dev belongs to acme.
	if _, err := o.Create(ctx, CreateRequest{Name: "x", Slug: "backend-dev", Owner: "bob", Tenant: "evil"}); err == nil || !errorsIs(err, ErrForbidden) {
		t.Fatalf("foreign tenant must be refused: %v", err)
	}
	// Tenants may only name catalogue versions; the admin may pass any reference.
	if _, err := o.Create(ctx, CreateRequest{Name: "x", Slug: "backend-dev", Owner: "a", Tenant: "acme", AgentVersion: "registry/evil:latest"}); err == nil || !errorsIs(err, ErrForbidden) {
		t.Fatalf("arbitrary image from a tenant must be refused: %v", err)
	}
	var ids []string
	for i := 0; i < 4; i++ {
		sb, err := o.Create(ctx, CreateRequest{Name: "s" + string(rune('a'+i)), Slug: "backend-dev", Owner: "alice", Tenant: "acme"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, sb.ID)
	}
	adm, err := o.Create(ctx, CreateRequest{Name: "adm", Slug: "backend-dev", Owner: "root", Tenant: "ops", AgentVersion: "registry/custom:9", Admin: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range append(ids, adm.ID) {
		waitStatus(t, o, id, model.StatusRunning)
	}
	sb, _ := o.Get(ctx, ids[0])
	if sb.AgentVersion != "registry/agent:1.0" || sb.EnvVersion != "env-registry/agent:1.0" || sb.Revision < 2 {
		t.Fatalf("new sandbox: %+v", sb)
	}
	if adm, _ = o.Get(ctx, adm.ID); adm.AgentVersion != "registry/custom:9" {
		t.Fatalf("admin version: %+v", adm)
	}

	// ids[1] is busy: a run is executing. ids[2] is asleep.
	run1, _ := o.CreateRun(ctx, ids[1], "long job")
	if _, err := o.NextRun(ctx, ids[1], time.Second); err != nil {
		t.Fatal(err)
	}
	if err := o.Output(ctx, ids[1], run1.ID, `{"type":"system","session_id":"sess-42"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Sleep(ctx, ids[2], false); err != nil {
		t.Fatal(err)
	}

	// Tenant rollout of the whole slug, not forced.
	res, err := o.Rollout(ctx, RolloutRequest{Version: "canary", Slug: "backend-dev", Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	modes := map[string]string{}
	for _, it := range res.Items {
		modes[it.Sandbox] = it.Mode
	}
	if res.Selected != 4 || res.Targeted != 4 || modes[ids[0]] != model.RolloutNow || modes[ids[1]] != model.RolloutDeferred || modes[ids[2]] != model.RolloutWake {
		t.Fatalf("rollout: %+v", res)
	}
	// Idle sandbox restarted at once on the new version; busy one keeps the old pod with a pending version.
	sb = waitStatus(t, o, ids[0], model.StatusRunning)
	if sb.AgentVersion != "registry/agent:1.1" || sb.DesiredVersion != "" || sb.Instance != 0 && sb.PodName == "" {
		t.Fatalf("rolled out sandbox: %+v", sb)
	}
	if sb, _ = o.Get(ctx, ids[1]); sb.AgentVersion != "registry/agent:1.0" || sb.DesiredVersion != "registry/agent:1.1" {
		t.Fatalf("busy sandbox must wait: %+v", sb)
	}
	// The run finishes: the deferred rollout applies.
	if err := o.FinishRun(ctx, ids[1], run1.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for sb, _ = o.Get(ctx, ids[1]); sb.AgentVersion != "registry/agent:1.1" && time.Now().Before(deadline); sb, _ = o.Get(ctx, ids[1]) {
		time.Sleep(20 * time.Millisecond)
	}
	if sb.AgentVersion != "registry/agent:1.1" {
		t.Fatalf("deferred rollout not applied: %+v", sb)
	}
	// The sleeping one switches when woken.
	if _, err := o.Wake(ctx, ids[2]); err != nil {
		t.Fatal(err)
	}
	if sb = waitStatus(t, o, ids[2], model.StatusRunning); sb.AgentVersion != "registry/agent:1.1" || sb.DesiredVersion != "" {
		t.Fatalf("wake rollout: %+v", sb)
	}

	// Forced rollout of one busy sandbox: the run is cancelled and continued by a resume run.
	run2, _ := o.CreateRun(ctx, ids[3], "refactor")
	if _, err := o.NextRun(ctx, ids[3], time.Second); err != nil {
		t.Fatal(err)
	}
	_ = o.Output(ctx, ids[3], run2.ID, `{"type":"system","session_id":"sess-7"}`)
	res, err = o.Rollout(ctx, RolloutRequest{Version: "stable", Sandbox: ids[3], Tenant: "acme", Force: true})
	if err != nil || len(res.Items) != 1 || res.Items[0].Mode != model.RolloutForced || res.Items[0].RunID != run2.ID || res.Items[0].ResumeID == "" {
		t.Fatalf("forced rollout: %v %+v", err, res)
	}
	waitStatus(t, o, ids[3], model.StatusRunning)
	old, _ := o.Store.GetRun(ctx, run2.ID)
	next, _ := o.Store.GetRun(ctx, res.Items[0].ResumeID)
	if old.Status != model.RunCancelled || next.Status != model.RunQueued || next.ResumeOf != run2.ID || next.Session != "sess-7" || next.Task != "refactor" {
		t.Fatalf("resume run: old=%+v new=%+v", old, next)
	}
	got, err := o.NextRun(ctx, ids[3], time.Second)
	if err != nil || got.ID != next.ID || got.AgentVersion != "registry/agent:1.0" {
		t.Fatalf("resume run claimed on the new agent: %v %+v", err, got)
	}

	// Canary: a percentage targets a deterministic subset; already-updated sandboxes are skipped.
	res, _ = o.Rollout(ctx, RolloutRequest{Version: "stable", All: true, Tenant: "acme", Percent: 50})
	again, _ := o.Rollout(ctx, RolloutRequest{Version: "stable", All: true, Tenant: "acme", Percent: 50})
	if res.Selected != 4 || res.Targeted == 0 || res.Targeted == 4 || res.Targeted != again.Targeted {
		t.Fatalf("canary: %+v / %+v", res, again)
	}
	// A tenant cannot touch another tenant's sandbox, nor the admin's by id.
	if _, err := o.Rollout(ctx, RolloutRequest{Version: "stable", Sandbox: adm.ID, Tenant: "acme"}); err == nil || !errorsIs(err, ErrForbidden) {
		t.Fatalf("cross-tenant rollout: %v", err)
	}
	if _, err := o.Rollout(ctx, RolloutRequest{Version: "stable", Tenant: "acme"}); err == nil || !errorsIs(err, ErrBadRequest) {
		t.Fatalf("rollout without selector: %v", err)
	}
	// Admin: by instance number (the registrar sets it at bootstrap; here by hand).
	sb, _ = o.Get(ctx, adm.ID)
	sb.Instance = 77
	if err := o.Store.UpdateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	res, err = o.Rollout(ctx, RolloutRequest{Version: "registry/custom:10", Instance: 77, Admin: true})
	if err != nil || res.Targeted != 1 || res.Items[0].Sandbox != adm.ID || res.Items[0].Mode != model.RolloutNow {
		t.Fatalf("rollout by instance: %v %+v", err, res)
	}
	if sb = waitStatus(t, o, adm.ID, model.StatusRunning); sb.AgentVersion != "registry/custom:10" {
		t.Fatalf("admin rollout to an arbitrary image: %+v", sb)
	}
}

func errorsIs(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
