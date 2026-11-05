package orchestrator

import (
	"context"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A replica that died between writing stopping and deleting the pod left the pod running and
// the record stopping forever (Wake refuses a stopping sandbox). The reconciler now deletes the
// pod again once the stop has outlived StopTimeout, cancels the run it was executing, and
// settles the sandbox as sleeping.
func TestReviewReconcileFinishesStopWithLivePod(t *testing.T) {
	ctx := context.Background()
	rt := NewFakeRuntime()
	st := store.NewMemory()
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_stop", Slug: "dev", Tenant: "acme", Name: "stop", Owner: "alice", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := rt.EnsureVolume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	sb.PodName, _ = rt.CreatePod(ctx, sb)
	if err := st.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	o := New(st, rt, nil, events.New(), Config{StopTimeout: 30 * time.Millisecond}, nil)
	if _, err := o.CreateRun(ctx, sb.ID, "task"); err != nil {
		t.Fatal(err)
	}
	run, err := o.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// What stopPod writes before it calls DeletePod; then the replica is gone.
	if _, err := o.setStatusFrom(ctx, sb.ID, []model.SandboxStatus{model.StatusRunning}, model.StatusStopping, nil); err != nil {
		t.Fatal(err)
	}
	o.Reconcile(ctx)
	if got, _ := st.GetSandbox(ctx, sb.ID); got.Status != model.StatusStopping {
		t.Fatalf("a fresh stop is left to whoever is doing it: %s", got.Status)
	}
	if _, _, err := rt.PodStatus(ctx, sb); err != nil {
		t.Fatalf("pod deleted before StopTimeout: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	o.Reconcile(ctx)
	waitFor(t, "sandbox to settle as sleeping", func() bool {
		got, _ := st.GetSandbox(ctx, sb.ID)
		return got.Status == model.StatusSleeping
	})
	if _, _, err := rt.PodStatus(ctx, sb); err == nil {
		t.Fatal("pod still running after the stop was taken over")
	}
	if r, _ := st.GetRun(ctx, run.ID); r.Status != model.RunCancelled {
		t.Fatalf("run of the stopped pod: %s", r.Status)
	}
	if _, err := o.Wake(ctx, sb.ID); err != nil {
		t.Fatalf("wake after the stop settled: %v", err)
	}
}

// ctxRuntime fails a runtime call whose context is cancelled, after cancelling it itself: the
// client hung up while the call was in flight.
type ctxRuntime struct {
	*FakeRuntime
	hangUp context.CancelFunc
}

func (r *ctxRuntime) DeletePod(ctx context.Context, sb *model.Sandbox) error {
	r.hangUp()
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.FakeRuntime.DeletePod(ctx, sb)
}

func (r *ctxRuntime) CreatePod(ctx context.Context, sb *model.Sandbox) (string, error) {
	r.hangUp()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return r.FakeRuntime.CreatePod(ctx, sb)
}

// Once a stop or a start has written its transition, the cluster call and its bookkeeping no
// longer depend on the request: a client hanging up does not strand the sandbox in stopping or
// waking (or leave an error status unwritten on Postgres).
func TestReviewStopAndStartSurviveClientHangUp(t *testing.T) {
	o, fake, sb := reviewRunningSandbox(t)
	reqCtx, hangUp := context.WithCancel(context.Background())
	o.Runtime = &ctxRuntime{FakeRuntime: fake.FakeRuntime, hangUp: hangUp}
	got, err := o.Sleep(reqCtx, sb.ID, false)
	if err != nil || got.Status != model.StatusSleeping {
		t.Fatalf("sleep with the client gone: %v %+v", err, got)
	}
	reqCtx, hangUp = context.WithCancel(context.Background())
	o.Runtime = &ctxRuntime{FakeRuntime: fake.FakeRuntime, hangUp: hangUp}
	got, err = o.Wake(reqCtx, sb.ID)
	if err != nil || got.Status != model.StatusWaking || got.PodName == "" {
		t.Fatalf("wake with the client gone: %v %+v", err, got)
	}
}
