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

// createHookRuntime runs during, once, inside CreatePod before the pod exists: another request
// acting on the sandbox while the cluster call is in flight (it finds no pod to delete).
type createHookRuntime struct {
	*FakeRuntime
	during func()
}

func (r *createHookRuntime) CreatePod(ctx context.Context, sb *model.Sandbox) (string, error) {
	if h := r.during; h != nil {
		r.during = nil
		h()
	}
	// The volume went with the delete; the cluster call that was already under way still lands.
	_ = r.FakeRuntime.EnsureVolume(ctx, sb)
	return r.FakeRuntime.CreatePod(ctx, sb)
}

// A Delete that ran while a wake was creating the pod found no pod, removed the volume and the
// record, and the pod created right after ran on with no record behind it. Now the wake sees
// the record gone when it records its pod and removes the pod.
func TestReviewDeleteDuringWakeLeavesNoPod(t *testing.T) {
	o, fake, sb := reviewRunningSandbox(t)
	ctx := context.Background()
	if _, err := o.Sleep(ctx, sb.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fake.PodStatus(ctx, sb); err == nil {
		t.Fatal("pod alive after sleep")
	}
	var delErr error
	o.Runtime = &createHookRuntime{FakeRuntime: fake.FakeRuntime, during: func() { delErr = o.Delete(ctx, sb.ID) }}
	if _, err := o.Wake(ctx, sb.ID); err == nil {
		t.Fatal("wake of a sandbox deleted meanwhile reported success")
	}
	if delErr != nil {
		t.Fatalf("delete during wake: %v", delErr)
	}
	if _, err := o.Store.GetSandbox(ctx, sb.ID); err == nil {
		t.Fatal("record survived the delete")
	}
	if _, _, err := fake.PodStatus(ctx, sb); err == nil {
		t.Fatal("orphan pod left running after wake raced delete")
	}
}

// Delete takes the tenant lock: it cannot interleave with a wake's quota check and status move.
func TestReviewDeleteWaitsForTenantLock(t *testing.T) {
	o, _, sb := reviewRunningSandbox(t)
	ctx := context.Background()
	held, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = o.Store.WithTenantLock(ctx, sb.Tenant, func(context.Context) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	done := make(chan error, 1)
	go func() { done <- o.Delete(ctx, sb.ID) }()
	select {
	case err := <-done:
		t.Fatalf("delete ran while the tenant lock was held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if got, _ := o.Store.GetSandbox(ctx, sb.ID); got == nil || got.Status != model.StatusRunning {
		t.Fatalf("sandbox moved while the lock was held: %+v", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// deleteHookRuntime runs during, once, inside DeletePod: a Delete arriving while a sleep is
// taking the pod down.
type deleteHookRuntime struct {
	*FakeRuntime
	during func()
}

func (r *deleteHookRuntime) DeletePod(ctx context.Context, sb *model.Sandbox) error {
	if h := r.during; h != nil {
		r.during = nil
		h()
	}
	return r.FakeRuntime.DeletePod(ctx, sb)
}

// A sleep finishing after a Delete marked the sandbox deleting wrote sleeping over it; when the
// cluster had refused the delete, the reconciler no longer retried it. The sleep now settles
// only out of stopping.
func TestReviewSleepDoesNotUndoADelete(t *testing.T) {
	o, fake, sb := reviewRunningSandbox(t)
	ctx := context.Background()
	fake.SetFailDelete(nil)
	rt := &deleteHookRuntime{FakeRuntime: fake.FakeRuntime}
	o.Runtime = rt
	rt.during = func() {
		fake.SetFailDelete(errFakeRefused)
		if err := o.Delete(ctx, sb.ID); err == nil {
			t.Error("delete succeeded although the cluster refused it")
		}
		fake.SetFailDelete(nil)
	}
	if _, err := o.Sleep(ctx, sb.ID, false); err == nil {
		t.Fatal("sleep reported success over a delete in progress")
	}
	got, err := o.Store.GetSandbox(ctx, sb.ID)
	if err != nil || got.Status != model.StatusDeleting {
		t.Fatalf("sandbox after sleep raced a refused delete: %v %+v", err, got)
	}
	o.Reconcile(ctx)
	if _, err := o.Store.GetSandbox(ctx, sb.ID); err == nil {
		t.Fatal("the reconciler did not retry the delete")
	}
}

var errFakeRefused = errors.New("cluster refused")
