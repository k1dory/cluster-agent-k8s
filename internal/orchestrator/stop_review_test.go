package orchestrator

import (
	"context"
	"errors"
	"strings"
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

// barrierRuntime removes the pod, then holds DeletePod until release is closed: a slow
// termination during which other replicas keep working.
type barrierRuntime struct {
	*FakeRuntime
	entered chan struct{}
	release chan struct{}
}

func (r *barrierRuntime) DeletePod(ctx context.Context, sb *model.Sandbox) error {
	err := r.FakeRuntime.DeletePod(ctx, sb)
	close(r.entered)
	<-r.release
	return err
}

// Replica A takes over a stuck stop. While its DeletePod is still returning, replica B sees the
// pod gone, settles the sandbox as sleeping and wakes it; a run starts on the replacement pod.
// A's cleanup must not retire that pod's identities or cancel its run: the takeover holds the
// tenant lock every wake takes, so the replacement only starts once the cleanup is over.
func TestReviewStopTakeoverSparesTheReplacement(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRuntime()
	st := store.NewMemory()
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_takeover", Slug: "dev", Tenant: "acme", Name: "t", Owner: "alice", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	if err := fake.EnsureVolume(ctx, sb); err != nil {
		t.Fatal(err)
	}
	sb.PodName, _ = fake.CreatePod(ctx, sb)
	if err := st.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	slow := &barrierRuntime{FakeRuntime: fake, entered: make(chan struct{}), release: make(chan struct{})}
	ret := &podWatchRetirer{rt: fake, sb: sb}
	a := New(st, slow, ret, events.New(), Config{StopTimeout: 20 * time.Millisecond}, nil)
	b := New(st, fake, nil, events.New(), Config{}, nil)
	if _, err := a.CreateRun(ctx, sb.ID, "old"); err != nil {
		t.Fatal(err)
	}
	run1, err := a.NextRun(ctx, sb.ID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.setStatusFrom(ctx, sb.ID, []model.SandboxStatus{model.StatusRunning}, model.StatusStopping, nil); err != nil {
		t.Fatal(err)
	}
	// The old pod's runner reported its result before the pod went away.
	if err := a.FinishRun(ctx, sb.ID, run1.ID, 0, nil); err != nil {
		t.Fatal(err)
	}
	a.Reconcile(ctx)
	time.Sleep(30 * time.Millisecond)
	a.Reconcile(ctx) // takes the stop over
	<-slow.entered   // the old pod is gone, A's cleanup has not run yet

	b.Reconcile(ctx) // sees no pod: sleeping
	woke := make(chan *model.Run, 1)
	go func() {
		if _, err := b.Wake(ctx, sb.ID); err != nil {
			t.Error(err)
			woke <- nil
			return
		}
		waitFor(t, "replacement running", func() bool {
			got, _ := st.GetSandbox(ctx, sb.ID)
			return got.Status == model.StatusRunning
		})
		if _, err := b.CreateRun(ctx, sb.ID, "new"); err != nil {
			t.Error(err)
		}
		r, err := b.NextRun(ctx, sb.ID, time.Second)
		if err != nil {
			t.Error(err)
		}
		woke <- r
	}()
	var run2 *model.Run
	early := false
	select {
	case run2 = <-woke:
		early = true // a replacement started while the old stop was still being cleaned up
	case <-time.After(150 * time.Millisecond):
	}
	close(slow.release)
	if !early {
		select {
		case run2 = <-woke:
		case <-time.After(5 * time.Second):
			t.Fatal("wake never completed")
		}
	}
	if run2 == nil {
		t.FailNow()
	}
	waitFor(t, "takeover to finish", func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return !a.stopping[sb.ID]
	})
	if r, _ := st.GetRun(ctx, run1.ID); r.Status != model.RunDone {
		t.Fatalf("run of the stopped pod: %s", r.Status)
	}
	if ret.calls == 0 || ret.replacementSeen {
		t.Fatalf("identities retired %d times, while a replacement pod was up: %v", ret.calls, ret.replacementSeen)
	}
	if r, _ := st.GetRun(ctx, run2.ID); r.Status != model.RunRunning {
		t.Fatalf("run on the replacement pod was settled by the old stop's cleanup: %s", r.Status)
	}
	if _, _, err := fake.PodStatus(ctx, sb); err != nil {
		t.Fatalf("replacement pod: %v", err)
	}
	if got, _ := st.GetSandbox(ctx, sb.ID); got.Status != model.StatusRunning {
		t.Fatalf("sandbox after the takeover: %s", got.Status)
	}
}

// podWatchRetirer records whether a pod existed when it was asked to retire the sandbox's
// identities: a retire meant for the stopped pod must happen before any replacement exists.
type podWatchRetirer struct {
	rt              *FakeRuntime
	sb              *model.Sandbox
	calls           int
	replacementSeen bool
}

func (r *podWatchRetirer) RetireSandbox(ctx context.Context, id string) error {
	r.calls++
	if _, _, err := r.rt.PodStatus(ctx, r.sb); err == nil {
		r.replacementSeen = true
	}
	return nil
}

// afterCreateRuntime runs during, once, inside CreatePod after the pod exists, before the
// creator gets the result back.
type afterCreateRuntime struct {
	*FakeRuntime
	during func(pod string)
}

func (r *afterCreateRuntime) CreatePod(ctx context.Context, sb *model.Sandbox) (string, error) {
	pod, err := r.FakeRuntime.CreatePod(ctx, sb)
	if h := r.during; h != nil && err == nil {
		r.during = nil
		h(pod)
	}
	return pod, err
}

// The pod bootstraps (naming itself on the record) and another replica's waitReady flips the
// sandbox to running before the creator records its result. That is the start succeeding: the
// creator used to see "not waking", treat its healthy pod as an orphan and delete it.
func TestReviewWakeKeepsAPodThatBecameReadyFirst(t *testing.T) {
	o, fake, sb := reviewRunningSandbox(t)
	ctx := context.Background()
	if _, err := o.Sleep(ctx, sb.ID, false); err != nil {
		t.Fatal(err)
	}
	o.Runtime = &afterCreateRuntime{FakeRuntime: fake.FakeRuntime, during: func(pod string) {
		// Bootstrap, then readiness observed by another replica.
		if _, err := o.mutate(ctx, sb.ID, func(s *model.Sandbox) error { s.PodName = pod; return nil }); err != nil {
			t.Error(err)
		}
		if _, err := o.setStatusFrom(ctx, sb.ID, []model.SandboxStatus{model.StatusWaking}, model.StatusRunning, nil); err != nil {
			t.Error(err)
		}
	}}
	got, err := o.Wake(ctx, sb.ID)
	if err != nil || got.Status != model.StatusRunning {
		t.Fatalf("wake whose pod became ready first: %v %+v", err, got)
	}
	if _, _, err := fake.PodStatus(ctx, sb); err != nil {
		t.Fatalf("the healthy pod was deleted: %v", err)
	}
}

// ctxStore refuses sandbox reads and writes on a done context, as Postgres does (the memory
// store ignores cancellation, which hid this).
type ctxStore struct{ store.Store }

func (s ctxStore) GetSandbox(ctx context.Context, id string) (*model.Sandbox, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.Store.GetSandbox(ctx, id)
}

func (s ctxStore) UpdateSandbox(ctx context.Context, sb *model.Sandbox) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.UpdateSandbox(ctx, sb)
}

// hangRuntime's cluster calls never answer: they return when their context ends.
type hangRuntime struct {
	*FakeRuntime
	beforeCreate func()
}

func (r *hangRuntime) DeletePod(ctx context.Context, _ *model.Sandbox) error {
	<-ctx.Done()
	return ctx.Err()
}

func (r *hangRuntime) CreatePod(ctx context.Context, _ *model.Sandbox) (string, error) {
	if h := r.beforeCreate; h != nil {
		r.beforeCreate = nil
		h()
	}
	<-ctx.Done()
	return "", ctx.Err()
}

// A cluster call that ran out its StopTimeout handed the expired context to fail, so on
// Postgres the error was never recorded and the sandbox sat in stopping or waking. The failure
// is now written on a fresh context, and only over the status the failed operation set.
func TestReviewFailureRecordedAfterTheDeadline(t *testing.T) {
	ctx := context.Background()
	fake := NewFakeRuntime()
	mem := store.NewMemory()
	now := time.Now()
	sb := &model.Sandbox{ID: "sb_deadline", Slug: "dev", Tenant: "acme", Name: "d", Owner: "alice", Status: model.StatusRunning, CreatedAt: now, LastActivity: now}
	_ = fake.EnsureVolume(ctx, sb)
	sb.PodName, _ = fake.CreatePod(ctx, sb)
	if err := mem.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	rt := &hangRuntime{FakeRuntime: fake}
	o := New(ctxStore{mem}, rt, nil, events.New(), Config{StopTimeout: 20 * time.Millisecond}, nil)

	if _, err := o.Sleep(ctx, sb.ID, false); err == nil {
		t.Fatal("sleep whose DeletePod timed out reported success")
	}
	if got, _ := mem.GetSandbox(ctx, sb.ID); got.Status != model.StatusError || !strings.Contains(got.Error, "delete pod") {
		t.Fatalf("after DeletePod ran out its deadline: %s %q", got.Status, got.Error)
	}
	if _, err := o.Wake(ctx, sb.ID); err == nil {
		t.Fatal("wake whose CreatePod timed out reported success")
	}
	if got, _ := mem.GetSandbox(ctx, sb.ID); got.Status != model.StatusError || !strings.Contains(got.Error, "pod: ") {
		t.Fatalf("after CreatePod ran out its deadline: %s %q", got.Status, got.Error)
	}

	// A delete the cluster refuses lands while the create hangs: the create's failure must not
	// write error over deleting (the delete's retry depends on it).
	fake.SetFailDelete(errFakeRefused)
	o2 := New(ctxStore{mem}, fake, nil, events.New(), Config{}, nil)
	rt.beforeCreate = func() { _ = o2.Delete(ctx, sb.ID) }
	if _, err := o.Wake(ctx, sb.ID); err == nil {
		t.Fatal("wake of a sandbox being deleted reported success")
	}
	if got, _ := mem.GetSandbox(ctx, sb.ID); got.Status != model.StatusDeleting {
		t.Fatalf("a failed create overwrote the delete: %s %q", got.Status, got.Error)
	}
}
