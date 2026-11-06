package orchestrator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// lifecycleVolumeFailOnce fails the first EnsureVolume, like a storage class that was briefly unavailable.
type lifecycleVolumeFailOnce struct {
	*FakeRuntime
	mu     sync.Mutex
	failed bool
}

func (r *lifecycleVolumeFailOnce) EnsureVolume(ctx context.Context, sb *model.Sandbox) error {
	r.mu.Lock()
	first := !r.failed
	r.failed = true
	r.mu.Unlock()
	if first {
		return errors.New("storage class unavailable")
	}
	return r.FakeRuntime.EnsureVolume(ctx, sb)
}

// Create stored the sandbox and then failed in EnsureVolume; the API answered with the record
// in error and "wake to retry", but Wake only created a pod, bound to a claim that did not
// exist, and failed the same way on every attempt. Every pod start now ensures the volume.
func TestRound2WakeRecoversAFailedVolume(t *testing.T) {
	ctx := context.Background()
	rt := &lifecycleVolumeFailOnce{FakeRuntime: NewFakeRuntime()}
	o := New(store.NewMemory(), rt, nil, events.New(), Config{ReadyTimeout: 5 * time.Second, StopTimeout: time.Second}, nil)
	sb, err := o.Create(ctx, CreateRequest{Name: "vol", Slug: "dev", Owner: "alice"})
	if !errors.Is(err, ErrRuntime) || sb == nil || sb.Status != model.StatusError {
		t.Fatalf("create with a failing volume: %v %+v", err, sb)
	}
	if _, err := o.Wake(ctx, sb.ID); err != nil {
		t.Fatalf("wake after the volume failure: %v", err)
	}
	got := waitStatus(t, o, sb.ID, model.StatusRunning)
	if _, _, err := rt.PodStatus(ctx, got); err != nil {
		t.Fatalf("pod of the woken sandbox: %v", err)
	}
	rt.FakeRuntime.mu.Lock()
	hasVolume := rt.FakeRuntime.volumes[sb.ID]
	rt.FakeRuntime.mu.Unlock()
	if !hasVolume {
		t.Fatal("woken sandbox has no volume")
	}
}

// lifecycleVolumeGate holds the next EnsureVolume, once armed, until released.
type lifecycleVolumeGate struct {
	*FakeRuntime
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (r *lifecycleVolumeGate) EnsureVolume(ctx context.Context, sb *model.Sandbox) error {
	if r.armed.CompareAndSwap(true, false) {
		close(r.entered)
		<-r.release
	}
	return r.FakeRuntime.EnsureVolume(ctx, sb)
}

// startPod ensured the volume after releasing the tenant lock: a Delete on another replica
// could remove the record and the volume in between, and the wake then created the volume
// again for a record that was gone (the orphan pod was removed, the volume never). Now the
// volume is ensured under the lock markDeleting takes: neither pod nor volume survives.
func TestRound2DeleteDuringWakeLeavesNoVolume(t *testing.T) {
	ctx := context.Background()
	rt := &lifecycleVolumeGate{FakeRuntime: NewFakeRuntime(), entered: make(chan struct{}), release: make(chan struct{})}
	o := New(store.NewMemory(), rt, nil, events.New(), Config{ReadyTimeout: 5 * time.Second, StopTimeout: 5 * time.Second}, nil)
	sb, err := o.Create(ctx, CreateRequest{Name: "vol", Slug: "dev", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, o, sb.ID, model.StatusRunning)
	if _, err := o.Sleep(ctx, sb.ID, true); err != nil {
		t.Fatal(err)
	}
	rt.armed.Store(true)
	woke := make(chan struct{})
	go func() { defer close(woke); _, _ = o.Wake(ctx, sb.ID) }()
	<-rt.entered
	deleted := make(chan error, 1)
	go func() { deleted <- o.Delete(ctx, sb.ID) }()
	var delErr error
	finished := false
	select {
	case delErr = <-deleted: // the old code: the delete ran while the wake was between steps
		finished = true
	case <-time.After(300 * time.Millisecond): // the fix: the delete waits for the wake's lock
	}
	close(rt.release)
	<-woke
	if !finished {
		delErr = <-deleted
	}
	if delErr != nil {
		t.Fatalf("delete: %v", delErr)
	}
	if _, err := o.Store.GetSandbox(ctx, sb.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("record after delete: %v", err)
	}
	rt.FakeRuntime.mu.Lock()
	_, pod := rt.FakeRuntime.pods[sb.ID]
	vol := rt.FakeRuntime.volumes[sb.ID]
	rt.FakeRuntime.mu.Unlock()
	if pod || vol {
		t.Fatalf("after a delete during a wake: pod left %v, volume left %v", pod, vol)
	}
}

// lifecycleLockCommitsWithCaller reports the caller's context error after the lock's callback,
// as Postgres does: the lock is a transaction committed with the caller's context, so a client
// that went away fails the commit after the callback's writes were committed through the pool.
type lifecycleLockCommitsWithCaller struct{ store.Store }

func (s *lifecycleLockCommitsWithCaller) WithTenantLock(ctx context.Context, key string, fn func(context.Context) error) error {
	if err := s.Store.WithTenantLock(ctx, key, fn); err != nil {
		return err
	}
	return ctx.Err()
}

// lifecycleVolumeHook runs hook inside the next EnsureVolume, once armed.
type lifecycleVolumeHook struct {
	*FakeRuntime
	mu   sync.Mutex
	hook func()
}

func (r *lifecycleVolumeHook) EnsureVolume(ctx context.Context, sb *model.Sandbox) error {
	r.mu.Lock()
	hook := r.hook
	r.hook = nil
	r.mu.Unlock()
	if hook != nil {
		hook()
	}
	return r.FakeRuntime.EnsureVolume(ctx, sb)
}

// The client hung up while the wake provisioned the volume: the lock's commit failed with the
// cancelled context and startPod returned before creating the pod, although the move to waking
// was committed. The record stayed waking with nothing behind it (a retried wake took waking for
// success). Now a committed start goes on to the pod on a detached context.
func TestRound2WakeSurvivesAClientGoneDuringTheVolume(t *testing.T) {
	rt := &lifecycleVolumeHook{FakeRuntime: NewFakeRuntime()}
	st := &lifecycleLockCommitsWithCaller{Store: store.NewMemory()}
	o := New(st, rt, nil, events.New(), Config{ReadyTimeout: 5 * time.Second, StopTimeout: 5 * time.Second}, nil)
	sb, err := o.Create(context.Background(), CreateRequest{Name: "vol", Slug: "dev", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, o, sb.ID, model.StatusRunning)
	if _, err := o.Sleep(context.Background(), sb.ID, true); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt.mu.Lock()
	rt.hook = cancel
	rt.mu.Unlock()
	if _, err := o.Wake(ctx, sb.ID); err != nil {
		t.Fatalf("wake whose client went away during the volume: %v", err)
	}
	got := waitStatus(t, o, sb.ID, model.StatusRunning)
	if _, _, err := rt.PodStatus(context.Background(), got); err != nil {
		t.Fatalf("pod of the woken sandbox: %v", err)
	}
}

// lifecycleGetFailsOnce fails the next GetSandbox once armed, like a lookup that timed out.
type lifecycleGetFailsOnce struct {
	store.Store
	armed atomic.Bool
}

func (s *lifecycleGetFailsOnce) GetSandbox(ctx context.Context, id string) (*model.Sandbox, error) {
	if s.armed.CompareAndSwap(true, false) {
		return nil, errors.New("lookup timed out")
	}
	return s.Store.GetSandbox(ctx, id)
}

// A replica with a cold metadata cache whose tenant lookup failed started the pod under the lock
// of tenant "": another replica's Delete, under the real tenant's lock, removed the record and
// the volume while the wake provisioned it, and the volume was created again for a record that
// was gone. The tenant is now read with its error, and a failed read aborts the start.
func TestRound2ColdReplicaDoesNotWakeUnderTheWrongLock(t *testing.T) {
	ctx := context.Background()
	rt := &lifecycleVolumeGate{FakeRuntime: NewFakeRuntime(), entered: make(chan struct{}), release: make(chan struct{})}
	mem := store.NewMemory()
	a := New(mem, rt, nil, events.New(), Config{ReadyTimeout: 5 * time.Second, StopTimeout: 5 * time.Second}, nil)
	sb, err := a.Create(ctx, CreateRequest{Name: "vol", Slug: "dev", Owner: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	waitStatus(t, a, sb.ID, model.StatusRunning)
	if _, err := a.Sleep(ctx, sb.ID, true); err != nil {
		t.Fatal(err)
	}
	// Replica B has never seen the sandbox; its first read of it (the tenant, at the start of
	// startPod, the step a wake runs) fails.
	cold := &lifecycleGetFailsOnce{Store: mem}
	b := New(cold, rt, nil, events.New(), Config{ReadyTimeout: 5 * time.Second, StopTimeout: 5 * time.Second}, nil)
	cold.armed.Store(true)
	rt.armed.Store(true)
	woke := make(chan error, 1)
	go func() { _, err := b.startPod(ctx, sb.ID); woke <- err }()
	var wakeErr error
	paused := false
	select {
	case <-rt.entered: // the old code: provisioning under the lock of tenant ""
		paused = true
	case wakeErr = <-woke:
	}
	deleted := make(chan error, 1)
	go func() { deleted <- a.Delete(ctx, sb.ID) }()
	var delErr error
	if paused {
		finished := false
		select {
		case delErr = <-deleted:
			finished = true
		case <-time.After(300 * time.Millisecond):
		}
		close(rt.release)
		wakeErr = <-woke
		if !finished {
			delErr = <-deleted
		}
	} else {
		delErr = <-deleted
	}
	if delErr != nil {
		t.Fatalf("delete: %v", delErr)
	}
	if wakeErr == nil {
		t.Fatal("a start whose tenant could not be read went ahead")
	}
	rt.FakeRuntime.mu.Lock()
	_, pod := rt.FakeRuntime.pods[sb.ID]
	vol := rt.FakeRuntime.volumes[sb.ID]
	rt.FakeRuntime.mu.Unlock()
	if pod || vol {
		t.Fatalf("after a delete during a cold replica's wake: pod left %v, volume left %v", pod, vol)
	}
}
