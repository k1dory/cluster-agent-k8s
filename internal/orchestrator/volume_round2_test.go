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
