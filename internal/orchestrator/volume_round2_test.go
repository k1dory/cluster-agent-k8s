package orchestrator

import (
	"context"
	"errors"
	"sync"
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
