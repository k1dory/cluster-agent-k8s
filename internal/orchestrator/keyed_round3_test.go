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

// Review round 3 of #32, finding 2: the recovery of a keyed create that never got to its pod
// provisioned the volume on its own, outside the tenant lock: a Delete on another replica
// could finish in between, and the volume was created again for a record that was gone. It
// now goes through startPod, which ensures the volume under the lock markDeleting takes.
func TestRound3RecoveredCreateRacingADeleteLeavesNoVolume(t *testing.T) {
	ctx := context.Background()
	rt := &lifecycleVolumeGate{FakeRuntime: NewFakeRuntime(), entered: make(chan struct{}), release: make(chan struct{})}
	o := New(store.NewMemory(), rt, nil, events.New(), Config{ReadyTimeout: 5 * time.Second, StopTimeout: 5 * time.Second}, nil)
	// What an attempt that died right after its insert leaves: the record, creating, nothing else.
	now := time.Now()
	sb := &model.Sandbox{ID: KeyedID("seed-round3", "sb"), Name: "vol", Slug: "dev", Owner: "alice", Tenant: "alice",
		Status: model.StatusCreating, LastActivity: now, CreatedAt: now}
	if err := o.Store.CreateSandbox(ctx, sb); err != nil {
		t.Fatal(err)
	}
	rt.armed.Store(true)
	resumed := make(chan struct{})
	go func() { defer close(resumed); _, _ = o.ResumeKeyedCreate(ctx, sb) }()
	<-rt.entered
	deleted := make(chan error, 1)
	go func() { deleted <- o.Delete(ctx, sb.ID) }()
	var delErr error
	finished := false
	select {
	case delErr = <-deleted: // the delete ran while the recovery provisioned the volume
		finished = true
	case <-time.After(300 * time.Millisecond): // the delete waits for the start's lock
	}
	close(rt.release)
	<-resumed
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
		t.Fatalf("after a delete during the recovery: pod left %v, volume left %v", pod, vol)
	}
}
