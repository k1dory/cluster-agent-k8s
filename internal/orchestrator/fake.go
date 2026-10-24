package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"agent-sandbox/internal/model"
)

// FakeRuntime pretends pods start instantly. Used by tests and `runtime: fake`.
type FakeRuntime struct {
	mu      sync.Mutex
	pods    map[string]string // sandbox id → ip
	volumes map[string]bool
	next    int
	// FailDelete, when set, makes DeletePod fail (tests of the delete retry path).
	FailDelete error
}

// SetFailDelete toggles DeletePod failures.
func (f *FakeRuntime) SetFailDelete(err error) {
	f.mu.Lock()
	f.FailDelete = err
	f.mu.Unlock()
}

// NewFakeRuntime returns an empty fake.
func NewFakeRuntime() *FakeRuntime {
	return &FakeRuntime{pods: map[string]string{}, volumes: map[string]bool{}}
}

func (f *FakeRuntime) EnsureVolume(_ context.Context, sb *model.Sandbox) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.volumes[sb.ID] = true
	return nil
}

func (f *FakeRuntime) CreatePod(_ context.Context, sb *model.Sandbox) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.volumes[sb.ID] {
		return "", fmt.Errorf("no volume for %s", sb.ID)
	}
	f.next++
	f.pods[sb.ID] = fmt.Sprintf("10.77.77.%d", 10+f.next%110)
	return fmt.Sprintf("agent-%s-%d", sb.Slug, f.next), nil
}

func (f *FakeRuntime) PodStatus(_ context.Context, sb *model.Sandbox) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ip, ok := f.pods[sb.ID]
	if !ok {
		return false, "", errors.New("pod not found")
	}
	return true, ip, nil
}

func (f *FakeRuntime) DeletePod(_ context.Context, sb *model.Sandbox) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailDelete != nil {
		return f.FailDelete
	}
	delete(f.pods, sb.ID)
	return nil
}

func (f *FakeRuntime) DeleteVolume(_ context.Context, sb *model.Sandbox) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.volumes, sb.ID)
	return nil
}
