package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	// DeleteDelay makes DeletePod take this long, like Kubernetes' graceful termination.
	DeleteDelay time.Duration
	// Launches remembers the launch each sandbox's latest pod was created with (tests).
	Launches map[string]*model.Launch
}

// LaunchOf returns the launch the sandbox's latest pod was created with (nil = defaults).
func (f *FakeRuntime) LaunchOf(sandboxID string) *model.Launch {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Launches[sandboxID]
}

// LosePod makes the runtime forget a pod (eviction, node loss) without DeletePod being called.
func (f *FakeRuntime) LosePod(sandboxID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.pods, sandboxID)
}

// SetFailDelete toggles DeletePod failures.
func (f *FakeRuntime) SetFailDelete(err error) {
	f.mu.Lock()
	f.FailDelete = err
	f.mu.Unlock()
}

// NewFakeRuntime returns an empty fake.
func NewFakeRuntime() *FakeRuntime {
	return &FakeRuntime{pods: map[string]string{}, volumes: map[string]bool{}, Launches: map[string]*model.Launch{}}
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
	f.Launches[sb.ID] = sb.Launch
	f.pods[sb.ID] = fmt.Sprintf("10.77.77.%d", 10+f.next%110)
	return fmt.Sprintf("agent-%s-%d", sb.Slug, f.next), nil
}

func (f *FakeRuntime) PodStatus(_ context.Context, sb *model.Sandbox) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ip, ok := f.pods[sb.ID]
	if !ok {
		return false, "", ErrPodNotFound
	}
	return true, ip, nil
}

func (f *FakeRuntime) DeletePod(_ context.Context, sb *model.Sandbox) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailDelete != nil {
		return f.FailDelete
	}
	if f.DeleteDelay > 0 {
		f.mu.Unlock()
		time.Sleep(f.DeleteDelay)
		f.mu.Lock()
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
