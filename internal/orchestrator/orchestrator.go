// Package orchestrator owns the sandbox lifecycle: create, run tasks, sleep when idle,
// wake on demand, delete. It talks to Kubernetes through the Runtime interface so the
// same logic runs against a fake runtime in tests and local development.
package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Runtime creates and destroys the pod and volume behind a sandbox.
type Runtime interface {
	// EnsureVolume creates the sandbox's persistent volume claim if missing.
	EnsureVolume(ctx context.Context, sb *model.Sandbox) error
	// CreatePod starts a pod on the volume and returns its name.
	CreatePod(ctx context.Context, sb *model.Sandbox) (string, error)
	// PodStatus reports whether the pod is ready and its IP (empty until assigned).
	PodStatus(ctx context.Context, sb *model.Sandbox) (ready bool, ip string, err error)
	// DeletePod removes the pod; the volume stays.
	DeletePod(ctx context.Context, sb *model.Sandbox) error
	// DeleteVolume removes the volume.
	DeleteVolume(ctx context.Context, sb *model.Sandbox) error
}

// Retirer invalidates issued identities when a pod goes away (the Registrar).
type Retirer interface {
	RetireSandbox(ctx context.Context, sandboxID string) error
}

// Config tunes the orchestrator.
type Config struct {
	DefaultIdleTimeout time.Duration // 0 → 1h
	PreviewDomain      string        // e.g. preview.example.com
	ReadyTimeout       time.Duration // how long a wake may take before marking error
	IdleCheckEvery     time.Duration
}

// Orchestrator is the sandbox lifecycle manager.
type Orchestrator struct {
	Store   store.Store
	Runtime Runtime
	Retirer Retirer
	Hub     *events.Hub
	Cfg     Config
	Log     *slog.Logger

	mu     sync.Mutex
	waking map[string]bool
}

// New wires an orchestrator.
func New(st store.Store, rt Runtime, ret Retirer, hub *events.Hub, cfg Config, log *slog.Logger) *Orchestrator {
	if cfg.DefaultIdleTimeout == 0 {
		cfg.DefaultIdleTimeout = time.Hour
	}
	if cfg.ReadyTimeout == 0 {
		cfg.ReadyTimeout = 3 * time.Minute
	}
	if cfg.IdleCheckEvery == 0 {
		cfg.IdleCheckEvery = time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &Orchestrator{Store: st, Runtime: rt, Retirer: ret, Hub: hub, Cfg: cfg, Log: log, waking: map[string]bool{}}
}

// Errors surfaced to the API.
var (
	ErrBadRequest = errors.New("bad request")
	ErrConflict   = errors.New("conflict")
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// CreateRequest is the input of POST /sandboxes.
type CreateRequest struct {
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	Owner         string `json:"owner"`
	Tenant        string `json:"tenant"`
	Repo          string `json:"repo"`
	IdleTimeout   *int   `json:"idle_timeout,omitempty"`
	WakeOnPreview *bool  `json:"wake_on_preview,omitempty"`
}

func newID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// Create registers a sandbox, provisions its volume and starts the first pod.
func (o *Orchestrator) Create(ctx context.Context, req CreateRequest) (*model.Sandbox, error) {
	if !slugRe.MatchString(req.Slug) {
		return nil, fmt.Errorf("%w: slug must match %s", ErrBadRequest, slugRe)
	}
	if !slugRe.MatchString(req.Name) {
		return nil, fmt.Errorf("%w: name must match %s", ErrBadRequest, slugRe)
	}
	if req.Owner == "" {
		return nil, fmt.Errorf("%w: owner is required", ErrBadRequest)
	}
	if req.Tenant == "" {
		req.Tenant = req.Owner
	}
	now := time.Now()
	sb := &model.Sandbox{
		ID: newID("sb"), Name: req.Name, Slug: req.Slug, Owner: req.Owner, Tenant: req.Tenant, Repo: req.Repo,
		IdleTimeout: int(o.Cfg.DefaultIdleTimeout.Seconds()), WakeOnPreview: true,
		Status: model.StatusCreating, LastActivity: now, CreatedAt: now,
	}
	if req.IdleTimeout != nil {
		if *req.IdleTimeout < 0 {
			return nil, fmt.Errorf("%w: idle_timeout must be >= 0", ErrBadRequest)
		}
		sb.IdleTimeout = *req.IdleTimeout
	}
	if req.WakeOnPreview != nil {
		sb.WakeOnPreview = *req.WakeOnPreview
	}
	if err := o.Store.CreateSandbox(ctx, sb); err != nil {
		return nil, err
	}
	if err := o.Runtime.EnsureVolume(ctx, sb); err != nil {
		o.fail(ctx, sb, "volume: "+err.Error())
		return sb, err
	}
	if err := o.startPod(ctx, sb); err != nil {
		return sb, err
	}
	return sb, nil
}

func (o *Orchestrator) startPod(ctx context.Context, sb *model.Sandbox) error {
	pod, err := o.Runtime.CreatePod(ctx, sb)
	if err != nil {
		o.fail(ctx, sb, "pod: "+err.Error())
		return err
	}
	sb.PodName = pod
	sb.IP = ""
	o.setStatus(ctx, sb, model.StatusWaking)
	go o.waitReady(sb.ID)
	return nil
}

// waitReady polls the runtime until the pod is ready, then flips the status to running.
func (o *Orchestrator) waitReady(id string) {
	o.mu.Lock()
	if o.waking[id] {
		o.mu.Unlock()
		return
	}
	o.waking[id] = true
	o.mu.Unlock()
	defer func() { o.mu.Lock(); delete(o.waking, id); o.mu.Unlock() }()

	ctx, cancel := context.WithTimeout(context.Background(), o.Cfg.ReadyTimeout)
	defer cancel()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		sb, err := o.Store.GetSandbox(ctx, id)
		if err != nil || sb.Status != model.StatusWaking {
			return
		}
		ready, ip, err := o.Runtime.PodStatus(ctx, sb)
		if err != nil {
			o.fail(ctx, sb, "pod status: "+err.Error())
			return
		}
		if ip != "" && ip != sb.IP {
			sb.IP = ip
			_ = o.Store.UpdateSandbox(ctx, sb)
		}
		if ready {
			sb.IP = ip
			o.setStatus(ctx, sb, model.StatusRunning)
			return
		}
		select {
		case <-ctx.Done():
			o.fail(context.Background(), sb, "pod did not become ready within "+o.Cfg.ReadyTimeout.String())
			return
		case <-t.C:
		}
	}
}

func (o *Orchestrator) setStatus(ctx context.Context, sb *model.Sandbox, st model.SandboxStatus) {
	sb.Status = st
	if st != model.StatusError {
		sb.Error = ""
	}
	if err := o.Store.UpdateSandbox(ctx, sb); err != nil {
		o.Log.Error("update sandbox", "id", sb.ID, "err", err)
	}
	o.emit(ctx, model.Event{SandboxID: sb.ID, Type: model.EventStatus, Data: string(st)})
	o.Log.Info("sandbox status", "id", sb.ID, "slug", sb.Slug, "status", st, "pod", sb.PodName, "ip", sb.IP)
}

func (o *Orchestrator) fail(ctx context.Context, sb *model.Sandbox, msg string) {
	sb.Error = msg
	o.Log.Error("sandbox error", "id", sb.ID, "err", msg)
	o.setStatus(ctx, sb, model.StatusError)
}

func (o *Orchestrator) emit(ctx context.Context, e model.Event) {
	if err := o.Store.AppendEvent(ctx, &e); err != nil {
		o.Log.Error("append event", "err", err)
	}
	if o.Hub != nil {
		o.Hub.Publish(e)
	}
}

// Get returns one sandbox.
func (o *Orchestrator) Get(ctx context.Context, id string) (*model.Sandbox, error) {
	return o.Store.GetSandbox(ctx, id)
}

// List returns all sandboxes.
func (o *Orchestrator) List(ctx context.Context) ([]*model.Sandbox, error) {
	return o.Store.ListSandboxes(ctx)
}

// Touch records user activity, postponing sleep.
func (o *Orchestrator) Touch(ctx context.Context, id string) {
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return
	}
	sb.LastActivity = time.Now()
	_ = o.Store.UpdateSandbox(ctx, sb)
}

// Sleep deletes the pod and keeps the volume. Running work is not interrupted unless force.
func (o *Orchestrator) Sleep(ctx context.Context, id string, force bool) (*model.Sandbox, error) {
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return nil, err
	}
	switch sb.Status {
	case model.StatusSleeping:
		return sb, nil
	case model.StatusCreating, model.StatusStopping:
		return nil, fmt.Errorf("%w: sandbox is %s", ErrConflict, sb.Status)
	}
	if !force {
		if _, err := o.Store.RunningRun(ctx, id); err == nil {
			return nil, fmt.Errorf("%w: a run is in progress", ErrConflict)
		}
	}
	o.setStatus(ctx, sb, model.StatusStopping)
	if err := o.Runtime.DeletePod(ctx, sb); err != nil {
		o.fail(ctx, sb, "delete pod: "+err.Error())
		return nil, err
	}
	if o.Retirer != nil {
		if err := o.Retirer.RetireSandbox(ctx, sb.ID); err != nil {
			o.Log.Error("retire identities", "id", sb.ID, "err", err)
		}
	}
	if r, err := o.Store.RunningRun(ctx, id); err == nil {
		now := time.Now()
		r.Status, r.FinishedAt = model.RunCancelled, &now
		_ = o.Store.UpdateRun(ctx, r)
		o.emit(ctx, model.Event{SandboxID: id, RunID: r.ID, Type: model.EventRunDone, Data: string(model.RunCancelled)})
	}
	sb.PodName, sb.IP = "", ""
	o.setStatus(ctx, sb, model.StatusSleeping)
	return sb, nil
}

// Wake starts a pod for a sleeping sandbox. Idempotent for waking/running.
func (o *Orchestrator) Wake(ctx context.Context, id string) (*model.Sandbox, error) {
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return nil, err
	}
	sb.LastActivity = time.Now()
	switch sb.Status {
	case model.StatusRunning, model.StatusWaking:
		_ = o.Store.UpdateSandbox(ctx, sb)
		return sb, nil
	case model.StatusSleeping, model.StatusError:
		if err := o.startPod(ctx, sb); err != nil {
			return nil, err
		}
		return sb, nil
	default:
		return nil, fmt.Errorf("%w: sandbox is %s", ErrConflict, sb.Status)
	}
}

// Delete stops the pod and removes the volume and records.
func (o *Orchestrator) Delete(ctx context.Context, id string) error {
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return err
	}
	o.setStatus(ctx, sb, model.StatusStopping)
	if err := o.Runtime.DeletePod(ctx, sb); err != nil {
		o.Log.Error("delete pod", "id", id, "err", err)
	}
	if o.Retirer != nil {
		_ = o.Retirer.RetireSandbox(ctx, sb.ID)
	}
	if err := o.Runtime.DeleteVolume(ctx, sb); err != nil {
		o.Log.Error("delete volume", "id", id, "err", err)
	}
	return o.Store.DeleteSandbox(ctx, id)
}

// CreateRun queues a task and wakes the sandbox if needed.
func (o *Orchestrator) CreateRun(ctx context.Context, sandboxID, task string) (*model.Run, error) {
	if strings.TrimSpace(task) == "" {
		return nil, fmt.Errorf("%w: task is required", ErrBadRequest)
	}
	sb, err := o.Store.GetSandbox(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	r := &model.Run{ID: newID("run"), SandboxID: sandboxID, Task: task, Status: model.RunQueued, CreatedAt: time.Now()}
	if err := o.Store.CreateRun(ctx, r); err != nil {
		return nil, err
	}
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: r.ID, Type: model.EventRunQueued})
	sb.LastActivity = time.Now()
	if sb.Status == model.StatusSleeping || sb.Status == model.StatusError {
		if _, err := o.Wake(ctx, sandboxID); err != nil {
			return r, err
		}
	} else {
		_ = o.Store.UpdateSandbox(ctx, sb)
	}
	return r, nil
}

// Input forwards a user message to the running agent as an event.
func (o *Orchestrator) Input(ctx context.Context, sandboxID, runID, text string) error {
	if _, err := o.Store.GetSandbox(ctx, sandboxID); err != nil {
		return err
	}
	o.Touch(ctx, sandboxID)
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventInput, Data: text})
	return nil
}

// NextRun long-polls for a queued run (agent side) and marks it running.
func (o *Orchestrator) NextRun(ctx context.Context, sandboxID string, wait time.Duration) (*model.Run, error) {
	deadline := time.Now().Add(wait)
	for {
		r, err := o.Store.NextQueuedRun(ctx, sandboxID)
		if err == nil {
			now := time.Now()
			r.Status, r.StartedAt = model.RunRunning, &now
			if err := o.Store.UpdateRun(ctx, r); err != nil {
				return nil, err
			}
			o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: r.ID, Type: model.EventRunStart})
			return r, nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, store.ErrNotFound
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Output appends agent output to the event stream.
func (o *Orchestrator) Output(ctx context.Context, sandboxID, runID, data string) {
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventRunOutput, Data: data})
}

// FinishRun records the result of a run.
func (o *Orchestrator) FinishRun(ctx context.Context, sandboxID, runID string, exitCode int) error {
	r, err := o.Store.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if r.SandboxID != sandboxID {
		return store.ErrNotFound
	}
	if r.Status == model.RunCancelled {
		return nil
	}
	now := time.Now()
	r.FinishedAt, r.ExitCode = &now, exitCode
	r.Status = model.RunDone
	if exitCode != 0 {
		r.Status = model.RunFailed
	}
	if err := o.Store.UpdateRun(ctx, r); err != nil {
		return err
	}
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventRunDone, Data: string(r.Status)})
	return nil
}

// CancelRun stops a queued or running run. A running run is cancelled by telling the agent
// through an input event ("\x04" end-of-input marker) and marking the run; the runner exits the harness.
func (o *Orchestrator) CancelRun(ctx context.Context, sandboxID, runID string) (*model.Run, error) {
	r, err := o.Store.GetRun(ctx, runID)
	if err != nil || r.SandboxID != sandboxID {
		return nil, store.ErrNotFound
	}
	switch r.Status {
	case model.RunDone, model.RunFailed, model.RunCancelled:
		return r, nil
	}
	now := time.Now()
	r.Status, r.FinishedAt = model.RunCancelled, &now
	if err := o.Store.UpdateRun(ctx, r); err != nil {
		return nil, err
	}
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventRunCancel})
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventRunDone, Data: string(model.RunCancelled)})
	return r, nil
}

// SetPreview exposes a port of the sandbox under a stable host name.
func (o *Orchestrator) SetPreview(ctx context.Context, id string, port int, access string) (*model.Sandbox, error) {
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return nil, err
	}
	if port == 0 {
		sb.Preview = nil
		return sb, o.Store.UpdateSandbox(ctx, sb)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("%w: port out of range", ErrBadRequest)
	}
	switch access {
	case "":
		access = model.AccessMembers
	case model.AccessLink, model.AccessSSO, model.AccessMembers:
	default:
		return nil, fmt.Errorf("%w: access must be link, sso or members", ErrBadRequest)
	}
	sb.Preview = &model.Preview{Port: port, Access: access, Host: o.PreviewHost(sb)}
	return sb, o.Store.UpdateSandbox(ctx, sb)
}

// PreviewHost is <name>-<owner>.<domain>.
func (o *Orchestrator) PreviewHost(sb *model.Sandbox) string {
	owner := strings.ToLower(regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(strings.ToLower(sb.Owner), "-"))
	return fmt.Sprintf("%s-%s.%s", sb.Name, owner, o.Cfg.PreviewDomain)
}

// IdleLoop sleeps sandboxes whose idle timeout elapsed without user activity.
// A sandbox in the middle of a run is left alone until the run ends.
func (o *Orchestrator) IdleLoop(ctx context.Context) {
	t := time.NewTicker(o.Cfg.IdleCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			o.sweepIdle(ctx)
		}
	}
}

func (o *Orchestrator) sweepIdle(ctx context.Context) {
	sbs, err := o.Store.ListSandboxes(ctx)
	if err != nil {
		o.Log.Error("idle sweep", "err", err)
		return
	}
	now := time.Now()
	for _, sb := range sbs {
		if sb.Status != model.StatusRunning || sb.IdleTimeout == 0 {
			continue
		}
		if now.Sub(sb.LastActivity) < sb.IdleDuration() {
			continue
		}
		if _, err := o.Store.RunningRun(ctx, sb.ID); err == nil {
			continue
		}
		o.Log.Info("idle timeout, sleeping", "id", sb.ID, "slug", sb.Slug, "idle", now.Sub(sb.LastActivity).Round(time.Second))
		if _, err := o.Sleep(ctx, sb.ID, false); err != nil {
			o.Log.Error("idle sleep", "id", sb.ID, "err", err)
		}
	}
}
