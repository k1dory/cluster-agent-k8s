// Package orchestrator owns the sandbox lifecycle: create, run tasks, sleep when idle,
// wake on demand, delete. It talks to Kubernetes through the Runtime interface so the
// same logic runs against a fake runtime in tests and local development.
package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/harness"
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

// Quota bounds what one tenant may hold. Zero means unlimited.
type Quota struct {
	MaxSandboxes int `yaml:"max_sandboxes" json:"max_sandboxes"` // records, awake or asleep
	MaxAwake     int `yaml:"max_awake" json:"max_awake"`         // pods at once (creating, waking, running)
}

// Config tunes the orchestrator.
type Config struct {
	DefaultIdleTimeout time.Duration // 0 → 1h
	PreviewDomain      string        // e.g. preview.example.com
	ReadyTimeout       time.Duration // how long a wake may take before marking error
	IdleCheckEvery     time.Duration
	DefaultQuota       Quota
	Quotas             map[string]Quota // per tenant, overrides DefaultQuota
}

// QuotaFor returns the quota that applies to a tenant.
func (c Config) QuotaFor(tenant string) Quota {
	if q, ok := c.Quotas[tenant]; ok {
		return q
	}
	return c.DefaultQuota
}

// Orchestrator is the sandbox lifecycle manager.
type Orchestrator struct {
	Store   store.Store
	Runtime Runtime
	Retirer Retirer
	Hub     *events.Hub
	Cfg     Config
	Log     *slog.Logger

	mu      sync.Mutex
	waking  map[string]bool
	meta    map[string]sbMeta      // sandbox id → tenant/slug, for stamping events
	running map[string]string      // sandbox id → running run id ("" = none), for egress attribution
	tenants map[string]*sync.Mutex // serialises quota check + allocation per tenant
}

// tenantLock returns the mutex that guards quota decisions of one tenant.
func (o *Orchestrator) tenantLock(tenant string) *sync.Mutex {
	o.mu.Lock()
	defer o.mu.Unlock()
	m, ok := o.tenants[tenant]
	if !ok {
		m = &sync.Mutex{}
		o.tenants[tenant] = m
	}
	return m
}

type sbMeta struct{ tenant, slug string }

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
	return &Orchestrator{Store: st, Runtime: rt, Retirer: ret, Hub: hub, Cfg: cfg, Log: log,
		waking: map[string]bool{}, meta: map[string]sbMeta{}, running: map[string]string{}, tenants: map[string]*sync.Mutex{}}
}

// Errors surfaced to the API.
var (
	ErrBadRequest = errors.New("bad request")
	ErrConflict   = errors.New("conflict")
	ErrQuota      = errors.New("quota exceeded")
	ErrRuntime    = errors.New("runtime") // the cluster refused or failed; retry later
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
	TTL           *int   `json:"ttl,omitempty"` // seconds until the sandbox is deleted; 0/absent = keep
}

// UpdateRequest is the input of PATCH /sandboxes/{id}; nil fields are left alone.
type UpdateRequest struct {
	Repo          *string `json:"repo,omitempty"`
	IdleTimeout   *int    `json:"idle_timeout,omitempty"`
	WakeOnPreview *bool   `json:"wake_on_preview,omitempty"`
	TTL           *int    `json:"ttl,omitempty"` // seconds from now; 0 removes the expiry
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
	if req.TTL != nil {
		if *req.TTL < 0 {
			return nil, fmt.Errorf("%w: ttl must be >= 0", ErrBadRequest)
		}
		if *req.TTL > 0 {
			t := now.Add(time.Duration(*req.TTL) * time.Second)
			sb.ExpiresAt = &t
		}
	}
	// Quota check and record creation under the tenant lock: two concurrent creates cannot
	// both see the last free slot.
	lock := o.tenantLock(sb.Tenant)
	lock.Lock()
	err := o.checkQuota(ctx, sb.Tenant, true)
	if err == nil {
		err = o.Store.CreateSandbox(ctx, sb)
	}
	lock.Unlock()
	if err != nil {
		return nil, err
	}
	o.remember(sb)
	if err := o.Runtime.EnsureVolume(ctx, sb); err != nil {
		o.fail(ctx, sb, "volume: "+err.Error())
		return sb, fmt.Errorf("%w: volume: %v", ErrRuntime, err)
	}
	if err := o.startPod(ctx, sb); err != nil {
		return sb, err
	}
	return sb, nil
}

// checkQuota enforces the tenant's limits before a new record (newRecord) or a new pod.
func (o *Orchestrator) checkQuota(ctx context.Context, tenant string, newRecord bool) error {
	q := o.Cfg.QuotaFor(tenant)
	if q.MaxSandboxes == 0 && q.MaxAwake == 0 {
		return nil
	}
	c, err := o.Store.CountSandboxes(ctx, tenant)
	if err != nil {
		return err
	}
	if newRecord && q.MaxSandboxes > 0 && c.Total >= q.MaxSandboxes {
		return fmt.Errorf("%w: tenant %s already has %d sandboxes (max_sandboxes=%d)", ErrQuota, tenant, c.Total, q.MaxSandboxes)
	}
	if q.MaxAwake > 0 && c.Awake >= q.MaxAwake {
		return fmt.Errorf("%w: tenant %s already has %d sandboxes awake (max_awake=%d)", ErrQuota, tenant, c.Awake, q.MaxAwake)
	}
	return nil
}

// startPod checks the awake quota and creates the pod under the tenant lock, so the status
// flip to waking (which the next check counts) happens before another wake is evaluated.
func (o *Orchestrator) startPod(ctx context.Context, sb *model.Sandbox) error {
	lock := o.tenantLock(sb.Tenant)
	lock.Lock()
	defer lock.Unlock()
	if sb.Status != model.StatusCreating {
		if err := o.checkQuota(ctx, sb.Tenant, false); err != nil {
			return err
		}
	}
	pod, err := o.Runtime.CreatePod(ctx, sb)
	if err != nil {
		o.fail(ctx, sb, "pod: "+err.Error())
		return fmt.Errorf("%w: pod: %v", ErrRuntime, err)
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

func (o *Orchestrator) remember(sb *model.Sandbox) {
	o.mu.Lock()
	o.meta[sb.ID] = sbMeta{sb.Tenant, sb.Slug}
	o.mu.Unlock()
}

// metaOf returns the tenant and slug of a sandbox, from cache or the store.
func (o *Orchestrator) metaOf(ctx context.Context, id string) sbMeta {
	o.mu.Lock()
	m, ok := o.meta[id]
	o.mu.Unlock()
	if ok {
		return m
	}
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return sbMeta{}
	}
	o.remember(sb)
	return sbMeta{sb.Tenant, sb.Slug}
}

// setRunning records which run is executing in a sandbox (for attributing egress).
func (o *Orchestrator) setRunning(sandboxID, runID string) {
	o.mu.Lock()
	o.running[sandboxID] = runID
	o.mu.Unlock()
}

// runningRunID returns the executing run of a sandbox, or "" if none.
func (o *Orchestrator) runningRunID(ctx context.Context, sandboxID string) string {
	o.mu.Lock()
	id, ok := o.running[sandboxID]
	o.mu.Unlock()
	if ok {
		return id
	}
	id = ""
	if r, err := o.Store.RunningRun(ctx, sandboxID); err == nil {
		id = r.ID
	}
	o.setRunning(sandboxID, id)
	return id
}

func (o *Orchestrator) emit(ctx context.Context, e model.Event) error {
	if e.Tenant == "" && e.Slug == "" {
		m := o.metaOf(ctx, e.SandboxID)
		e.Tenant, e.Slug = m.tenant, m.slug
	}
	if err := o.Store.AppendEvent(ctx, &e); err != nil {
		o.Log.Error("append event", "err", err)
		return err
	}
	if o.Hub != nil {
		o.Hub.Publish(e)
	}
	return nil
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

// Update changes the mutable settings of a sandbox.
func (o *Orchestrator) Update(ctx context.Context, id string, req UpdateRequest) (*model.Sandbox, error) {
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return nil, err
	}
	if sb.Status == model.StatusDeleting {
		return nil, fmt.Errorf("%w: sandbox is being deleted", ErrConflict)
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
	if req.Repo != nil {
		sb.Repo = *req.Repo
	}
	if req.TTL != nil {
		switch {
		case *req.TTL < 0:
			return nil, fmt.Errorf("%w: ttl must be >= 0", ErrBadRequest)
		case *req.TTL == 0:
			sb.ExpiresAt = nil
		default:
			t := time.Now().Add(time.Duration(*req.TTL) * time.Second)
			sb.ExpiresAt = &t
		}
	}
	return sb, o.Store.UpdateSandbox(ctx, sb)
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
	case model.StatusCreating, model.StatusStopping, model.StatusDeleting:
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
		return nil, fmt.Errorf("%w: delete pod: %v", ErrRuntime, err)
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
	o.setRunning(id, "")
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

// Delete stops the pod, removes the volume and then the record. If the cluster refuses, the
// record stays in status `deleting` with the error attached; the sweeper and a repeated
// DELETE retry it, so nothing is silently left behind.
func (o *Orchestrator) Delete(ctx context.Context, id string) error {
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return err
	}
	if sb.Status != model.StatusDeleting {
		o.setStatus(ctx, sb, model.StatusDeleting)
	}
	if o.Retirer != nil {
		_ = o.Retirer.RetireSandbox(ctx, sb.ID)
	}
	if err := o.Runtime.DeletePod(ctx, sb); err != nil {
		sb.Error = "delete pod: " + err.Error()
		_ = o.Store.UpdateSandbox(ctx, sb)
		return fmt.Errorf("%w: delete pod: %v", ErrRuntime, err)
	}
	if err := o.Runtime.DeleteVolume(ctx, sb); err != nil {
		sb.Error = "delete volume: " + err.Error()
		_ = o.Store.UpdateSandbox(ctx, sb)
		return fmt.Errorf("%w: delete volume: %v", ErrRuntime, err)
	}
	if r, err := o.Store.RunningRun(ctx, id); err == nil {
		now := time.Now()
		r.Status, r.FinishedAt = model.RunCancelled, &now
		_ = o.Store.UpdateRun(ctx, r)
		o.emit(ctx, model.Event{SandboxID: id, RunID: r.ID, Type: model.EventRunDone, Data: string(model.RunCancelled)})
	}
	err = o.Store.DeleteSandbox(ctx, id)
	o.mu.Lock()
	delete(o.meta, id)
	delete(o.running, id)
	o.mu.Unlock()
	return err
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
	if sb.Status == model.StatusDeleting {
		return nil, fmt.Errorf("%w: sandbox is being deleted", ErrConflict)
	}
	r := &model.Run{ID: newID("run"), SandboxID: sandboxID, Tenant: sb.Tenant, Slug: sb.Slug, Task: task, Status: model.RunQueued, CreatedAt: time.Now()}
	if err := o.Store.CreateRun(ctx, r); err != nil {
		return nil, err
	}
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: r.ID, Type: model.EventRunQueued})
	sb.LastActivity = time.Now()
	if sb.Status == model.StatusSleeping || sb.Status == model.StatusError {
		// The run is queued either way; a failed wake shows in the sandbox status and the run
		// starts on the next successful wake. The caller still gets the run it created.
		if _, err := o.Wake(ctx, sandboxID); err != nil {
			o.Log.Warn("wake for run failed", "sandbox", sandboxID, "run", r.ID, "err", err)
		}
	} else {
		_ = o.Store.UpdateSandbox(ctx, sb)
	}
	return r, nil
}

// Input forwards a user message to the agent. The run must exist in this sandbox and still be
// queued or running; otherwise the client would get a false "delivered".
func (o *Orchestrator) Input(ctx context.Context, sandboxID, runID, text string) error {
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("%w: text is required", ErrBadRequest)
	}
	if _, err := o.Store.GetSandbox(ctx, sandboxID); err != nil {
		return err
	}
	r, err := o.Store.GetRun(ctx, runID)
	if err != nil || r.SandboxID != sandboxID {
		return fmt.Errorf("run %s: %w", runID, store.ErrNotFound)
	}
	switch r.Status {
	case model.RunQueued, model.RunRunning:
	default:
		return fmt.Errorf("%w: run is %s", ErrConflict, r.Status)
	}
	o.Touch(ctx, sandboxID)
	return o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventInput, Data: text})
}

// NextRun long-polls for a queued run (agent side) and marks it running.
func (o *Orchestrator) NextRun(ctx context.Context, sandboxID string, wait time.Duration) (*model.Run, error) {
	deadline := time.Now().Add(wait)
	for {
		r, err := o.Store.ClaimQueuedRun(ctx, sandboxID, time.Now())
		if err == nil {
			o.setRunning(sandboxID, r.ID)
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

// Output appends agent output to the event stream. Lines that carry usage (Claude Code's
// result line, generic `{"type":"usage"}` records) also update the run's accounting.
func (o *Orchestrator) Output(ctx context.Context, sandboxID, runID, data string) error {
	if err := o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventRunOutput, Data: data}); err != nil {
		return err
	}
	if u, mode, ok := harness.ParseUsage(data); ok {
		if err := o.applyUsage(ctx, sandboxID, runID, u, mode == harness.Total); err != nil {
			o.Log.Warn("record usage", "run", runID, "err", err)
		}
	}
	return nil
}

func (o *Orchestrator) applyUsage(ctx context.Context, sandboxID, runID string, u model.Usage, replace bool) error {
	r, err := o.Store.GetRun(ctx, runID)
	if err != nil || r.SandboxID != sandboxID {
		return store.ErrNotFound
	}
	if replace {
		r.Usage = u
	} else {
		r.Usage.Add(u)
	}
	return o.Store.UpdateRun(ctx, r)
}

// FinishRun records the result of a run. usage, if given, is the harness's own total and
// overrides whatever was parsed from the output stream.
func (o *Orchestrator) FinishRun(ctx context.Context, sandboxID, runID string, exitCode int, usage *model.Usage) error {
	r, err := o.Store.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if r.SandboxID != sandboxID {
		return store.ErrNotFound
	}
	o.setRunning(sandboxID, "")
	if r.Status == model.RunCancelled {
		return nil
	}
	now := time.Now()
	r.FinishedAt, r.ExitCode = &now, exitCode
	r.Status = model.RunDone
	if exitCode != 0 {
		r.Status = model.RunFailed
	}
	if usage != nil && !usage.IsZero() {
		r.Usage = *usage
	}
	if err := o.Store.UpdateRun(ctx, r); err != nil {
		return err
	}
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventRunDone, Data: string(r.Status)})
	return nil
}

// RecordEgress writes one gateway decision into the trace, attributed to the run that was
// executing at the time. Called by the authz handler on the hot path: it must stay cheap.
func (o *Orchestrator) RecordEgress(ctx context.Context, sandboxID string, allowed bool, eg model.Egress) {
	if sandboxID == "" {
		return
	}
	typ := model.EventEgressDen
	if allowed {
		typ = model.EventEgressOK
	}
	b, _ := json.Marshal(eg)
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: o.runningRunID(ctx, sandboxID), Type: typ, Data: string(b)})
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
	o.setRunning(sandboxID, "")
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

// IdleLoop sleeps sandboxes whose idle timeout elapsed without user activity, deletes expired
// ones and retries deletions the cluster refused. A sandbox in the middle of a run is left
// alone until the run ends.
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
		switch {
		case sb.Status == model.StatusDeleting:
			// A delete the cluster refused earlier: try again.
			if err := o.Delete(ctx, sb.ID); err != nil {
				o.Log.Warn("delete retry", "id", sb.ID, "err", err)
			}
			continue
		case sb.ExpiresAt != nil && now.After(*sb.ExpiresAt):
			o.Log.Info("sandbox expired, deleting", "id", sb.ID, "slug", sb.Slug, "expired_at", sb.ExpiresAt)
			if err := o.Delete(ctx, sb.ID); err != nil {
				o.Log.Error("expire delete", "id", sb.ID, "err", err)
			}
			continue
		}
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
