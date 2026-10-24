// Package orchestrator owns the sandbox lifecycle: create, run tasks, sleep when idle,
// wake on demand, roll agents out to new versions, delete. It talks to Kubernetes through
// the Runtime interface so the same logic runs against a fake runtime in tests and local
// development.
//
// Several replicas may run at once against one Postgres: every write goes through the
// store's revision check (mutate reloads and retries on a conflict), quota decisions happen
// under a store-level tenant lock, and the background reconciler runs on the replica that
// holds the leadership lease. Pods a dead replica left in "waking" are picked up by the leader.
package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Runtime.PodStatus distinguishes three outcomes by error: ErrPodNotFound (the pod does not
// exist, yet or any more), ErrPodTerminated (it exists in a terminal phase) and any other
// error, which means the state could not be observed (API outage) and says nothing about the
// pod. Only the first two are facts the orchestrator acts on.
var (
	ErrPodNotFound   = errors.New("pod not found")
	ErrPodTerminated = errors.New("pod terminated")
)

// podGone reports an observed fact (absent or terminal), never an observation failure.
func podGone(err error) bool {
	return errors.Is(err, ErrPodNotFound) || errors.Is(err, ErrPodTerminated)
}

// Runtime creates and destroys the pod and volume behind a sandbox.
type Runtime interface {
	// EnsureVolume creates the sandbox's persistent volume claim if missing.
	EnsureVolume(ctx context.Context, sb *model.Sandbox) error
	// CreatePod starts a pod on the volume (image from sb.AgentVersion) and returns its name.
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

// PolicyGuard decides which tenant may use which slug (the policy set's tenants lists).
// AllowedFor gates creation; Revoked says an existing sandbox lost its slug and must be
// stopped (see policy.Set.Revoked for the two kinds of grant).
type PolicyGuard interface {
	AllowedFor(slug, tenant string) bool
	Revoked(slug, tenant string, adminGrant bool) bool
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

	// DefaultAgentVersion is the agent image used when a request names no version.
	DefaultAgentVersion string
	// Versions maps version names tenants may ask for (e.g. "stable", "1.5.0") to image
	// references. Tenants are confined to these names; the admin may also pass any image ref.
	Versions map[string]string
	// EnvVersion fingerprints the environment a pod is started under (policy content, harness
	// command, image, pod env); stored on the sandbox so drift is visible. nil → "".
	EnvVersion func(sb *model.Sandbox) string
}

// QuotaFor returns the quota that applies to a tenant.
func (c Config) QuotaFor(tenant string) Quota {
	if q, ok := c.Quotas[tenant]; ok {
		return q
	}
	return c.DefaultQuota
}

// ResolveVersion turns what a client asked for into an image reference. "" is the default;
// a configured name maps to its image; anything else is accepted only from the admin.
func (c Config) ResolveVersion(v string, admin bool) (string, error) {
	if v == "" {
		return c.DefaultAgentVersion, nil // "" when the deployment does not version agents
	}
	if ref, ok := c.Versions[v]; ok {
		return ref, nil
	}
	if admin {
		return v, nil
	}
	names := make([]string, 0, len(c.Versions))
	for n := range c.Versions {
		names = append(names, n)
	}
	return "", fmt.Errorf("%w: unknown agent version %q (known: %s)", ErrForbidden, v, strings.Join(names, ", "))
}

// Orchestrator is the sandbox lifecycle manager.
type Orchestrator struct {
	Store    store.Store
	Runtime  Runtime
	Retirer  Retirer
	Policies PolicyGuard // optional
	Hub      *events.Hub
	Cfg      Config
	Log      *slog.Logger

	// ListenerPublishes is set when the store feeds appended events back through
	// store.EventListener: then emit does not publish locally, or every event would arrive twice.
	ListenerPublishes bool

	mu       sync.Mutex
	waking   map[string]bool   // sandboxes this replica is watching to readiness
	meta     map[string]sbMeta // sandbox id → tenant/slug, for stamping events
	sessions map[string]string // run id → last harness session id stored, to skip repeated writes
	leading  atomic.Bool
}

// Leading reports whether this replica holds the reconciler lease.
func (o *Orchestrator) Leading() bool { return o.leading.Load() }

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
		waking: map[string]bool{}, meta: map[string]sbMeta{}, sessions: map[string]string{}}
}

// Errors surfaced to the API.
var (
	ErrBadRequest = errors.New("bad request")
	ErrForbidden  = errors.New("forbidden")
	ErrConflict   = errors.New("conflict")
	ErrQuota      = errors.New("quota exceeded")
	ErrRuntime    = errors.New("runtime") // the cluster refused or failed; retry later
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// errAlreadyStarted is startPod's internal signal that the pod is already up or coming up.
var errAlreadyStarted = errors.New("already started")

// CreateRequest is the input of POST /sandboxes.
type CreateRequest struct {
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	Owner         string `json:"owner"`
	Tenant        string `json:"tenant"`
	Repo          string `json:"repo"`
	IdleTimeout   *int   `json:"idle_timeout,omitempty"`
	WakeOnPreview *bool  `json:"wake_on_preview,omitempty"`
	TTL           *int   `json:"ttl,omitempty"`           // seconds until the sandbox is deleted; 0/absent = keep
	AgentVersion  string `json:"agent_version,omitempty"` // version name (tenants) or image ref (admin); "" = default
	// AgentRef creates the sandbox from a catalogue AgentDefinition ("name" or "name@N"): the API
	// resolves it into Slug, Repo, lifecycle defaults, AgentVersion and the fields below.
	AgentRef string `json:"agent_ref,omitempty"`

	// Set by the API from the caller's credentials and the catalogue, never from the body.
	Admin               bool          `json:"-"`
	ExpiresBefore       time.Time     `json:"-"` // hard cap on expires_at (an OIDC token's lifetime)
	AgentRevision       int           `json:"-"`
	EnvironmentRef      string        `json:"-"`
	EnvironmentRevision int           `json:"-"`
	Launch              *model.Launch `json:"-"`
}

// UpdateRequest is the input of PATCH /sandboxes/{id}; nil fields are left alone.
type UpdateRequest struct {
	Repo          *string `json:"repo,omitempty"`
	IdleTimeout   *int    `json:"idle_timeout,omitempty"`
	WakeOnPreview *bool   `json:"wake_on_preview,omitempty"`
	TTL           *int    `json:"ttl,omitempty"` // seconds from now; 0 removes the expiry

	// ExpiresBefore (set by the API from an expiring credential) caps the new expiry; a ttl of 0
	// cannot remove an expiry such a credential imposed.
	ExpiresBefore time.Time `json:"-"`
}

func newID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// mutate applies fn to the current record and writes it back, retrying when another writer
// got in between. fn's own error is returned as is (no retry); the stored record is returned
// on success.
func (o *Orchestrator) mutate(ctx context.Context, id string, fn func(sb *model.Sandbox) error) (*model.Sandbox, error) {
	for attempt := 0; attempt < 20; attempt++ {
		sb, err := o.Store.GetSandbox(ctx, id)
		if err != nil {
			return nil, err
		}
		if err := fn(sb); err != nil {
			return sb, err
		}
		err = o.Store.UpdateSandbox(ctx, sb)
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		return sb, err
	}
	return nil, fmt.Errorf("%w: sandbox %s kept changing", ErrConflict, id)
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
	adminGrant := false
	if o.Policies != nil && !o.Policies.AllowedFor(req.Slug, req.Tenant) {
		if !req.Admin {
			return nil, fmt.Errorf("%w: tenant %s may not use slug %s (policy tenants list)", ErrForbidden, req.Tenant, req.Slug)
		}
		adminGrant = true // the admin overrides ownership; recorded, carried in the certificate
	}
	version := req.AgentVersion
	var err error
	if req.Launch == nil {
		// Bare slug creation: the version name is resolved here. With a launch attached, the
		// catalogue already resolved the environment's image under its author's rights.
		if version, err = o.Cfg.ResolveVersion(req.AgentVersion, req.Admin); err != nil {
			return nil, err
		}
	}
	now := time.Now()
	sb := &model.Sandbox{
		ID: newID("sb"), Name: req.Name, Slug: req.Slug, Owner: req.Owner, Tenant: req.Tenant, Repo: req.Repo,
		IdleTimeout: int(o.Cfg.DefaultIdleTimeout.Seconds()), WakeOnPreview: true, AgentVersion: version, AdminGrant: adminGrant,
		AgentRef: req.AgentRef, AgentRevision: req.AgentRevision, EnvironmentRef: req.EnvironmentRef, EnvironmentRevision: req.EnvironmentRevision,
		Launch: req.Launch, Status: model.StatusCreating, LastActivity: now, CreatedAt: now,
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
	if !req.ExpiresBefore.IsZero() && (sb.ExpiresAt == nil || req.ExpiresBefore.Before(*sb.ExpiresAt)) {
		t := req.ExpiresBefore
		sb.ExpiresAt = &t
	}
	// Quota check and record creation under the tenant lock (shared by every replica): two
	// concurrent creates cannot both see the last free slot.
	err = o.Store.WithTenantLock(ctx, sb.Tenant, func(ctx context.Context) error {
		if err := o.checkQuota(ctx, sb.Tenant, true); err != nil {
			return err
		}
		return o.Store.CreateSandbox(ctx, sb)
	})
	if err != nil {
		return nil, err
	}
	o.remember(sb)
	if err := o.Runtime.EnsureVolume(ctx, sb); err != nil {
		o.fail(ctx, sb.ID, "volume: "+err.Error())
		sb, _ = o.Store.GetSandbox(ctx, sb.ID)
		return sb, fmt.Errorf("%w: volume: %v", ErrRuntime, err)
	}
	id := sb.ID
	if sb, err = o.startPod(ctx, id); err != nil {
		cur, _ := o.Store.GetSandbox(ctx, id)
		return cur, err
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

// startPod moves the sandbox to waking (under the tenant lock, so the awake quota counts it
// before another wake is evaluated), creates the pod with the pending or current agent
// version and starts watching for readiness.
func (o *Orchestrator) startPod(ctx context.Context, id string) (*model.Sandbox, error) {
	var sb *model.Sandbox
	var from string
	tenant := o.metaOf(ctx, id).tenant
	err := o.Store.WithTenantLock(ctx, tenant, func(ctx context.Context) error {
		cur, err := o.Store.GetSandbox(ctx, id)
		if err != nil {
			return err
		}
		switch cur.Status {
		case model.StatusWaking, model.StatusRunning:
			// Another caller (or replica) started the pod between our read and the lock: nothing to do.
			sb = cur
			return errAlreadyStarted
		case model.StatusDeleting:
			return fmt.Errorf("%w: sandbox is being deleted", ErrConflict)
		case model.StatusCreating:
		default:
			if err := o.checkQuota(ctx, cur.Tenant, false); err != nil {
				return err
			}
		}
		from = cur.AgentVersion
		sb, err = o.setStatusFrom(ctx, id, []model.SandboxStatus{cur.Status}, model.StatusWaking, func(s *model.Sandbox) {
			if s.DesiredVersion != "" {
				s.AgentVersion, s.DesiredVersion = s.DesiredVersion, ""
			}
			if s.AgentVersion == "" {
				s.AgentVersion = o.Cfg.DefaultAgentVersion
			}
			if s.Launch != nil && s.AgentVersion != "" {
				// A rollout moves the sandbox to another image; the rest of the launch stays.
				s.Launch.Image = s.AgentVersion
			}
			if o.Cfg.EnvVersion != nil {
				s.EnvVersion = o.Cfg.EnvVersion(s)
			}
			s.PodName, s.IP = "", ""
		})
		return err
	})
	if errors.Is(err, errAlreadyStarted) {
		return sb, nil
	}
	if err != nil {
		return nil, err
	}
	if from != "" && from != sb.AgentVersion {
		o.Log.Info("agent version switch", "id", sb.ID, "from", from, "to", sb.AgentVersion)
	}
	pod, err := o.Runtime.CreatePod(ctx, sb)
	if err != nil {
		o.fail(ctx, id, "pod: "+err.Error())
		return nil, fmt.Errorf("%w: pod: %v", ErrRuntime, err)
	}
	sb, err = o.mutate(ctx, id, func(s *model.Sandbox) error {
		s.PodName = pod
		return nil
	})
	if err != nil {
		return nil, err
	}
	go o.waitReady(id)
	return sb, nil
}

// waitReady polls the runtime until the pod is ready, then flips the status to running.
// Errors from the runtime are retried until the deadline: a pod that is not found yet may
// still be in creation on another replica.
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
	var lastErr error
	for {
		sb, err := o.Store.GetSandbox(ctx, id)
		if err != nil || sb.Status != model.StatusWaking {
			return
		}
		if sb.PodName != "" {
			ready, ip, err := o.Runtime.PodStatus(ctx, sb)
			lastErr = err
			switch {
			case errors.Is(err, ErrPodTerminated):
				// Crashed init container, evicted: no point waiting for the deadline.
				o.fail(context.Background(), id, "pod status: "+err.Error())
				return
			case err != nil:
				// Not visible yet (another replica is still creating it) or the API is unreachable:
				// neither says anything about the pod, keep waiting.
			default:
				if ip != "" && ip != sb.IP {
					_, _ = o.mutate(ctx, id, func(s *model.Sandbox) error { s.IP = ip; return nil })
				}
				if ready {
					_, _ = o.setStatusFrom(ctx, id, []model.SandboxStatus{model.StatusWaking}, model.StatusRunning, func(s *model.Sandbox) { s.IP = ip })
					return
				}
			}
		}
		select {
		case <-ctx.Done():
			msg := "pod did not become ready within " + o.Cfg.ReadyTimeout.String()
			if lastErr != nil {
				msg += ": " + lastErr.Error()
			}
			o.fail(context.Background(), id, msg)
			return
		case <-t.C:
		}
	}
}

// setStatus stores a status transition (plus whatever apply changes) and emits the event.
func (o *Orchestrator) setStatus(ctx context.Context, id string, st model.SandboxStatus, apply func(s *model.Sandbox)) (*model.Sandbox, error) {
	return o.setStatusFrom(ctx, id, nil, st, apply)
}

// setStatusFrom is setStatus with a precondition: the transition happens only while the current
// status is one of from (nil = any). Otherwise ErrConflict, and the caller knows another writer
// moved the sandbox first instead of overwriting its work.
func (o *Orchestrator) setStatusFrom(ctx context.Context, id string, from []model.SandboxStatus, st model.SandboxStatus, apply func(s *model.Sandbox)) (*model.Sandbox, error) {
	sb, err := o.mutate(ctx, id, func(s *model.Sandbox) error {
		if from != nil {
			ok := false
			for _, f := range from {
				ok = ok || s.Status == f
			}
			if !ok {
				return fmt.Errorf("%w: sandbox is %s, not %v", ErrConflict, s.Status, from)
			}
		}
		if apply != nil {
			apply(s)
		}
		s.Status = st
		if st != model.StatusError {
			s.Error = ""
		}
		return nil
	})
	if errors.Is(err, ErrConflict) {
		return nil, err
	}
	if err != nil {
		o.Log.Error("update sandbox", "id", id, "status", st, "err", err)
		return nil, err
	}
	o.emit(ctx, model.Event{SandboxID: id, Type: model.EventStatus, Data: string(st)})
	o.Log.Info("sandbox status", "id", sb.ID, "slug", sb.Slug, "status", st, "pod", sb.PodName, "ip", sb.IP, "agent", sb.AgentVersion)
	return sb, nil
}

func (o *Orchestrator) fail(ctx context.Context, id, msg string) {
	o.Log.Error("sandbox error", "id", id, "err", msg)
	_, _ = o.setStatus(ctx, id, model.StatusError, func(s *model.Sandbox) { s.Error = msg })
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

// runningRunID returns the executing run of a sandbox, or "" if none. It is always read from
// the store: egress events are kept forever with this run id, and a run may have been claimed
// or finished on another replica a moment ago. One indexed query per allowed request.
func (o *Orchestrator) runningRunID(ctx context.Context, sandboxID string) string {
	if r, err := o.Store.RunningRun(ctx, sandboxID); err == nil {
		return r.ID
	}
	return ""
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
	if o.Hub != nil && !o.ListenerPublishes {
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

// Touch records user activity, postponing sleep. It never bumps the revision.
func (o *Orchestrator) Touch(ctx context.Context, id string) {
	_ = o.Store.TouchSandbox(ctx, id, time.Now())
}

// Update changes the mutable settings of a sandbox.
func (o *Orchestrator) Update(ctx context.Context, id string, req UpdateRequest) (*model.Sandbox, error) {
	if req.IdleTimeout != nil && *req.IdleTimeout < 0 {
		return nil, fmt.Errorf("%w: idle_timeout must be >= 0", ErrBadRequest)
	}
	if req.TTL != nil && *req.TTL < 0 {
		return nil, fmt.Errorf("%w: ttl must be >= 0", ErrBadRequest)
	}
	return o.mutate(ctx, id, func(sb *model.Sandbox) error {
		if sb.Status == model.StatusDeleting {
			return fmt.Errorf("%w: sandbox is being deleted", ErrConflict)
		}
		if req.IdleTimeout != nil {
			sb.IdleTimeout = *req.IdleTimeout
		}
		if req.WakeOnPreview != nil {
			sb.WakeOnPreview = *req.WakeOnPreview
		}
		if req.Repo != nil {
			sb.Repo = *req.Repo
		}
		if req.TTL != nil {
			if *req.TTL == 0 {
				sb.ExpiresAt = nil
			} else {
				t := time.Now().Add(time.Duration(*req.TTL) * time.Second)
				sb.ExpiresAt = &t
			}
		}
		if !req.ExpiresBefore.IsZero() && (sb.ExpiresAt == nil || req.ExpiresBefore.Before(*sb.ExpiresAt)) {
			t := req.ExpiresBefore
			sb.ExpiresAt = &t
		}
		return nil
	})
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
	return o.stopPod(ctx, id, model.StatusSleeping)
}

// stopPod takes a pod down (status stopping → final), retires its identity and cancels a run
// that was executing. final is sleeping, or waking when a new pod follows at once.
func (o *Orchestrator) stopPod(ctx context.Context, id string, final model.SandboxStatus) (*model.Sandbox, error) {
	// Only a sandbox that has (or is getting) a pod can be stopped, and only by one writer: a
	// second stopper, or a stop racing a sleep on another replica, gets ErrConflict here.
	sb, err := o.setStatusFrom(ctx, id, []model.SandboxStatus{model.StatusRunning, model.StatusWaking, model.StatusError}, model.StatusStopping, nil)
	if err != nil {
		return nil, err
	}
	if err := o.Runtime.DeletePod(ctx, sb); err != nil {
		o.fail(ctx, id, "delete pod: "+err.Error())
		return nil, fmt.Errorf("%w: delete pod: %v", ErrRuntime, err)
	}
	if o.Retirer != nil {
		if err := o.Retirer.RetireSandbox(ctx, id); err != nil {
			o.Log.Error("retire identities", "id", id, "err", err)
		}
	}
	if r, err := o.Store.RunningRun(ctx, id); err == nil {
		now := time.Now()
		r.Status, r.FinishedAt = model.RunCancelled, &now
		_ = o.Store.UpdateRun(ctx, r)
		o.emit(ctx, model.Event{SandboxID: id, RunID: r.ID, Type: model.EventRunDone, Data: string(model.RunCancelled)})
	}
	if final == model.StatusWaking {
		return o.startPod(ctx, id)
	}
	return o.setStatus(ctx, id, final, func(s *model.Sandbox) { s.PodName, s.IP = "", "" })
}

// Wake starts a pod for a sleeping sandbox. Idempotent for waking/running.
func (o *Orchestrator) Wake(ctx context.Context, id string) (*model.Sandbox, error) {
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return nil, err
	}
	o.Touch(ctx, id)
	switch sb.Status {
	case model.StatusRunning, model.StatusWaking:
		return sb, nil
	case model.StatusSleeping, model.StatusError:
		return o.startPod(ctx, id)
	default:
		return nil, fmt.Errorf("%w: sandbox is %s", ErrConflict, sb.Status)
	}
}

// Delete stops the pod, removes the volume and then the record. If the cluster refuses, the
// record stays in status `deleting` with the error attached; the reconciler and a repeated
// DELETE retry it, so nothing is silently left behind.
func (o *Orchestrator) Delete(ctx context.Context, id string) error {
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return err
	}
	if sb.Status != model.StatusDeleting {
		if sb, err = o.setStatus(ctx, id, model.StatusDeleting, nil); err != nil {
			return err
		}
	}
	if o.Retirer != nil {
		_ = o.Retirer.RetireSandbox(ctx, id)
	}
	if err := o.Runtime.DeletePod(ctx, sb); err != nil {
		_, _ = o.mutate(ctx, id, func(s *model.Sandbox) error { s.Error = "delete pod: " + err.Error(); return nil })
		return fmt.Errorf("%w: delete pod: %v", ErrRuntime, err)
	}
	if err := o.Runtime.DeleteVolume(ctx, sb); err != nil {
		_, _ = o.mutate(ctx, id, func(s *model.Sandbox) error { s.Error = "delete volume: " + err.Error(); return nil })
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
	o.mu.Unlock()
	return err
}

// CreateRun queues a task and wakes the sandbox if needed.
func (o *Orchestrator) CreateRun(ctx context.Context, sandboxID, task string) (*model.Run, error) {
	return o.queueRun(ctx, sandboxID, &model.Run{Task: task})
}

func (o *Orchestrator) queueRun(ctx context.Context, sandboxID string, r *model.Run) (*model.Run, error) {
	if strings.TrimSpace(r.Task) == "" {
		return nil, fmt.Errorf("%w: task is required", ErrBadRequest)
	}
	sb, err := o.Store.GetSandbox(ctx, sandboxID)
	if err != nil {
		return nil, err
	}
	if sb.Status == model.StatusDeleting {
		return nil, fmt.Errorf("%w: sandbox is being deleted", ErrConflict)
	}
	r.ID, r.SandboxID, r.Tenant, r.Slug = newID("run"), sandboxID, sb.Tenant, sb.Slug
	r.Status, r.CreatedAt = model.RunQueued, time.Now()
	if err := o.Store.CreateRun(ctx, r); err != nil {
		return nil, err
	}
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: r.ID, Type: model.EventRunQueued, Data: r.ResumeOf})
	o.Touch(ctx, sandboxID)
	if sb.Status == model.StatusSleeping || sb.Status == model.StatusError {
		// The run is queued either way; a failed wake shows in the sandbox status and the run
		// starts on the next successful wake. The caller still gets the run it created.
		if _, err := o.Wake(ctx, sandboxID); err != nil {
			o.Log.Warn("wake for run failed", "sandbox", sandboxID, "run", r.ID, "err", err)
		}
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

// NextRun long-polls for a queued run (agent side) and marks it running, stamped with the
// agent version that is executing it.
func (o *Orchestrator) NextRun(ctx context.Context, sandboxID string, wait time.Duration) (*model.Run, error) {
	deadline := time.Now().Add(wait)
	for {
		// A pod that is being stopped or replaced must not pick up work: the run would die with it.
		if sb, err := o.Store.GetSandbox(ctx, sandboxID); err != nil || sb.Status != model.StatusRunning {
			if err != nil {
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
			continue
		}
		r, err := o.Store.ClaimQueuedRun(ctx, sandboxID, time.Now())
		if err == nil {
			// The run records what it executes under; later catalogue changes never touch it.
			if sb, err := o.Store.GetSandbox(ctx, sandboxID); err == nil {
				r.AgentVersion, r.AgentRef, r.AgentRevision = sb.AgentVersion, sb.AgentRef, sb.AgentRevision
				r.EnvironmentRef, r.EnvironmentRevision = sb.EnvironmentRef, sb.EnvironmentRevision
				_ = o.Store.UpdateRun(ctx, r)
			}
			o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: r.ID, Type: model.EventRunStart, Data: r.AgentVersion})
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
// result line, generic `{"type":"usage"}` records) also update the run's accounting; lines
// that carry the harness session id are remembered for resume.
func (o *Orchestrator) Output(ctx context.Context, sandboxID, runID, data string) error {
	if err := o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventRunOutput, Data: data}); err != nil {
		return err
	}
	u, mode, hasUsage := harness.ParseUsage(data)
	session, hasSession := harness.ParseSession(data)
	if hasSession {
		// Claude Code stamps every line with the session id: only the first sighting (or a change)
		// is worth a store round trip.
		o.mu.Lock()
		known := o.sessions[runID]
		if known == session {
			hasSession = false
		} else {
			o.sessions[runID] = session
		}
		o.mu.Unlock()
	}
	if !hasUsage && !hasSession {
		return nil
	}
	r, err := o.Store.GetRun(ctx, runID)
	if err != nil || r.SandboxID != sandboxID {
		return nil
	}
	changed := false
	if hasUsage {
		if mode == harness.Total {
			r.Usage = u
		} else {
			r.Usage.Add(u)
		}
		changed = true
	}
	if hasSession && r.Session != session {
		r.Session = session
		changed = true
	}
	if changed {
		if err := o.Store.UpdateRun(ctx, r); err != nil {
			o.Log.Warn("record run data", "run", runID, "err", err)
		}
	}
	return nil
}

// FinishRun records the result of a run. usage, if given, is the harness's own total and
// overrides whatever was parsed from the output stream. A rollout deferred until the run ended
// is applied right after.
func (o *Orchestrator) FinishRun(ctx context.Context, sandboxID, runID string, exitCode int, usage *model.Usage) error {
	r, err := o.Store.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if r.SandboxID != sandboxID {
		return store.ErrNotFound
	}
	switch r.Status {
	case model.RunCancelled, model.RunDone, model.RunFailed:
		return nil // already settled: a retried /finish after a lost acknowledgement is a no-op
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
	o.mu.Lock()
	delete(o.sessions, runID)
	o.mu.Unlock()
	// A deferred rollout is applied by the reconciler; the leader does it right away rather than
	// on its next tick, the others leave it to the leader.
	if o.Leading() {
		go o.applyPending(context.Background(), sandboxID)
	}
	return nil
}

// applyPending restarts the pod of a running sandbox that has a rollout waiting and no run
// in progress. Called after a run ends and by the reconciler.
func (o *Orchestrator) applyPending(ctx context.Context, id string) {
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil || sb.DesiredVersion == "" || sb.Status != model.StatusRunning {
		return
	}
	if _, err := o.Store.RunningRun(ctx, id); err == nil {
		return
	}
	o.Log.Info("applying deferred rollout", "id", id, "from", sb.AgentVersion, "to", sb.DesiredVersion)
	if _, err := o.stopPod(ctx, id, model.StatusWaking); err != nil && !errors.Is(err, ErrConflict) {
		o.Log.Error("deferred rollout", "id", id, "err", err)
	}
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
// through a run.cancel event and marking the run; the runner exits the harness.
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

// RolloutRequest is the input of POST /rollouts: move agents to another version.
//
// Exactly one selector: Sandbox (one id), Instance (one agent by its identity number), Slug
// (every sandbox of that agent definition) or All. Percent keeps a deterministic share of the
// selection (canary); the same percent later targets the same sandboxes, a larger one a superset.
// Force interrupts runs in progress and, unless Resume is false, re-queues each as a resume run.
type RolloutRequest struct {
	Version  string `json:"version"`
	Sandbox  string `json:"sandbox,omitempty"`
	Instance int    `json:"instance,omitempty"`
	Slug     string `json:"slug,omitempty"`
	All      bool   `json:"all,omitempty"`
	Percent  int    `json:"percent,omitempty"`
	Force    bool   `json:"force,omitempty"`
	Resume   *bool  `json:"resume,omitempty"`

	// Set by the API from the caller's credentials.
	Tenant string `json:"-"` // non-admin: only this tenant's sandboxes
	Admin  bool   `json:"-"`
}

// RolloutItem is the outcome for one sandbox.
type RolloutItem struct {
	Sandbox  string `json:"sandbox"`
	Slug     string `json:"slug"`
	From     string `json:"from"`
	Mode     string `json:"mode"` // now | forced | deferred | wake | skipped
	Reason   string `json:"reason,omitempty"`
	RunID    string `json:"run_id,omitempty"`    // forced: the interrupted run
	ResumeID string `json:"resume_id,omitempty"` // forced: the run continuing it
}

// RolloutResult summarises a rollout call.
type RolloutResult struct {
	Version  string        `json:"version"`
	Selected int           `json:"selected"` // sandboxes matched by the selector (before percent)
	Targeted int           `json:"targeted"` // after percent
	Items    []RolloutItem `json:"items"`
}

// Rollout moves the selected sandboxes to a version. Sleeping ones switch on their next wake,
// idle running ones restart now, busy ones wait for their run to finish unless Force.
func (o *Orchestrator) Rollout(ctx context.Context, req RolloutRequest) (*RolloutResult, error) {
	selectors := 0
	for _, on := range []bool{req.Sandbox != "", req.Instance != 0, req.Slug != "", req.All} {
		if on {
			selectors++
		}
	}
	if selectors != 1 {
		return nil, fmt.Errorf("%w: exactly one of sandbox, instance, slug or all is required", ErrBadRequest)
	}
	if req.Percent < 0 || req.Percent > 100 {
		return nil, fmt.Errorf("%w: percent must be 0..100", ErrBadRequest)
	}
	if req.Slug != "" && !req.Admin && o.Policies != nil && !o.Policies.AllowedFor(req.Slug, req.Tenant) {
		return nil, fmt.Errorf("%w: tenant %s does not own slug %s", ErrForbidden, req.Tenant, req.Slug)
	}
	version, err := o.Cfg.ResolveVersion(req.Version, req.Admin)
	if err != nil {
		return nil, err
	}
	resume := req.Resume == nil || *req.Resume

	var selected []*model.Sandbox
	switch {
	case req.Sandbox != "":
		sb, err := o.Store.GetSandbox(ctx, req.Sandbox)
		if err != nil {
			return nil, err
		}
		selected = []*model.Sandbox{sb}
	default:
		selected, err = o.Store.QuerySandboxes(ctx, store.SandboxFilter{Tenant: req.Tenant, Slug: req.Slug, Instance: req.Instance, Limit: 100000})
		if err != nil {
			return nil, err
		}
	}
	res := &RolloutResult{Version: version, Items: []RolloutItem{}}
	for _, sb := range selected {
		if req.Tenant != "" && sb.Tenant != req.Tenant {
			return nil, fmt.Errorf("%w: sandbox %s belongs to another tenant", ErrForbidden, sb.ID)
		}
	}
	res.Selected = len(selected)
	for _, sb := range selected {
		if req.Percent > 0 && req.Percent < 100 && !inCanary(sb.ID, req.Percent) {
			continue
		}
		res.Targeted++
		res.Items = append(res.Items, o.rolloutOne(ctx, sb, version, req.Force, resume))
	}
	return res, nil
}

// inCanary places a sandbox in the first percent of a stable ordering of all sandboxes.
func inCanary(id string, percent int) bool {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return int(h.Sum32()%100) < percent
}

func (o *Orchestrator) rolloutOne(ctx context.Context, sb *model.Sandbox, version string, force, resume bool) RolloutItem {
	item := RolloutItem{Sandbox: sb.ID, Slug: sb.Slug, From: sb.AgentVersion}
	if sb.AgentVersion == version && sb.DesiredVersion == "" {
		item.Mode, item.Reason = "skipped", "already at this version"
		return item
	}
	record := func(mode string, runID, resumeID string) {
		item.Mode, item.RunID, item.ResumeID = mode, runID, resumeID
		b, _ := json.Marshal(model.Rollout{From: sb.AgentVersion, To: version, Mode: mode, RunID: runID, ResumeID: resumeID})
		o.emit(ctx, model.Event{SandboxID: sb.ID, RunID: runID, Type: model.EventRollout, Data: string(b)})
	}
	setDesired := func() error {
		_, err := o.mutate(ctx, sb.ID, func(s *model.Sandbox) error {
			if s.AgentVersion == version {
				s.DesiredVersion = ""
			} else {
				s.DesiredVersion = version
			}
			return nil
		})
		return err
	}
	switch sb.Status {
	case model.StatusDeleting:
		item.Mode, item.Reason = "skipped", "sandbox is being deleted"
		return item
	case model.StatusSleeping, model.StatusError:
		if err := setDesired(); err != nil {
			item.Mode, item.Reason = "skipped", err.Error()
			return item
		}
		record(model.RolloutWake, "", "")
		return item
	case model.StatusCreating, model.StatusWaking, model.StatusStopping:
		if err := setDesired(); err != nil {
			item.Mode, item.Reason = "skipped", err.Error()
			return item
		}
		record(model.RolloutDeferred, "", "")
		item.Reason = "sandbox is " + string(sb.Status) + "; applied when it is running and idle"
		return item
	}
	// Running.
	if err := setDesired(); err != nil {
		item.Mode, item.Reason = "skipped", err.Error()
		return item
	}
	r, err := o.Store.RunningRun(ctx, sb.ID)
	if err != nil {
		record(model.RolloutNow, "", "")
		if _, err := o.stopPod(ctx, sb.ID, model.StatusWaking); err != nil {
			item.Reason = "restart failed: " + err.Error()
		}
		return item
	}
	if !force {
		record(model.RolloutDeferred, r.ID, "")
		item.Reason = "run in progress; applied when it finishes"
		return item
	}
	// Forced: interrupt, replace the pod, then queue the continuation. The order matters: the
	// resume run is created only after the old pod's identity is retired, so the dying runner
	// cannot claim it; NextRun also refuses claims while the sandbox is not running.
	if _, err := o.CancelRun(ctx, sb.ID, r.ID); err != nil {
		item.Mode, item.Reason = "skipped", "cancel run: "+err.Error()
		return item
	}
	if _, err := o.stopPod(ctx, sb.ID, model.StatusWaking); err != nil {
		item.Reason = "restart failed: " + err.Error()
	}
	var resumeID string
	if resume {
		nr, err := o.queueRun(ctx, sb.ID, &model.Run{Task: r.Task, ResumeOf: r.ID, Session: r.Session})
		if err != nil {
			item.Reason = strings.TrimSpace(item.Reason + " resume run not queued: " + err.Error())
		} else {
			resumeID = nr.ID
		}
	}
	record(model.RolloutForced, r.ID, resumeID)
	return item
}

// SetPreview exposes a port of the sandbox under a stable host name.
func (o *Orchestrator) SetPreview(ctx context.Context, id string, port int, access string) (*model.Sandbox, error) {
	if port != 0 && (port < 1 || port > 65535) {
		return nil, fmt.Errorf("%w: port out of range", ErrBadRequest)
	}
	switch access {
	case "":
		access = model.AccessMembers
	case model.AccessLink, model.AccessSSO, model.AccessMembers:
	default:
		return nil, fmt.Errorf("%w: access must be link, sso or members", ErrBadRequest)
	}
	return o.mutate(ctx, id, func(sb *model.Sandbox) error {
		if port == 0 {
			sb.Preview = nil
			return nil
		}
		sb.Preview = &model.Preview{Port: port, Access: access, Host: o.PreviewHost(sb)}
		return nil
	})
}

// PreviewHost is <name>-<owner>.<domain>.
func (o *Orchestrator) PreviewHost(sb *model.Sandbox) string {
	owner := strings.ToLower(regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(strings.ToLower(sb.Owner), "-"))
	return fmt.Sprintf("%s-%s.%s", sb.Name, owner, o.Cfg.PreviewDomain)
}

// Run is the background work of the control plane: whichever replica holds the leadership
// lease reconciles (idle sleep, expiry, deferred rollouts, refused deletes, orphaned pods); the
// others stand by and take over when the lease is lost.
func (o *Orchestrator) Run(ctx context.Context) {
	for ctx.Err() == nil {
		lease, held, err := o.Store.TryLead(ctx, "orchestrator")
		if err != nil {
			o.Log.Warn("leadership", "err", err)
		}
		if !held {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		o.Log.Info("leadership acquired")
		o.lead(ctx, lease)
		lease.Release()
		o.Log.Info("leadership released")
	}
}

func (o *Orchestrator) lead(ctx context.Context, lease store.Lease) {
	o.leading.Store(true)
	defer o.leading.Store(false)
	o.Reconcile(ctx)
	t := time.NewTicker(o.Cfg.IdleCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := lease.Ping(ctx); err != nil {
				o.Log.Warn("leadership lost", "err", err)
				return
			}
			o.Reconcile(ctx)
		}
	}
}

// failRun settles a run whose executor is gone: status failed, the reason in the output, the
// usual run.finished event. Clients watching the run see it end instead of hanging forever.
func (o *Orchestrator) failRun(ctx context.Context, sandboxID string, r *model.Run, reason string) {
	now := time.Now()
	r.Status, r.FinishedAt, r.ExitCode = model.RunFailed, &now, -1
	if err := o.Store.UpdateRun(ctx, r); err != nil {
		o.Log.Error("fail run", "run", r.ID, "err", err)
		return
	}
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: r.ID, Type: model.EventRunOutput, Data: "[control plane] run lost: " + reason})
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: r.ID, Type: model.EventRunDone, Data: string(model.RunFailed)})
}

// IdleLoop is the single-replica form of Run, kept for callers that manage leadership themselves.
func (o *Orchestrator) IdleLoop(ctx context.Context) {
	o.leading.Store(true)
	defer o.leading.Store(false)
	t := time.NewTicker(o.Cfg.IdleCheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			o.Reconcile(ctx)
		}
	}
}

// Reconcile is one pass of the background work. Exported for tests.
func (o *Orchestrator) Reconcile(ctx context.Context) {
	sbs, err := o.Store.ListSandboxes(ctx)
	if err != nil {
		o.Log.Error("reconcile", "err", err)
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
		case sb.Status == model.StatusWaking:
			// Started by a replica that may be gone: watch it from here (no-op if we already do).
			go o.waitReady(sb.ID)
			continue
		case sb.Status == model.StatusCreating && now.Sub(sb.CreatedAt) > o.Cfg.ReadyTimeout:
			o.fail(ctx, sb.ID, "creation did not complete (control plane restarted?); wake to retry")
			continue
		case sb.Status == model.StatusStopping:
			// A stop interrupted by a replica restart: once the runtime no longer knows the pod,
			// settle as sleeping so the sandbox can be woken again.
			if _, _, err := o.Runtime.PodStatus(ctx, sb); errors.Is(err, ErrPodNotFound) {
				_, _ = o.setStatusFrom(ctx, sb.ID, []model.SandboxStatus{model.StatusStopping}, model.StatusSleeping, func(s *model.Sandbox) { s.PodName, s.IP = "", "" })
			}
			continue
		}
		if sb.Status != model.StatusRunning {
			// A run marked running while the sandbox has no pod is a leftover of a lost pod or a
			// crashed replica: nobody will ever finish it.
			if r, err := o.Store.RunningRun(ctx, sb.ID); err == nil {
				o.failRun(ctx, sb.ID, r, "sandbox is "+string(sb.Status)+" while the run was executing")
			}
			continue
		}
		// The pod must still exist and be alive; Kubernetes may have evicted or killed it. Only an
		// observed fact counts: an API outage is logged and the sandbox left exactly as it is.
		if _, _, err := o.Runtime.PodStatus(ctx, sb); err != nil && !podGone(err) {
			o.Log.Warn("cannot observe pod, leaving the sandbox alone", "id", sb.ID, "pod", sb.PodName, "err", err)
			continue
		} else if err != nil {
			reason := "pod disappeared"
			if errors.Is(err, ErrPodTerminated) {
				reason = "pod failed: " + err.Error()
			}
			o.Log.Warn("running sandbox lost its pod", "id", sb.ID, "pod", sb.PodName, "reason", reason)
			if r, err := o.Store.RunningRun(ctx, sb.ID); err == nil {
				o.failRun(ctx, sb.ID, r, reason)
			}
			if o.Retirer != nil {
				_ = o.Retirer.RetireSandbox(ctx, sb.ID)
			}
			_, _ = o.setStatusFrom(ctx, sb.ID, []model.SandboxStatus{model.StatusRunning}, model.StatusError, func(s *model.Sandbox) {
				s.Error = reason + "; wake to start a new pod"
				s.PodName, s.IP = "", ""
			})
			continue
		}
		if o.Policies != nil && o.Policies.Revoked(sb.Slug, sb.Tenant, sb.AdminGrant) {
			// The policy repository revoked the slug from this tenant: the gateway already refuses
			// every request; take the pod down too so nothing keeps running under rights it lost.
			o.Log.Warn("tenant lost its slug, stopping sandbox", "id", sb.ID, "slug", sb.Slug, "tenant", sb.Tenant)
			if _, err := o.Sleep(ctx, sb.ID, true); err != nil {
				o.Log.Error("stop after revocation", "id", sb.ID, "err", err)
			}
			continue
		}
		if sb.DesiredVersion != "" {
			o.applyPending(ctx, sb.ID)
			continue
		}
		if sb.IdleTimeout == 0 || now.Sub(sb.LastActivity) < sb.IdleDuration() {
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
