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

// Quotas decides the limits that apply: per tenant (QuotaFor) and per tenant and slug
// (SlugQuota, zero when the slug carries no limit of its own). Config implements the tenant
// part from its static tables; tenant settings and policy bindings replace it at runtime.
type Quotas interface {
	QuotaFor(tenant string) Quota
	SlugQuota(slug, tenant string) Quota
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
	// DefaultHarnessInput is the input mode of the deployment's default harness (kube.harness_input):
	// a sandbox whose profile names no harness of its own runs it.
	DefaultHarnessInput string
	// StopTimeout bounds a pod stop: the cluster calls a stop makes once it has moved the sandbox
	// to stopping, and how long the reconciler lets a sandbox sit in stopping with its pod alive
	// before it takes the stop over (the replica that began it died). 0 → 2m.
	StopTimeout time.Duration
}

// SlugQuota: the static configuration has no per-slug limits.
func (c Config) SlugQuota(string, string) Quota { return Quota{} }

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
	Quotas   Quotas      // optional: nil = Cfg
	Hub      *events.Hub
	Cfg      Config
	Log      *slog.Logger

	// ListenerPublishes is set when the store feeds appended events back through
	// store.EventListener: then emit does not publish locally, or every event would arrive twice.
	ListenerPublishes bool

	mu       sync.Mutex
	waking   map[string]bool      // sandboxes this replica is watching to readiness
	meta     map[string]sbMeta    // sandbox id → tenant/slug, for stamping events
	stopping map[string]bool      // sandboxes this replica is taking down right now
	stopSeen map[string]time.Time // when the reconciler first saw a sandbox stopping with its pod alive
	leading  atomic.Bool
	started  atomic.Bool
}

// Leading reports whether this replica holds the reconciler lease.
func (o *Orchestrator) Leading() bool { return o.leading.Load() }

// Started reports whether the reconciler (Run or IdleLoop) has been started. Policies and
// Quotas are plain fields read by it: they must be set before, never after.
func (o *Orchestrator) Started() bool { return o.started.Load() }

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
	if cfg.StopTimeout == 0 {
		cfg.StopTimeout = 2 * time.Minute
	}
	if log == nil {
		log = slog.Default()
	}
	return &Orchestrator{Store: st, Runtime: rt, Retirer: ret, Hub: hub, Cfg: cfg, Log: log,
		waking: map[string]bool{}, meta: map[string]sbMeta{},
		stopping: map[string]bool{}, stopSeen: map[string]time.Time{}}
}

// Errors surfaced to the API.
var (
	ErrBadRequest = errors.New("bad request")
	ErrForbidden  = errors.New("forbidden")
	ErrConflict   = errors.New("conflict")
	ErrQuota      = errors.New("quota exceeded")
	ErrTimeout    = errors.New("timed out waiting for the agent pod")
	ErrRuntime    = errors.New("runtime") // the cluster refused or failed; retry later
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// errAlreadyStarted is startPod's internal signal that the pod is already up or coming up.
var errAlreadyStarted = errors.New("already started")

// errUnchanged makes a mutate return the current record without writing it.
var errUnchanged = errors.New("unchanged")

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
	Connections         []string      `json:"-"` // the agent's connections, as references from the sandbox tenant's scope
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
		Launch: req.Launch, Connections: req.Connections, Status: model.StatusCreating, LastActivity: now, CreatedAt: now,
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
		if err := o.checkQuota(ctx, sb.Tenant, sb.Slug, true); err != nil {
			return err
		}
		return o.Store.CreateSandbox(ctx, sb)
	})
	if err != nil {
		return nil, err
	}
	o.remember(sb)
	// The volume is provisioned by startPod, as on every start: a creation whose volume failed is
	// recovered by a wake.
	id := sb.ID
	if sb, err = o.startPod(ctx, id); err != nil {
		cur, _ := o.Store.GetSandbox(ctx, id)
		return cur, err
	}
	return sb, nil
}

// checkQuota enforces the tenant's limits, then the slug's, before a new record (newRecord)
// or a new pod.
func (o *Orchestrator) checkQuota(ctx context.Context, tenant, slug string, newRecord bool) error {
	var quotas Quotas = o.Cfg
	if o.Quotas != nil {
		quotas = o.Quotas
	}
	check := func(q Quota, scope, by string) error {
		if q.MaxSandboxes == 0 && q.MaxAwake == 0 {
			return nil
		}
		c, err := o.Store.CountSandboxes(ctx, tenant, by)
		if err != nil {
			return err
		}
		if newRecord && q.MaxSandboxes > 0 && c.Total >= q.MaxSandboxes {
			return fmt.Errorf("%w: %s already has %d sandboxes (max_sandboxes=%d)", ErrQuota, scope, c.Total, q.MaxSandboxes)
		}
		if q.MaxAwake > 0 && c.Awake >= q.MaxAwake {
			return fmt.Errorf("%w: %s already has %d sandboxes awake (max_awake=%d)", ErrQuota, scope, c.Awake, q.MaxAwake)
		}
		return nil
	}
	if err := check(quotas.QuotaFor(tenant), "tenant "+tenant, ""); err != nil {
		return err
	}
	return check(quotas.SlugQuota(slug, tenant), "tenant "+tenant+" on slug "+slug, slug)
}

// startPod moves the sandbox to waking (under the tenant lock, so the awake quota counts it
// before another wake is evaluated), creates the pod with the pending or current agent
// version and starts watching for readiness.
func (o *Orchestrator) startPod(ctx context.Context, id string) (*model.Sandbox, error) {
	var sb *model.Sandbox
	var from string
	var volErr error
	started := false
	// The lock must be the tenant's: markDeleting takes it to keep a Delete away from the volume
	// provisioned below. A failed read is an error, never the lock of tenant "".
	tenant, err := o.tenantOf(ctx, id)
	if err != nil {
		return nil, err
	}
	err = o.Store.WithTenantLock(ctx, tenant, func(ctx context.Context) error {
		// Writers that do not take the lock can still move the record between the read and the
		// transition: the reconciler (this replica's or another's) settling a stop whose pod is
		// gone as sleeping, waitReady, a failure being recorded. The transition then fails its
		// precondition; reading again and deciding from the new status keeps a rollout's restart
		// (stopping → waking) from leaving the sandbox asleep because the leader settled the
		// stop first.
		for attempt := 0; ; attempt++ {
			err := o.startTransition(ctx, id, &sb, &from)
			if errors.Is(err, errRetryStart) && attempt < 10 {
				continue
			}
			if errors.Is(err, errRetryStart) {
				return fmt.Errorf("%w: sandbox %s kept changing", ErrConflict, id)
			}
			if err != nil {
				return err
			}
			break
		}
		started = true
		// Every pod start ensures the volume (idempotent): a sandbox whose first provisioning
		// failed would otherwise get a pod bound to a claim that does not exist, on every wake. It
		// is done under this lock, which markDeleting also takes: a Delete either ran before (the
		// transition above saw it) or runs after and removes this volume, never in between
		// leaving a volume created for a record that is gone.
		vctx, vcancel := o.detached(ctx)
		defer vcancel()
		volErr = o.Runtime.EnsureVolume(vctx, sb)
		return nil
	})
	if started && err != nil {
		// The move to waking is committed (it does not go through the lock's transaction); a
		// failure to release the lock, the client's cancelled context included, must not abandon
		// it: the pod is created, or its failure recorded, below on a detached context.
		o.Log.Warn("tenant lock released with an error after the start", "id", id, "err", err)
		err = nil
	}
	if errors.Is(err, errAlreadyStarted) {
		return sb, nil
	}
	if err != nil {
		return nil, err
	}
	if from != "" && from != sb.AgentVersion {
		o.Log.Info("agent version switch", "id", sb.ID, "from", from, "to", sb.AgentVersion)
	}
	// The sandbox is waking now: creating the pod and recording it (or the failure) must not stop
	// because the client went away, or the record stays waking with nothing behind it.
	ctx, cancel := o.detached(ctx)
	defer cancel()
	if volErr != nil {
		o.fail(ctx, id, model.StatusWaking, "volume: "+volErr.Error())
		return nil, fmt.Errorf("%w: volume: %v", ErrRuntime, volErr)
	}
	pod, err := o.Runtime.CreatePod(ctx, sb)
	if err != nil {
		o.fail(ctx, id, model.StatusWaking, "pod: "+err.Error())
		return nil, fmt.Errorf("%w: pod: %v", ErrRuntime, err)
	}
	// The lock was released before CreatePod, so the record may have moved meanwhile:
	//   - forward, on this pod: its bootstrap named it and a waitReady (any replica) found it
	//     ready, so the sandbox is waking or running with PodName "" or pod. That is the start
	//     succeeding, not a conflict: record the name if missing and leave the rest alone.
	//   - away from it: a Delete (record gone or deleting) or a stop (stopping, sleeping) ran
	//     and found no pod to remove. Only then is the pod a proven orphan, removed here, or it
	//     would run on with no record behind it.
	//   - anything else (error, another pod named): not ours to decide; left as it is.
	created := *sb
	created.PodName = pod
	orphan := false
	var observed int64
	sb, err = o.mutate(ctx, id, func(s *model.Sandbox) error {
		observed = s.Revision
		switch s.Status {
		case model.StatusWaking, model.StatusRunning:
			if s.PodName != "" && s.PodName != pod {
				return fmt.Errorf("%w: sandbox runs pod %s now", ErrConflict, s.PodName)
			}
			if s.PodName == pod {
				return errUnchanged
			}
			s.PodName = pod
			return nil
		case model.StatusDeleting, model.StatusStopping, model.StatusSleeping:
			orphan = true
		}
		return fmt.Errorf("%w: sandbox is %s", ErrConflict, s.Status)
	})
	if errors.Is(err, errUnchanged) {
		err = nil
	}
	if errors.Is(err, store.ErrNotFound) {
		orphan = true
	}
	if orphan {
		o.removeOrphan(ctx, tenant, &created, observed)
		return nil, fmt.Errorf("%w: sandbox changed while its pod was being created", ErrConflict)
	}
	if err != nil {
		return nil, err
	}
	go o.waitReady(id)
	return sb, nil
}

// errRetryStart: startTransition lost its precondition to another writer; read again.
var errRetryStart = errors.New("sandbox moved during start")

// startTransition is one attempt of startPod's locked step: read the record, decide, and move it
// to waking with the status read as precondition. errRetryStart when another writer moved the
// record in between; out and from receive the record and the agent version it had.
func (o *Orchestrator) startTransition(ctx context.Context, id string, out **model.Sandbox, from *string) error {
	cur, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return err
	}
	switch cur.Status {
	case model.StatusWaking, model.StatusRunning:
		// Another caller (or replica) started the pod between our read and the lock: nothing to do.
		*out = cur
		return errAlreadyStarted
	case model.StatusDeleting:
		return fmt.Errorf("%w: sandbox is being deleted", ErrConflict)
	case model.StatusCreating:
	default:
		if err := o.checkQuota(ctx, cur.Tenant, cur.Slug, false); err != nil {
			return err
		}
	}
	*from = cur.AgentVersion
	sb, err := o.setStatusFrom(ctx, id, []model.SandboxStatus{cur.Status}, model.StatusWaking, func(s *model.Sandbox) {
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
	if errors.Is(err, ErrConflict) {
		return errRetryStart
	}
	*out = sb
	return err
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
				o.fail(context.Background(), id, model.StatusWaking, "pod status: "+err.Error())
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
			o.fail(context.Background(), id, model.StatusWaking, msg)
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

// failTimeout bounds the write of a failure, on a context of its own.
const failTimeout = 10 * time.Second

// fail records that the operation which moved the sandbox to from went wrong: status error
// with the reason, only while the sandbox is still in from (a writer that moved it on since,
// a delete or a newer start, keeps its state). The write gets a fresh context: the caller's
// is often the reason it failed (its deadline ran out in the cluster call, the client left),
// and a cancelled context would keep Postgres from recording anything.
func (o *Orchestrator) fail(ctx context.Context, id string, from model.SandboxStatus, msg string) {
	o.Log.Error("sandbox error", "id", id, "err", msg)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), failTimeout)
	defer cancel()
	if _, err := o.setStatusFrom(ctx, id, []model.SandboxStatus{from}, model.StatusError, func(s *model.Sandbox) { s.Error = msg }); err != nil && !errors.Is(err, ErrConflict) {
		o.Log.Error("record sandbox error", "id", id, "err", err)
	}
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
	// Without force, "no run in progress" is decided under the claim lock, together with the move
	// to stopping (see stopPodIf).
	return o.stopPodIf(ctx, id, model.StatusSleeping, !force)
}

// stopPod takes a pod down whatever it is executing; see stopPodIf.
func (o *Orchestrator) stopPod(ctx context.Context, id string, final model.SandboxStatus) (*model.Sandbox, error) {
	return o.stopPodIf(ctx, id, final, false)
}

// stopPodIf takes a pod down (status stopping → final), retires its identity and cancels a run
// that was executing. final is sleeping, or waking when a new pod follows at once. With idle,
// the stop happens only while no run executes (errRunInProgress otherwise).
func (o *Orchestrator) stopPodIf(ctx context.Context, id string, final model.SandboxStatus, idle bool) (*model.Sandbox, error) {
	// Only a sandbox that has (or is getting) a pod can be stopped, and only by one writer: a
	// second stopper, or a stop racing a sleep on another replica, gets ErrConflict here.
	sb, err := o.toStopping(ctx, id, idle)
	if err != nil {
		return nil, stopNotBegun{err}
	}
	o.mu.Lock()
	o.stopping[id] = true
	o.mu.Unlock()
	defer func() { o.mu.Lock(); delete(o.stopping, id); o.mu.Unlock() }()
	// The sandbox is stopping now: the rest no longer depends on the caller. A client that hangs
	// up must not leave the pod running behind a record that says stopping.
	ctx, cancel := o.detached(ctx)
	defer cancel()
	if err := o.Runtime.DeletePod(ctx, sb); err != nil {
		o.fail(ctx, id, model.StatusStopping, "delete pod: "+err.Error())
		return nil, fmt.Errorf("%w: delete pod: %v", ErrRuntime, err)
	}
	if o.Retirer != nil {
		if err := o.Retirer.RetireSandbox(ctx, id); err != nil {
			o.Log.Error("retire identities", "id", id, "err", err)
		}
	}
	if err := o.cancelRunning(ctx, id, sb); err != nil {
		// The stop is not complete while its run may still be running: the sandbox stays
		// stopping, and the reconciler cancels the run and settles it (settleStopped).
		return nil, err
	}
	if final == model.StatusWaking {
		return o.startPod(ctx, id)
	}
	// Only out of stopping: a Delete that moved the sandbox to deleting meanwhile must keep it
	// there (its retry depends on it), and a reconciler that already settled it has done this.
	sb, err = o.setStatusFrom(ctx, id, []model.SandboxStatus{model.StatusStopping}, final, func(s *model.Sandbox) { s.PodName, s.IP = "", "" })
	if errors.Is(err, ErrConflict) {
		if cur, gerr := o.Store.GetSandbox(ctx, id); gerr == nil && cur.Status == final {
			return cur, nil
		}
	}
	return sb, err
}

// removeOrphan deletes a pod startPod created for a sandbox that went away meanwhile (deleted,
// stopped, put to sleep). Pod names are reused per sandbox, so between that observation and the
// deletion another replica could wake the sandbox and create its replacement under the same
// name. The deletion therefore runs under the tenant lock every wake takes, after checking the
// record again:
//   - gone or deleting: nothing wakes it any more.
//   - sleeping, at any revision: a sleeping sandbox has no pod, and none can start while the
//     lock is held, so the name belongs to nobody but this pod. (A stop that was still running
//     when the orphan was observed finishes as sleeping; skipping then left the pod forever,
//     since nothing reconciles the pods of sleeping sandboxes.)
//   - stopping at the observed revision: the stop that missed the pod, not yet finished.
//
// Anything else (waking, running, error, a newer stop) means the sandbox moved on and the name
// may already be a replacement's: the pod is left to its new owner.
func (o *Orchestrator) removeOrphan(ctx context.Context, tenant string, created *model.Sandbox, observed int64) {
	err := o.Store.WithTenantLock(ctx, tenant, func(ctx context.Context) error {
		cur, err := o.Store.GetSandbox(ctx, created.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return err
		case cur.Status == model.StatusDeleting, cur.Status == model.StatusSleeping:
		case cur.Status == model.StatusStopping && cur.Revision == observed:
		default:
			o.Log.Info("sandbox moved on before its orphan pod was removed, leaving the pod", "id", created.ID, "pod", created.PodName, "status", cur.Status)
			return nil
		}
		o.Log.Warn("sandbox went away while its pod was created, removing the pod", "id", created.ID, "pod", created.PodName)
		return o.Runtime.DeletePod(ctx, created)
	})
	if err != nil {
		o.Log.Error("remove orphan pod", "id", created.ID, "pod", created.PodName, "err", err)
	}
}

// detached returns a context that outlives the caller's (a request whose client went away) but
// not forever: work that must finish once a state transition is written, and the bookkeeping of
// its failure.
func (o *Orchestrator) detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), o.Cfg.StopTimeout)
}

// cancelRunning settles the run that was executing in a sandbox whose pod is going away. Only
// a run still running is moved: one its runner finished meanwhile keeps that result, and the
// run.finished event is emitted once, by whoever settled it. An error means the run may still
// be running: Delete keeps the sandbox in deleting and a stop keeps it in stopping, so the
// retry (the reconciler's, or the caller's) settles it.
//
// fence, when set, is the sandbox as the caller observed its stop: the cancellation commits only
// while the record is still stopping (an ErrFenced is nothing to do: the stop was finished
// elsewhere and the run now executing belongs to a replacement pod). Status, not revision:
// other writes bump the revision of a stopping sandbox, and a newer stop of it wants its run
// cancelled just the same.
func (o *Orchestrator) cancelRunning(ctx context.Context, id string, fence *model.Sandbox) error {
	r, err := o.Store.RunningRun(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	// The status and run.finished are one write: a crash between them cannot leave a cancelled
	// run that its watchers never see end.
	evs := []*model.Event{{SandboxID: id, RunID: r.ID, Type: model.EventRunDone, Data: string(model.RunCancelled)}}
	settle := store.Settle{RunID: r.ID, From: []model.RunStatus{model.RunRunning},
		To: model.RunCancelled, ExitCode: r.ExitCode, FinishedAt: time.Now(), Events: evs}
	if fence != nil {
		settle.Sandbox = &store.SandboxFence{ID: fence.ID, Status: fence.Status}
	}
	if _, err := o.Store.SettleRunWithEvents(ctx, settle); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil // settled by its runner or a cancel meanwhile, or the stop moved on (ErrFenced)
		}
		return fmt.Errorf("cancel run %s: %w", r.ID, err)
	}
	o.publish(evs)
	return nil
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
		// A sandbox whose tenant lost the slug (policy list, binding) is not started again: the
		// reconciler would only stop it, and the gateway refuses it anyway.
		if o.Policies != nil && o.Policies.Revoked(sb.Slug, sb.Tenant, sb.AdminGrant) {
			return nil, fmt.Errorf("%w: tenant %s no longer owns slug %s", ErrForbidden, sb.Tenant, sb.Slug)
		}
		if err := o.settleLeftoverRun(ctx, sb); err != nil {
			return nil, err
		}
		return o.startPod(ctx, id)
	default:
		return nil, fmt.Errorf("%w: sandbox is %s", ErrConflict, sb.Status)
	}
}

// Delete stops the pod, removes the volume and then the record. If the cluster refuses, the
// record stays in status `deleting` with the error attached; the reconciler and a repeated
// DELETE retry it, so nothing is silently left behind.
func (o *Orchestrator) Delete(ctx context.Context, id string) error {
	sb, err := o.markDeleting(ctx, id)
	if err != nil {
		return err
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
	if err := o.cancelRunning(ctx, id, nil); err != nil {
		// The record is what lets the retry find the run: without it the run stays running
		// with neither an executor nor anything that reconciles it.
		_, _ = o.mutate(ctx, id, func(s *model.Sandbox) error { s.Error = err.Error(); return nil })
		return err
	}
	err = o.Store.DeleteSandbox(ctx, id)
	o.mu.Lock()
	delete(o.meta, id)
	delete(o.stopSeen, id)
	o.mu.Unlock()
	return err
}

// markDeleting moves the sandbox to deleting under the tenant lock that startPod and Create take,
// with the status it read as the precondition: a wake that already passed its lock sees deleting
// when it records its pod (and removes the pod), and a transition by another writer meanwhile
// (waitReady flipping to running) is read again rather than overwritten.
func (o *Orchestrator) markDeleting(ctx context.Context, id string) (*model.Sandbox, error) {
	var sb *model.Sandbox
	tenant, err := o.tenantOf(ctx, id)
	if err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		err := o.Store.WithTenantLock(ctx, tenant, func(ctx context.Context) error {
			cur, err := o.Store.GetSandbox(ctx, id)
			if err != nil {
				return err
			}
			if cur.Status == model.StatusDeleting {
				sb = cur
				return nil
			}
			sb, err = o.setStatusFrom(ctx, id, []model.SandboxStatus{cur.Status}, model.StatusDeleting, nil)
			return err
		})
		if errors.Is(err, ErrConflict) && attempt < 20 {
			continue
		}
		return sb, err
	}
}

// CreateRun queues a task and wakes the sandbox if needed.
func (o *Orchestrator) CreateRun(ctx context.Context, sandboxID, task string) (*model.Run, error) {
	return o.queueRun(ctx, sandboxID, &model.Run{Task: task})
}

func (o *Orchestrator) queueRun(ctx context.Context, sandboxID string, r *model.Run) (*model.Run, error) {
	r, wake, err := o.enqueue(ctx, sandboxID, r)
	if err != nil {
		return nil, err
	}
	if wake {
		o.wakeForRun(ctx, sandboxID, r.ID)
	}
	return r, nil
}

// enqueue records a queued run and reports whether the sandbox must be woken for it. Waking
// is left to the caller: it takes the tenant lock, so it must happen outside any other lock
// the caller holds (locks are a bounded resource shared by every replica).
func (o *Orchestrator) enqueue(ctx context.Context, sandboxID string, r *model.Run) (*model.Run, bool, error) {
	if strings.TrimSpace(r.Task) == "" {
		return nil, false, fmt.Errorf("%w: task is required", ErrBadRequest)
	}
	sb, err := o.Store.GetSandbox(ctx, sandboxID)
	if err != nil {
		return nil, false, err
	}
	if sb.Status == model.StatusDeleting {
		return nil, false, fmt.Errorf("%w: sandbox is being deleted", ErrConflict)
	}
	r.ID, r.SandboxID, r.Tenant, r.Slug = newID("run"), sandboxID, sb.Tenant, sb.Slug
	r.Status, r.CreatedAt = model.RunQueued, time.Now()
	if err := o.Store.CreateRun(ctx, r); err != nil {
		return nil, false, err
	}
	o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: r.ID, Type: model.EventRunQueued, Data: r.ResumeOf})
	o.Touch(ctx, sandboxID)
	return r, sb.Status == model.StatusSleeping || sb.Status == model.StatusError, nil
}

// wakeForRun wakes a sandbox that has a run waiting. The run is queued either way; a failed
// wake shows in the sandbox status and the run starts on the next successful wake.
func (o *Orchestrator) wakeForRun(ctx context.Context, sandboxID, runID string) {
	if _, err := o.Wake(ctx, sandboxID); err != nil {
		o.Log.Warn("wake for run failed", "sandbox", sandboxID, "run", runID, "err", err)
	}
}

// Input forwards a user message to the agent. The run must exist in this sandbox and still be
// queued or running; otherwise the client would get a false "delivered".
func (o *Orchestrator) Input(ctx context.Context, sandboxID, runID, text string) error {
	if strings.TrimSpace(text) == "" {
		return fmt.Errorf("%w: text is required", ErrBadRequest)
	}
	sb, err := o.Store.GetSandbox(ctx, sandboxID)
	if err != nil {
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
	if !o.streamsInput(sb) {
		// The runner closes a text-mode harness's stdin after the task: an input event would be
		// recorded and never read.
		return fmt.Errorf("%w: a text-mode harness takes no input during a run; send it as a message (it becomes the next run)", ErrConflict)
	}
	o.Touch(ctx, sandboxID)
	return o.emit(ctx, model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventInput, Data: text})
}

// NextRun is NextRunFor a caller that does not name itself: its claims are never handed out again.
func (o *Orchestrator) NextRun(ctx context.Context, sandboxID string, wait time.Duration) (*model.Run, error) {
	return o.NextRunFor(ctx, sandboxID, "", wait)
}

// NextRunFor long-polls for a queued run (agent side) and marks it running, stamped with the
// agent version that is executing it and handed to owner (the pod's instance). A run owner
// claimed and never confirmed (the response was lost: the runner asks again) is handed to it
// again first, under a new attempt; the claim is confirmed by the runner's first call about the
// run (see AckClaim).
func (o *Orchestrator) NextRunFor(ctx context.Context, sandboxID, owner string, wait time.Duration) (*model.Run, error) {
	deadline := time.Now().Add(wait)
	for {
		// A pod that is being stopped or replaced must not pick up work: the run would die with it.
		sb, err := o.Store.GetSandbox(ctx, sandboxID)
		if err != nil || sb.Status != model.StatusRunning {
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
		// run.start was emitted by the claim being handed out again: the run is the same one.
		if r, err := o.Store.ReclaimRun(ctx, sandboxID, owner); err == nil {
			return r, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		// The run records what it executes under, written by the claim itself; later catalogue
		// changes never touch it.
		r, reclaimed, err := o.claim(ctx, sandboxID, store.RunStamp{
			AgentVersion: sb.AgentVersion, AgentRef: sb.AgentRef, AgentRevision: sb.AgentRevision,
			EnvironmentRef: sb.EnvironmentRef, EnvironmentRevision: sb.EnvironmentRevision, Owner: owner,
		})
		if err == nil {
			_ = reclaimed // run.start was appended by the claim itself (store.ClaimRunFor), once
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

// claim takes the oldest queued run of the sandbox. A message run queued while the run it
// follows had no session yet gets that session now: it is read first and written by the claim
// itself (one conditional update), so a failed read leaves the run queued with nothing to undo.
// The claim is decided together with the reclaim check (store.ClaimRunFor): a claim of
// stamp.Owner made meanwhile by the request whose response was lost is handed out instead of
// the next queued run (reclaimed true).
func (o *Orchestrator) claim(ctx context.Context, sandboxID string, stamp store.RunStamp) (*model.Run, bool, error) {
	for {
		q, err := o.Store.QueuedRun(ctx, sandboxID)
		if err != nil {
			return nil, false, err
		}
		session := q.Session
		if q.Mode == model.RunMessage && session == "" && q.ResumeOf != "" {
			if session, err = o.sessionOf(ctx, q.ResumeOf); err != nil {
				return nil, false, fmt.Errorf("session of run %s: %w", q.ResumeOf, err)
			}
		}
		r, reclaimed, err := o.claimAwake(ctx, sandboxID, q.ID, session, stamp)
		if errors.Is(err, errNotAwake) {
			return nil, false, store.ErrNotFound // stopping or gone: the poll waits for a running pod
		}
		if errors.Is(err, store.ErrOwnerBusy) {
			return nil, false, store.ErrNotFound // nothing for this owner until its run is settled
		}
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			continue // claimed by another poller or cancelled meanwhile: the next one in line
		}
		return r, reclaimed, err
	}
}

// sessionOf finds the harness session a message run continues: that of the run it follows, or
// of the nearest earlier one in the chain when that run never reported one (cancelled early).
// The message was queued while those runs were pending, so their sessions were not known yet.
// "" means the chain has no session (or its runs are gone); a failed read is an error, not that.
func (o *Orchestrator) sessionOf(ctx context.Context, runID string) (string, error) {
	for i := 0; runID != "" && i < 100; i++ {
		r, err := o.Store.GetRun(ctx, runID)
		if errors.Is(err, store.ErrNotFound) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if r.Session != "" {
			return r.Session, nil
		}
		runID = r.ResumeOf
	}
	return "", nil
}

// Output appends one line of agent output (see OutputBatch).
func (o *Orchestrator) Output(ctx context.Context, sandboxID, runID, data string) error {
	_, err := o.OutputBatch(ctx, sandboxID, runID, "", 0, []string{data}, false)
	return err
}

// OutputBatch appends agent output to the event stream. Lines that carry usage (Claude Code's
// result line, generic `{"type":"usage"}` records) also update the run's accounting; lines
// that carry the harness session id are remembered for resume. The lines, their usage and
// session, and the progress of batchID are one write: all of it is stored or none. An error
// usually means none, but not always (a commit whose acknowledgement was lost), which is why
// the runner retries under the same batchID: a retry of a batch that was stored stores nothing
// again. partial: lines are only the beginning of the body (it was cut off), so the batch may
// be continued under its id. attempt > 0 refuses an attempt the run has been handed out past.
func (o *Orchestrator) OutputBatch(ctx context.Context, sandboxID, runID, batchID string, attempt int, lines []string, partial bool) (*store.OutputResult, error) {
	b := &store.OutputBatch{SandboxID: sandboxID, RunID: runID, BatchID: batchID, Attempt: attempt, Lines: make([]store.OutputLine, len(lines)), Partial: partial}
	for i, data := range lines {
		l := store.OutputLine{Data: data}
		if u, mode, ok := harness.ParseUsage(data); ok {
			l.Usage, l.UsageTotal = &u, mode == harness.Total
		}
		l.Session, _ = harness.ParseSession(data)
		b.Lines[i] = l
	}
	res, err := o.Store.AppendRunOutput(ctx, b)
	if err != nil {
		return nil, err
	}
	o.publish(res.Events)
	return res, nil
}

// FinishRun is FinishRunAttempt for any attempt.
func (o *Orchestrator) FinishRun(ctx context.Context, sandboxID, runID string, exitCode int, usage *model.Usage) error {
	return o.FinishRunAttempt(ctx, sandboxID, runID, 0, exitCode, usage)
}

// FinishRunAttempt records the result of a run. usage, if given, is the harness's own total and
// overrides whatever was parsed from the output stream. The result and run.finished are one
// write. attempt > 0 refuses (store.ErrStaleAttempt) an attempt the run has been handed out
// past. A rollout deferred until the run ended is applied right after.
func (o *Orchestrator) FinishRunAttempt(ctx context.Context, sandboxID, runID string, attempt, exitCode int, usage *model.Usage) error {
	r, err := o.Store.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if r.SandboxID != sandboxID {
		return store.ErrNotFound
	}
	if usage != nil && usage.IsZero() {
		usage = nil
	}
	to := model.RunDone
	if exitCode != 0 {
		to = model.RunFailed
	}
	done := &model.Event{SandboxID: sandboxID, RunID: runID, Type: model.EventRunDone, Data: string(to)}
	r, err = o.Store.SettleRunWithEvents(ctx, store.Settle{RunID: runID, From: []model.RunStatus{model.RunQueued, model.RunRunning},
		To: to, ExitCode: exitCode, FinishedAt: time.Now(), Usage: usage, Attempt: attempt, Events: []*model.Event{done}})
	if errors.Is(err, store.ErrStaleAttempt) {
		return err
	}
	if errors.Is(err, store.ErrConflict) {
		// Already settled: a retried /finish after a lost acknowledgement, or a cancel that won
		// the race. A cancelled run still gets the tokens its harness reports it spent.
		if usage != nil {
			if err := o.Store.RecordRunUsage(ctx, runID, *usage, true); err != nil && !errors.Is(err, store.ErrConflict) {
				return err
			}
		}
		return nil
	}
	if err != nil {
		return err
	}
	o.publish([]*model.Event{done})
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
	if _, err := o.Store.RunningRun(ctx, id); !errors.Is(err, store.ErrNotFound) {
		if err != nil {
			o.Log.Error("deferred rollout: read running run", "id", id, "err", err)
		}
		return
	}
	o.Log.Info("applying deferred rollout", "id", id, "from", sb.AgentVersion, "to", sb.DesiredVersion)
	if _, err := o.stopPodIf(ctx, id, model.StatusWaking, true); err != nil && !errors.Is(err, ErrConflict) {
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
	case model.RunDone, model.RunFailed:
		return r, nil
	case model.RunCancelled:
		// A repeated cancel delivers the command again if the first never got it out.
		return r, o.EnsureCancelDelivered(ctx, r)
	}
	// The status and the command the runner acts on are one write: a cancelled run always
	// has its run.cancel.
	evs := []*model.Event{
		{SandboxID: sandboxID, RunID: runID, Type: model.EventRunCancel},
		{SandboxID: sandboxID, RunID: runID, Type: model.EventRunDone, Data: string(model.RunCancelled)},
	}
	settled, err := o.Store.SettleRunWithEvents(ctx, store.Settle{RunID: runID, From: []model.RunStatus{model.RunQueued, model.RunRunning},
		To: model.RunCancelled, ExitCode: r.ExitCode, FinishedAt: time.Now(), Events: evs})
	if errors.Is(err, store.ErrConflict) {
		// Finished or cancelled by another writer since the read: that outcome stands.
		cur, err := o.Store.GetRun(ctx, runID)
		if err == nil && cur.Status == model.RunCancelled {
			err = o.EnsureCancelDelivered(ctx, cur)
		}
		return cur, err
	}
	if err != nil {
		return nil, err
	}
	o.publish(evs)
	return settled, nil
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
		// Recorded after a restart that runs detached: a client that hung up meanwhile must not
		// lose the trace of a version change that went through.
		ctx, cancel := o.detached(ctx)
		defer cancel()
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
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		// Not knowing whether a run executes is not "idle": the desired version stays set and the
		// reconciler applies it once the store answers.
		record(model.RolloutDeferred, "", "")
		item.Reason = "cannot tell whether a run is in progress: " + err.Error()
		return item
	}
	if err != nil {
		// Idle when read; the restart decides again, under the claim lock, before it stops anything.
		_, err := o.stopPodIf(ctx, sb.ID, model.StatusWaking, true)
		var notBegun stopNotBegun
		if !errors.Is(err, errRunInProgress) && errors.As(err, &notBegun) {
			// Nothing was stopped (the locked re-check could not read the runs, or another writer
			// moved the sandbox): the desired version stays set, applied when running and idle.
			record(model.RolloutDeferred, "", "")
			item.Reason = "restart not begun: " + err.Error() + "; applied when the sandbox is running and idle"
			return item
		}
		if !errors.Is(err, errRunInProgress) {
			record(model.RolloutNow, "", "")
			if err != nil {
				item.Reason = "restart failed: " + err.Error()
			}
			return item
		}
		// A run was claimed between the read and the restart: go on as if it had been read.
		if r, err = o.Store.RunningRun(ctx, sb.ID); err != nil {
			record(model.RolloutDeferred, "", "")
			item.Reason = "run in progress; applied when it finishes"
			return item
		}
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
		nr, err := o.queueRun(ctx, sb.ID, &model.Run{Task: r.Task, ResumeOf: r.ID, Session: r.Session, Mode: model.RunResume})
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
		// Closing the preview or changing who may see it revokes every sign-in issued so far.
		if sb.Preview != nil && (port == 0 || sb.Preview.Access != access) {
			sb.PreviewGen++
		}
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
	o.started.Store(true)
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

// reconcileStopping finishes a stop that was interrupted (the replica died, or its DeletePod
// failed after the record said stopping). Once the runtime no longer knows the pod, the sandbox
// settles as sleeping so it can be woken again. A pod still there after StopTimeout is deleted
// again, in the background so a slow termination does not hold up the pass (see takeOverStop).
func (o *Orchestrator) reconcileStopping(ctx context.Context, sb *model.Sandbox, now time.Time) {
	_, _, err := o.Runtime.PodStatus(ctx, sb)
	if errors.Is(err, ErrPodNotFound) {
		o.mu.Lock()
		busy := o.stopping[sb.ID]
		o.mu.Unlock()
		if busy {
			return // this replica's stop is still cleaning up after the pod: it settles itself
		}
		o.forgetStop(sb.ID)
		if err := o.settleStopped(ctx, sb); err != nil {
			o.Log.Warn("settle a stopped sandbox", "id", sb.ID, "err", err) // the next pass tries again
		}
		return
	}
	if err != nil && !errors.Is(err, ErrPodTerminated) {
		o.Log.Warn("cannot observe pod of a stopping sandbox", "id", sb.ID, "pod", sb.PodName, "err", err)
		return
	}
	o.mu.Lock()
	first, seen := o.stopSeen[sb.ID]
	if !seen {
		o.stopSeen[sb.ID], first = now, now
	}
	if o.stopping[sb.ID] || now.Sub(first) < o.Cfg.StopTimeout {
		o.mu.Unlock()
		return // a stop in progress, here or (for all we know) on another replica
	}
	o.stopping[sb.ID] = true
	o.mu.Unlock()
	o.Log.Warn("sandbox stuck stopping with its pod alive, deleting the pod again", "id", sb.ID, "pod", sb.PodName)
	go o.takeOverStop(sb)
}

// errStopMoved: the stuck stop was finished or replaced by another writer before the takeover
// got the lock; there is nothing left that belongs to it.
var errStopMoved = errors.New("stop finished elsewhere")

// takeOverStop deletes the pod of a stuck stop, retires its identities, cancels its run and
// settles the sandbox as sleeping. The whole sequence runs under the tenant lock, fenced on the
// revision the reconciler observed: every wake takes that lock to leave sleeping, so while the
// cleanup runs no replacement pod, identity or run can exist, even if another replica (or the
// slow original stopper) settles the sandbox meanwhile. The pod name, the "current" identities
// and the running run therefore all still belong to the stopped pod. If the record moved on
// before the lock was taken (finished elsewhere, woken, stopped again), nothing is touched.
// The lock is held across DeletePod: the recovery path is rare and its tenant waits briefly.
func (o *Orchestrator) takeOverStop(seen *model.Sandbox) {
	defer func() { o.mu.Lock(); delete(o.stopping, seen.ID); o.mu.Unlock() }()
	ctx, cancel := o.detached(context.Background())
	defer cancel()
	err := o.Store.WithTenantLock(ctx, seen.Tenant, func(ctx context.Context) error {
		cur, err := o.Store.GetSandbox(ctx, seen.ID)
		if err != nil {
			return err
		}
		if cur.Status != model.StatusStopping || cur.Revision != seen.Revision {
			return errStopMoved
		}
		if err := o.Runtime.DeletePod(ctx, cur); err != nil {
			return fmt.Errorf("delete pod: %w", err)
		}
		if o.Retirer != nil {
			if err := o.Retirer.RetireSandbox(ctx, cur.ID); err != nil {
				o.Log.Error("retire identities", "id", cur.ID, "err", err)
			}
		}
		return o.settleStopped(ctx, cur)
	})
	switch {
	case err == nil, errors.Is(err, errStopMoved), errors.Is(err, store.ErrNotFound):
		o.forgetStop(seen.ID)
	default:
		o.Log.Error("take over a stuck stop", "id", seen.ID, "err", err) // the next pass tries again
	}
}

// settleStopped moves a sandbox whose pod is gone from stopping to sleeping, once the run that
// was executing in it is cancelled. Until then it stays stopping (the reconciler tries again):
// a sleeping sandbox can be woken, and a healthy new pod would leave the old run running with
// nothing that ever settles it.
//
// seen is the sandbox as the caller observed the stop: the run is cancelled only while the
// record is still stopping (store.Settle.Sandbox). Another replica may have finished the
// stop meanwhile and woken the sandbox; the run executing then is a replacement pod's.
func (o *Orchestrator) settleStopped(ctx context.Context, seen *model.Sandbox) error {
	id := seen.ID
	if err := o.cancelRunning(ctx, id, seen); err != nil {
		return err
	}
	_, _ = o.setStatusFrom(ctx, id, []model.SandboxStatus{model.StatusStopping}, model.StatusSleeping, func(s *model.Sandbox) { s.PodName, s.IP = "", "" })
	return nil
}

// forgetStop drops what the reconciler remembered about a stuck stop.
func (o *Orchestrator) forgetStop(id string) {
	o.mu.Lock()
	delete(o.stopSeen, id)
	o.mu.Unlock()
}

// failRun settles a run whose executor is gone: status failed, the reason in the output, the
// usual run.finished event. Clients watching the run see it end instead of hanging forever.
//
// fence is the sandbox as the caller observed it when it concluded the run was lost; the
// settle commits only while the sandbox is still in that state. Another replica may have
// woken the sandbox meanwhile and started a run in the new pod: RunningRun then returns that
// run, and failing it would kill healthy work. A sandbox that moved on makes the cleanup
// obsolete: store.ErrFenced is returned, so a caller does nothing further on the strength of
// its stale observation. A run settled by its runner or a cancel meanwhile is nil.
func (o *Orchestrator) failRun(ctx context.Context, fence store.SandboxFence, r *model.Run, reason string) error {
	// The status, the reason and run.finished are one write.
	evs := []*model.Event{
		{SandboxID: fence.ID, RunID: r.ID, Type: model.EventRunOutput, Data: "[control plane] run lost: " + reason},
		{SandboxID: fence.ID, RunID: r.ID, Type: model.EventRunDone, Data: string(model.RunFailed)},
	}
	if _, err := o.Store.SettleRunWithEvents(ctx, store.Settle{RunID: r.ID, From: []model.RunStatus{model.RunRunning},
		To: model.RunFailed, ExitCode: -1, FinishedAt: time.Now(), Events: evs, Sandbox: &fence}); err != nil {
		if errors.Is(err, store.ErrFenced) {
			return err
		}
		if !errors.Is(err, store.ErrConflict) {
			o.Log.Error("fail run", "run", r.ID, "err", err)
			return err
		}
		return nil // settled by its runner or a cancel meanwhile
	}
	o.publish(evs)
	return nil
}

// IdleLoop is the single-replica form of Run, kept for callers that manage leadership themselves.
func (o *Orchestrator) IdleLoop(ctx context.Context) {
	o.started.Store(true)
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
	o.purgeFSBlobs(ctx)
	now := time.Now()
	for _, sb := range sbs {
		if sb.Status != model.StatusStopping {
			o.forgetStop(sb.ID)
		}
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
			o.fail(ctx, sb.ID, model.StatusCreating, "creation did not complete (control plane restarted?); wake to retry")
			continue
		case sb.Status == model.StatusStopping:
			o.reconcileStopping(ctx, sb, now)
			continue
		}
		if sb.Status != model.StatusRunning {
			// A run marked running while the sandbox has no pod is a leftover of a lost pod or a
			// crashed replica: nobody will ever finish it.
			// Fenced on the status seen: status is enough here, because the sandbox comes back to
			// sleeping or error only through a stop or a lost pod, and both settle a newer run first.
			if r, err := o.Store.RunningRun(ctx, sb.ID); err == nil {
				_ = o.failRun(ctx, store.SandboxFence{ID: sb.ID, Status: sb.Status}, r, "sandbox is "+string(sb.Status)+" while the run was executing") // retried next pass; Wake settles it first
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
			if err := o.settleLostPod(ctx, sb, reason); err != nil {
				o.Log.Warn("settle a lost pod", "id", sb.ID, "err", err) // the next pass sees the pod gone again and retries
			}
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

// errRunInProgress: a stop that must leave running work alone found a run executing.
var errRunInProgress = fmt.Errorf("%w: a run is in progress", ErrConflict)

// errNotAwake: a claim found the sandbox not running (stopping, replaced, gone).
var errNotAwake = errors.New("sandbox is not running")

// claimLock names the lock, shared by every replica, under which a run is claimed and under
// which a stop that spares running work decides that none runs. Without it the two interleave:
// the stop reads "no run", NextRun (having read "running") claims, the stop moves the sandbox
// to stopping, and the run just handed out dies with its pod. With it, whichever goes second
// sees the other's write: the claim sees stopping and leaves the run queued, or the stop sees
// the running run and does not happen.
func claimLock(sandboxID string) string { return "claim:" + sandboxID }

// toStopping moves the sandbox to stopping from a status that has (or is getting) a pod. With
// idle, only while no run executes, decided under claimLock; a failed read of the running run is
// an error, never taken for "no run".
func (o *Orchestrator) toStopping(ctx context.Context, id string, idle bool) (*model.Sandbox, error) {
	from := []model.SandboxStatus{model.StatusRunning, model.StatusWaking, model.StatusError}
	if !idle {
		return o.setStatusFrom(ctx, id, from, model.StatusStopping, nil)
	}
	var sb *model.Sandbox
	moved := false
	err := o.Store.WithTenantLock(ctx, claimLock(id), func(ctx context.Context) error {
		_, err := o.Store.RunningRun(ctx, id)
		if err == nil {
			return errRunInProgress
		}
		if !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %w", errRunUnknown, err)
		}
		if sb, err = o.setStatusFrom(ctx, id, from, model.StatusStopping, nil); err != nil {
			return err
		}
		moved = true
		return nil
	})
	if moved {
		// The move is committed (it does not go through the lock's transaction): a failure to
		// release the lock afterwards must not leave the sandbox stopping with nobody stopping it.
		if err != nil {
			o.Log.Warn("claim lock released with an error after the move to stopping", "id", id, "err", err)
		}
		return sb, nil
	}
	return nil, err
}

// claimAwake claims a queued run under claimLock, only while the sandbox is running: a pod that
// is being stopped or replaced must not pick up work. errNotAwake otherwise. The claim is
// store.ClaimRunFor: a claim of stamp.Owner it never confirmed is handed out instead (reclaimed),
// and a new claim carries its run.start, written in its transaction.
func (o *Orchestrator) claimAwake(ctx context.Context, sandboxID, runID, session string, stamp store.RunStamp) (*model.Run, bool, error) {
	var r *model.Run
	var start *model.Event
	err := o.Store.WithTenantLock(ctx, claimLock(sandboxID), func(ctx context.Context) error {
		sb, err := o.Store.GetSandbox(ctx, sandboxID)
		if errors.Is(err, store.ErrNotFound) {
			return errNotAwake
		}
		if err != nil {
			return err
		}
		if sb.Status != model.StatusRunning {
			return errNotAwake
		}
		r, start, err = o.Store.ClaimRunFor(ctx, sandboxID, runID, time.Now(), session, stamp)
		return err
	})
	if start != nil {
		o.publish([]*model.Event{start})
	}
	if r != nil {
		// The claim is committed (it does not go through the lock's transaction): a failure to
		// release the lock afterwards must not turn it into an error, or the run stays running
		// with no runner that knows it has it.
		if err != nil {
			o.Log.Warn("claim lock released with an error after a claim", "sandbox", sandboxID, "run", r.ID, "err", err)
		}
		return r, start == nil, nil
	}
	return nil, false, err
}

// errRunUnknown: a stop that must leave running work alone could not read whether a run executes.
var errRunUnknown = errors.New("cannot tell whether a run is in progress")

// stopNotBegun wraps an error of stopPodIf returned before the sandbox moved to stopping: nothing
// was changed, so a rollout is still pending rather than failed.
type stopNotBegun struct{ err error }

func (e stopNotBegun) Error() string { return e.err.Error() }
func (e stopNotBegun) Unwrap() error { return e.err }

// tenantOf returns the sandbox's tenant (cached once read: it never changes), or the error of
// the read. Unlike metaOf it never answers "" for a sandbox it could not read: the tenant names
// the lock that keeps a wake's volume provisioning and a Delete apart.
func (o *Orchestrator) tenantOf(ctx context.Context, id string) (string, error) {
	o.mu.Lock()
	m, ok := o.meta[id]
	o.mu.Unlock()
	if ok {
		return m.tenant, nil
	}
	sb, err := o.Store.GetSandbox(ctx, id)
	if err != nil {
		return "", err
	}
	o.remember(sb)
	return sb.Tenant, nil
}

// publish hands events the store appended to the local hub (unless the listener does).
func (o *Orchestrator) publish(evs []*model.Event) {
	if o.Hub == nil || o.ListenerPublishes {
		return
	}
	for _, e := range evs {
		o.Hub.Publish(*e)
	}
}

// EnsureCancelDelivered appends run.cancel to a cancelled run that has none: one cancelled by
// a replica of an older release that wrote the status and then failed to write the command, or
// settled by the pod going away. The runner acts on the event, not on the status.
func (o *Orchestrator) EnsureCancelDelivered(ctx context.Context, r *model.Run) error {
	if r.Status != model.RunCancelled {
		return nil
	}
	e := &model.Event{SandboxID: r.SandboxID, RunID: r.ID, Type: model.EventRunCancel}
	added, err := o.Store.EnsureRunEvent(ctx, e)
	if err != nil {
		return err
	}
	if added {
		o.publish([]*model.Event{e})
	}
	return nil
}

// AckClaim records that owner received attempt of the run (its first call about it): the run
// is no longer handed out again by NextRunFor. A call naming no attempt confirms the current
// one (a runner of an older release). store.ErrStaleAttempt when the run was handed out past
// attempt. Nothing to do for a run that is not running, or not owner's.
func (o *Orchestrator) AckClaim(ctx context.Context, r *model.Run, owner string, attempt int) error {
	if attempt > 0 && attempt != r.Attempt {
		return store.ErrStaleAttempt
	}
	if r.Status != model.RunRunning || r.ClaimAcked || owner == "" || r.ClaimedBy != owner {
		return nil
	}
	if attempt == 0 {
		attempt = r.Attempt
	}
	return o.Store.AckRunClaim(ctx, r.ID, attempt)
}

// settleLeftoverRun fails a run still marked running in a sandbox about to get a new pod
// (sleeping or error: no pod, so no runner executes it): the reconciler's settlement of a lost
// pod's run that failed, or has not run yet. A failure fails the wake: with the new pod
// healthy, nothing would ever settle the old run.
func (o *Orchestrator) settleLeftoverRun(ctx context.Context, sb *model.Sandbox) error {
	r, err := o.Store.RunningRun(ctx, sb.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	err = o.failRun(ctx, store.SandboxFence{ID: sb.ID, Status: sb.Status}, r, "sandbox is "+string(sb.Status)+" while the run was executing")
	if errors.Is(err, store.ErrFenced) {
		return nil // woken elsewhere meanwhile: the start that follows sees the new status
	}
	return err
}

// settleLostPod cleans up after a running sandbox whose pod the reconciler observed gone: it
// fails the run that was executing, retires the pod's identities and moves the sandbox to
// error, so a wake can start a new pod.
//
// The observation is stale by the time the cleanup runs. Another replica may have stopped the
// sandbox (a forced sleep), woken it, and the replacement pod claimed a new run: the sandbox
// reads running again, and RunningRun returns the new run. So the cleanup runs under the tenant
// lock, which every start takes to leave sleeping or error (startPod): while it is held, no
// replacement pod can come up. Inside it the sandbox must still be at the revision observed
// (every status change bumps it; activity does not), and the run is settled fenced on that
// revision. A sandbox that moved on is left alone: no run failed, no identity retired, no
// status changed; the next pass observes it afresh.
//
// A failed settlement leaves the sandbox running (a wake is a no-op) until the run is settled:
// in error it could be woken, and with a healthy new pod nothing would settle the old run. The
// next pass sees the pod gone again and retries.
func (o *Orchestrator) settleLostPod(ctx context.Context, seen *model.Sandbox, reason string) error {
	return o.Store.WithTenantLock(ctx, seen.Tenant, func(ctx context.Context) error {
		cur, err := o.Store.GetSandbox(ctx, seen.ID)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if cur.Status != model.StatusRunning || cur.Revision != seen.Revision {
			return nil // moved on since the pod was seen gone
		}
		fence := store.SandboxFence{ID: cur.ID, Status: model.StatusRunning, Revision: cur.Revision}
		r, err := o.Store.RunningRun(ctx, cur.ID)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return err // cannot tell whether a run is left: the next pass looks again
		default:
			if err := o.failRun(ctx, fence, r, reason); errors.Is(err, store.ErrFenced) {
				return nil // a stop got to it first: it cancels the run itself
			} else if err != nil {
				return err
			}
		}
		if o.Retirer != nil {
			_ = o.Retirer.RetireSandbox(ctx, cur.ID)
		}
		_, _ = o.setStatusFrom(ctx, cur.ID, []model.SandboxStatus{model.StatusRunning}, model.StatusError, func(s *model.Sandbox) {
			s.Error = reason + "; wake to start a new pod"
			s.PodName, s.IP = "", ""
		})
		return nil
	})
}
