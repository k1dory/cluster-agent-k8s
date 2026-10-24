// Package catalog is the configuration catalogue: versioned AgentDefinitions and
// EnvironmentProfiles per tenant (plus shared ones the admin manages), with strict schemas,
// append-only revisions and optimistic concurrency. A sandbox is created from an agent
// reference; the environment the agent names is rendered into a model.Launch that stays on
// the sandbox, and every run records the revisions it executed under.
//
// The same document shape is used by the API (JSON) and by declarative files (YAML):
//
//	kind: EnvironmentProfile | AgentDefinition
//	name: <dns label>
//	description: ...
//	spec: {...}                 (EnvironmentSpec or AgentSpec)
//	expected_revision: <int>    (optional, API only: refuse unless the latest revision is this)
//
// References ("environment" in an agent, "agent_ref" at creation) are "name", "name@N" to pin
// a revision, or "shared/name[@N]" for a shared item. A bare name is looked up in the caller's
// scope first, then among the shared items, and is stored in the form it resolved to, so the
// scope of a dependency is fixed when the document is written: a tenant later creating an
// item of the same name does not capture references that resolved to the shared one.
package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// Errors the API maps to status codes (shared by every resource kind, see package resource).
var (
	ErrInvalid   = res.ErrInvalid
	ErrForbidden = res.ErrForbidden
	ErrConflict  = res.ErrConflict
	ErrNotFound  = res.ErrNotFound
)

// Document is the wire and file form of an item (resource.Document).
type Document = res.Document

// Parsers, re-exported for the API and sandboxctl.
var (
	ParseYAML    = res.ParseYAML
	ParseYAMLAll = res.ParseYAMLAll
	ParseJSON    = res.ParseJSON
)

// SharedPrefix marks a reference to a shared item: "shared/name".
const SharedPrefix = res.SharedPrefix

// HarnessSpec is how the agent process is started inside the pod.
type HarnessSpec struct {
	Command       string `yaml:"command,omitempty" json:"command,omitempty"`
	ResumeCommand string `yaml:"resume_command,omitempty" json:"resume_command,omitempty"`
	ResumePrompt  string `yaml:"resume_prompt,omitempty" json:"resume_prompt,omitempty"`
	// Input: "text" (default; a line on stdin) or "stream-json" (Claude Code's streaming
	// input, which keeps the conversation open: follow-up messages reach the running harness).
	// ChatIdle: seconds without a new message after a turn before the runner closes an open
	// conversation (0 = runtime default, 600). Between runs the conversation continues through
	// ResumeCommand with $SANDBOX_SESSION and the message in $SANDBOX_RESUME_PROMPT.
	Input    string `yaml:"input,omitempty" json:"input,omitempty"`
	ChatIdle *int   `yaml:"chat_idle,omitempty" json:"chat_idle,omitempty"`
}

// ModelSpec names the model and its client settings.
type ModelSpec struct {
	Name string            `yaml:"name,omitempty" json:"name,omitempty"` // exported by the platform as SANDBOX_MODEL / ANTHROPIC_MODEL
	Env  map[string]string `yaml:"env,omitempty" json:"env,omitempty"`   // e.g. ANTHROPIC_BASE_URL; platform names are refused
}

// ResourcesSpec sizes the pod and its workspace. Quantities are Kubernetes quantities, must be
// positive, and a request must not exceed its limit.
type ResourcesSpec struct {
	CPURequest    string `yaml:"cpu_request,omitempty" json:"cpu_request,omitempty"`
	CPULimit      string `yaml:"cpu_limit,omitempty" json:"cpu_limit,omitempty"`
	MemoryRequest string `yaml:"memory_request,omitempty" json:"memory_request,omitempty"`
	MemoryLimit   string `yaml:"memory_limit,omitempty" json:"memory_limit,omitempty"`
	VolumeSize    string `yaml:"volume_size,omitempty" json:"volume_size,omitempty"`
}

// LifecycleSpec sets the sandbox defaults a creation request may still override.
type LifecycleSpec struct {
	IdleTimeout   *int  `yaml:"idle_timeout,omitempty" json:"idle_timeout,omitempty"` // seconds; 0 = never sleep
	TTL           *int  `yaml:"ttl,omitempty" json:"ttl,omitempty"`                   // seconds; 0 = keep
	WakeOnPreview *bool `yaml:"wake_on_preview,omitempty" json:"wake_on_preview,omitempty"`
}

// EnvironmentSpec is an EnvironmentProfile: everything about how a pod runs except the task.
type EnvironmentSpec struct {
	Image        string            `yaml:"image" json:"image"` // version name from the catalogue; the admin may use an image reference
	Harness      HarnessSpec       `yaml:"harness,omitempty" json:"harness,omitempty"`
	Model        ModelSpec         `yaml:"model,omitempty" json:"model,omitempty"`
	Resources    ResourcesSpec     `yaml:"resources,omitempty" json:"resources,omitempty"`
	Lifecycle    LifecycleSpec     `yaml:"lifecycle,omitempty" json:"lifecycle,omitempty"`
	RuntimeClass string            `yaml:"runtime_class,omitempty" json:"runtime_class,omitempty"`
	Env          map[string]string `yaml:"env,omitempty" json:"env,omitempty"` // agent container only; platform names (model.PlatformEnv) are refused
}

// AgentSpec is an AgentDefinition: which policy, which environment, what the agent is told.
type AgentSpec struct {
	Policy       string   `yaml:"policy" json:"policy"`           // policy slug (ownership is checked)
	Environment  string   `yaml:"environment" json:"environment"` // "name" (latest at creation), "name@N", "shared/name[@N]"; stored as resolved
	Repo         string   `yaml:"repo,omitempty" json:"repo,omitempty"`
	Instructions string   `yaml:"instructions,omitempty" json:"instructions,omitempty"`
	Connections  []string `yaml:"connections,omitempty" json:"connections,omitempty"` // Connection references ("name", "shared/name"); stored as resolved
}

// Images resolves what an environment names as image (orchestrator.Config.ResolveVersion).
type Images interface {
	ResolveVersion(v string, admin bool) (string, error)
}

// Policies answers whether a policy slug exists and who may use it (the policy set, or the
// guard that adds PolicyBindings to it).
type Policies interface {
	AllowedFor(slug, tenant string) bool
	Slugs() []string
}

// Connections resolves a connection reference from a tenant's scope to its canonical form
// (the connections service).
type Connections interface {
	Canonical(ctx context.Context, tenant, ref string) (string, error)
}

// Tenants says which environments a tenant may use (tenant settings).
type Tenants interface {
	EnvironmentAllowed(tenant, ref string) bool
}

// Service validates, stores and resolves catalogue items.
type Service struct {
	Store       store.Catalog
	Images      Images
	Policies    Policies    // optional
	Connections Connections // optional: without it, agents may not name connections
	Tenants     Tenants     // optional: per-tenant allowed environments
}

// Put validates a document and appends it as a new revision. who is recorded as the author.
// tenant is the scope the caller works in ("" = shared, admin only); admin relaxes what an
// image may name and lets the policy be one the tenant does not own.
func (s *Service) Put(ctx context.Context, kind, tenant string, d *Document, admin bool, who string) (*model.CatalogItem, error) {
	it, err := s.Validate(ctx, kind, tenant, d, admin, who)
	if err != nil {
		return nil, err
	}
	if err := s.Store.PutItem(ctx, it, d.Expected()); err != nil {
		return nil, err
	}
	return it, nil
}

// Validate checks a document against the catalogue (references are looked up in Store) and
// returns the item it would become, canonical spec included, without writing anything.
func (s *Service) Validate(ctx context.Context, kind, tenant string, d *Document, admin bool, who string) (*model.CatalogItem, error) {
	if err := res.CheckDocument(d, kind); err != nil {
		return nil, err
	}
	spec, err := s.validate(ctx, kind, tenant, d.Spec, admin)
	if err != nil {
		return nil, err
	}
	return &model.CatalogItem{Kind: kind, Tenant: tenant, Name: d.Name, Description: d.Description, Spec: spec, CreatedBy: who}, nil
}

// validate decodes the spec strictly, checks it and returns it re-encoded in canonical form.
func (s *Service) validate(ctx context.Context, kind, tenant string, raw json.RawMessage, admin bool) (json.RawMessage, error) {
	switch kind {
	case model.KindEnvironment:
		var e EnvironmentSpec
		if err := res.DecodeStrict(raw, &e); err != nil {
			return nil, err
		}
		if e.Image == "" {
			return nil, fmt.Errorf("%w: spec.image is required", ErrInvalid)
		}
		if s.Images != nil {
			if _, err := s.Images.ResolveVersion(e.Image, admin); err != nil {
				return nil, fmt.Errorf("%w: spec.image: %v", ErrInvalid, err)
			}
		}
		if err := validateResources(e.Resources); err != nil {
			return nil, err
		}
		if e.Harness.Input != "" && e.Harness.Input != harness.InputText && e.Harness.Input != harness.InputStreamJSON {
			return nil, fmt.Errorf("%w: spec.harness.input must be %s or %s", ErrInvalid, harness.InputText, harness.InputStreamJSON)
		}
		if e.Harness.ChatIdle != nil && *e.Harness.ChatIdle < 0 {
			return nil, fmt.Errorf("%w: spec.harness.chat_idle must be >= 0", ErrInvalid)
		}
		if e.Lifecycle.IdleTimeout != nil && *e.Lifecycle.IdleTimeout < 0 || e.Lifecycle.TTL != nil && *e.Lifecycle.TTL < 0 {
			return nil, fmt.Errorf("%w: spec.lifecycle values must be >= 0", ErrInvalid)
		}
		for field, vars := range map[string]map[string]string{"spec.env": e.Env, "spec.model.env": e.Model.Env} {
			for k := range vars {
				if k == "" || strings.ContainsAny(k, "= \t\n") {
					return nil, fmt.Errorf("%w: %s: %q is not a variable name", ErrInvalid, field, k)
				}
				if model.PlatformEnv(k) {
					return nil, fmt.Errorf("%w: %s: %s is set by the platform and cannot be overridden by a profile", ErrInvalid, field, k)
				}
			}
		}
		return json.Marshal(e)
	case model.KindAgent:
		var a AgentSpec
		if err := res.DecodeStrict(raw, &a); err != nil {
			return nil, err
		}
		if !res.NameRe.MatchString(a.Policy) {
			return nil, fmt.Errorf("%w: spec.policy must be a policy slug", ErrInvalid)
		}
		if s.Policies != nil {
			known := false
			for _, sl := range s.Policies.Slugs() {
				known = known || sl == a.Policy || sl == "default"
			}
			if !known {
				return nil, fmt.Errorf("%w: spec.policy %q: no such policy", ErrInvalid, a.Policy)
			}
			if tenant != "" && !admin && !s.Policies.AllowedFor(a.Policy, tenant) {
				return nil, fmt.Errorf("%w: tenant %s may not use policy %s", ErrForbidden, tenant, a.Policy)
			}
		}
		ref, err := res.ParseRef(a.Environment)
		if err != nil {
			return nil, fmt.Errorf("%w: spec.environment: %v", ErrInvalid, err)
		}
		env, err := res.Lookup(ctx, s.Store, model.KindEnvironment, tenant, ref)
		if err != nil {
			return nil, fmt.Errorf("%w: spec.environment %q: %v", ErrInvalid, a.Environment, err)
		}
		// Fix the scope the reference resolved to: a shared environment stays "shared/..." however
		// the tenant names its own items later.
		a.Environment = ref.InScope(env, tenant)
		if s.Tenants != nil && tenant != "" && !s.Tenants.EnvironmentAllowed(tenant, res.RefOf(env, tenant)) {
			return nil, fmt.Errorf("%w: environment %s is not allowed for tenant %s (tenant settings)", ErrForbidden, a.Environment, tenant)
		}
		seen := map[string]bool{}
		for i, c := range a.Connections {
			if s.Connections == nil {
				return nil, fmt.Errorf("%w: spec.connections: connections are not enabled", ErrInvalid)
			}
			canon, err := s.Connections.Canonical(ctx, tenant, c)
			if err != nil {
				return nil, fmt.Errorf("%w: spec.connections %q: %v", ErrInvalid, c, err)
			}
			if seen[canon] {
				return nil, fmt.Errorf("%w: spec.connections: %q named twice", ErrInvalid, c)
			}
			seen[canon] = true
			a.Connections[i] = canon
		}
		return json.Marshal(a)
	}
	return nil, fmt.Errorf("%w: unknown kind %q", ErrInvalid, kind)
}

func intOf(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// RefOf is the reference string that names an item from tenant's point of view.
func RefOf(it *model.CatalogItem, tenant string) string { return res.RefOf(it, tenant) }

// validateResources checks the quantities: parseable, positive, request within limit.
func validateResources(r ResourcesSpec) error {
	parse := func(field, v string) (*resource.Quantity, error) {
		if v == "" {
			return nil, nil
		}
		q, err := resource.ParseQuantity(v)
		if err != nil {
			return nil, fmt.Errorf("%w: spec.resources.%s %q: %v", ErrInvalid, field, v, err)
		}
		if q.Sign() <= 0 {
			return nil, fmt.Errorf("%w: spec.resources.%s %q: must be positive", ErrInvalid, field, v)
		}
		return &q, nil
	}
	for _, pair := range []struct{ req, lim, reqV, limV string }{
		{"cpu_request", "cpu_limit", r.CPURequest, r.CPULimit},
		{"memory_request", "memory_limit", r.MemoryRequest, r.MemoryLimit},
	} {
		req, err := parse(pair.req, pair.reqV)
		if err != nil {
			return err
		}
		lim, err := parse(pair.lim, pair.limV)
		if err != nil {
			return err
		}
		if req != nil && lim != nil && req.Cmp(*lim) > 0 {
			return fmt.Errorf("%w: spec.resources.%s %q exceeds %s %q", ErrInvalid, pair.req, pair.reqV, pair.lim, pair.limV)
		}
	}
	_, err := parse("volume_size", r.VolumeSize)
	return err
}

// Get returns one item visible from tenant (own, else shared); revision 0 = latest.
func (s *Service) Get(ctx context.Context, kind, tenant, name string, revision int) (*model.CatalogItem, error) {
	return res.Lookup(ctx, s.Store, kind, tenant, res.Ref{Name: name, Rev: revision})
}

// List returns the latest revisions visible from tenant: its own items and the shared ones
// it does not shadow.
func (s *Service) List(ctx context.Context, kind, tenant string) ([]*model.CatalogItem, error) {
	return res.ListVisible(ctx, s.Store, kind, tenant)
}

// Revisions lists an item's whole history, deleted revisions included (own scope, else shared).
func (s *Service) Revisions(ctx context.Context, kind, tenant, name string) ([]*model.CatalogItem, error) {
	return res.Revisions(ctx, s.Store, kind, tenant, name)
}

// Delete hides an item in the given scope (a tenant cannot delete shared items). Its revisions
// stay as history and can no longer be resolved; a later write continues the numbering.
func (s *Service) Delete(ctx context.Context, kind, tenant, name string) error {
	return s.Store.DeleteItem(ctx, kind, tenant, name)
}

// Resolved is what an agent reference turns into for a sandbox creation.
type Resolved struct {
	Agent          *model.CatalogItem
	Environment    *model.CatalogItem
	AgentRef       string   // the agent as named from the caller's scope: "name" or "shared/name"
	EnvironmentRef string   // the environment as named from the agent's scope
	Connections    []string // the agent's connections as named from the caller's scope
	AgentSpec      AgentSpec
	EnvSpec        EnvironmentSpec
	Launch         model.Launch
	Image          string // resolved image reference
}

// Resolve turns "agent", "agent@N" or "shared/agent[@N]" into the agent revision, the
// environment revision it names (pinned, or the latest at this moment, in the scope the agent
// was written with) and the Launch rendered from them.
func (s *Service) Resolve(ctx context.Context, tenant, agentRef string, admin bool) (*Resolved, error) {
	ar, err := res.ParseRef(agentRef)
	if err != nil {
		return nil, fmt.Errorf("%w: agent_ref: %v", ErrInvalid, err)
	}
	agent, err := res.Lookup(ctx, s.Store, model.KindAgent, tenant, ar)
	if err != nil {
		return nil, fmt.Errorf("agent %s: %w", agentRef, err)
	}
	var as AgentSpec
	if err := json.Unmarshal(agent.Spec, &as); err != nil {
		return nil, err
	}
	er, err := res.ParseRef(as.Environment)
	if err != nil {
		return nil, fmt.Errorf("%w: agent %s environment: %v", ErrInvalid, agentRef, err)
	}
	// The environment is looked up in the agent's own scope, exactly as stored: "shared/..."
	// only among the shared items, a bare name only among the agent's tenant's (the scope was
	// fixed when the agent was written). Never another tenant's.
	env, err := s.Store.GetItem(ctx, model.KindEnvironment, er.Scope(agent.Tenant), er.Name, er.Rev)
	if err != nil {
		return nil, fmt.Errorf("agent %s environment %s: %w", agentRef, as.Environment, err)
	}
	// Tenant settings may confine the tenant to some environments; checked at creation too, so
	// an agent written before the settings changed does not keep an environment it lost.
	if s.Tenants != nil && tenant != "" && !s.Tenants.EnvironmentAllowed(tenant, res.RefOf(env, tenant)) {
		return nil, fmt.Errorf("%w: environment %s is not allowed for tenant %s (tenant settings)", ErrForbidden, as.Environment, tenant)
	}
	var es EnvironmentSpec
	if err := json.Unmarshal(env.Spec, &es); err != nil {
		return nil, err
	}
	image := es.Image
	if s.Images != nil {
		// An image reference the environment's author was allowed to write stays usable by the
		// tenant that references the environment: shared environments are admin-written.
		if image, err = s.Images.ResolveVersion(es.Image, admin || env.Tenant == ""); err != nil {
			return nil, fmt.Errorf("environment %s: %w", as.Environment, err)
		}
	}
	// The profile's variables, model settings first. Model name and instructions are not
	// variables: the runtime exports them itself (SANDBOX_MODEL, ANTHROPIC_MODEL,
	// SANDBOX_INSTRUCTIONS) so a profile cannot carry anything under a platform name.
	envVars := map[string]string{}
	for k, v := range es.Model.Env {
		envVars[k] = v
	}
	for k, v := range es.Env {
		envVars[k] = v
	}
	if len(envVars) == 0 {
		envVars = nil
	}
	// A shared agent's connections are shared ones: name them so from the caller's scope.
	var conns []string
	for _, c := range as.Connections {
		if agent.Tenant == "" && tenant != "" && !strings.HasPrefix(c, res.SharedPrefix) {
			c = res.SharedPrefix + c
		}
		conns = append(conns, c)
	}
	return &Resolved{
		Agent: agent, Environment: env, AgentRef: res.RefOf(agent, tenant), EnvironmentRef: res.RefOf(env, agent.Tenant), Connections: conns,
		AgentSpec: as, EnvSpec: es, Image: image,
		Launch: model.Launch{
			Image: image, HarnessCommand: es.Harness.Command, HarnessResumeCommand: es.Harness.ResumeCommand,
			ResumePrompt: es.Harness.ResumePrompt, HarnessInput: es.Harness.Input, ChatIdle: intOf(es.Harness.ChatIdle),
			Model: es.Model.Name, Instructions: as.Instructions, Env: envVars,
			CPURequest: es.Resources.CPURequest, CPULimit: es.Resources.CPULimit,
			MemoryRequest: es.Resources.MemoryRequest, MemoryLimit: es.Resources.MemoryLimit,
			VolumeSize: es.Resources.VolumeSize, RuntimeClass: es.RuntimeClass,
		},
	}, nil
}
