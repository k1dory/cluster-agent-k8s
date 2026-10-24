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
package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/resource"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Errors the API maps to status codes.
var (
	ErrInvalid   = errors.New("invalid")   // 400 / 422
	ErrForbidden = errors.New("forbidden") // 403: a reference the caller may not use
	ErrConflict  = store.ErrConflict       // 409
	ErrNotFound  = store.ErrNotFound       // 404
)

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// HarnessSpec is how the agent process is started inside the pod.
type HarnessSpec struct {
	Command       string `yaml:"command,omitempty" json:"command,omitempty"`
	ResumeCommand string `yaml:"resume_command,omitempty" json:"resume_command,omitempty"`
	ResumePrompt  string `yaml:"resume_prompt,omitempty" json:"resume_prompt,omitempty"`
}

// ModelSpec names the model and its client settings.
type ModelSpec struct {
	Name string            `yaml:"name,omitempty" json:"name,omitempty"` // exported as SANDBOX_MODEL / ANTHROPIC_MODEL
	Env  map[string]string `yaml:"env,omitempty" json:"env,omitempty"`   // e.g. ANTHROPIC_BASE_URL
}

// ResourcesSpec sizes the pod and its workspace.
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
	Env          map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
}

// AgentSpec is an AgentDefinition: which policy, which environment, what the agent is told.
type AgentSpec struct {
	Policy       string   `yaml:"policy" json:"policy"`           // policy slug (ownership is checked)
	Environment  string   `yaml:"environment" json:"environment"` // "name" (latest at creation) or "name@N"
	Repo         string   `yaml:"repo,omitempty" json:"repo,omitempty"`
	Instructions string   `yaml:"instructions,omitempty" json:"instructions,omitempty"`
	Connections  []string `yaml:"connections,omitempty" json:"connections,omitempty"` // reserved: connection names (step 4)
}

// Document is the wire and file form of an item.
type Document struct {
	Kind             string          `yaml:"kind,omitempty" json:"kind,omitempty"`
	Tenant           *string         `yaml:"tenant,omitempty" json:"tenant,omitempty"` // admin only; "" = shared
	Name             string          `yaml:"name" json:"name"`
	Description      string          `yaml:"description,omitempty" json:"description,omitempty"`
	Spec             json.RawMessage `yaml:"spec" json:"spec"`
	ExpectedRevision *int            `yaml:"expected_revision,omitempty" json:"expected_revision,omitempty"`
}

// ParseYAML reads a declarative file (strict: unknown fields are errors).
func ParseYAML(raw []byte) (*Document, error) {
	var generic map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// Round-trip through JSON so the spec is validated by the same strict decoder as the API.
	b, err := json.Marshal(generic)
	if err != nil {
		return nil, err
	}
	return ParseJSON(b)
}

// ParseJSON reads an API body (strict).
func ParseJSON(raw []byte) (*Document, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return &d, nil
}

func decodeStrict(raw json.RawMessage, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%w: spec: %v", ErrInvalid, err)
	}
	return nil
}

// Images resolves what an environment names as image (orchestrator.Config.ResolveVersion).
type Images interface {
	ResolveVersion(v string, admin bool) (string, error)
}

// Policies answers whether a policy slug exists and who may use it (the policy set).
type Policies interface {
	AllowedFor(slug, tenant string) bool
	Slugs() []string
}

// Service validates, stores and resolves catalogue items.
type Service struct {
	Store    store.Catalog
	Images   Images
	Policies Policies // optional
}

// Put validates a document and appends it as a new revision. who is recorded as the author.
// tenant is the scope the caller works in ("" = shared, admin only); admin relaxes what an
// image may name and lets the policy be one the tenant does not own.
func (s *Service) Put(ctx context.Context, kind, tenant string, d *Document, admin bool, who string) (*model.CatalogItem, error) {
	if d.Kind != "" && d.Kind != kind {
		return nil, fmt.Errorf("%w: kind %q does not match %s", ErrInvalid, d.Kind, kind)
	}
	if !nameRe.MatchString(d.Name) {
		return nil, fmt.Errorf("%w: name must match %s", ErrInvalid, nameRe)
	}
	if len(bytes.TrimSpace(d.Spec)) == 0 {
		return nil, fmt.Errorf("%w: spec is required", ErrInvalid)
	}
	spec, err := s.validate(ctx, kind, tenant, d.Spec, admin)
	if err != nil {
		return nil, err
	}
	it := &model.CatalogItem{Kind: kind, Tenant: tenant, Name: d.Name, Description: d.Description, Spec: spec, CreatedBy: who}
	expected := -1
	if d.ExpectedRevision != nil {
		expected = *d.ExpectedRevision
	}
	if err := s.Store.PutItem(ctx, it, expected); err != nil {
		return nil, err
	}
	return it, nil
}

// validate decodes the spec strictly, checks it and returns it re-encoded in canonical form.
func (s *Service) validate(ctx context.Context, kind, tenant string, raw json.RawMessage, admin bool) (json.RawMessage, error) {
	switch kind {
	case model.KindEnvironment:
		var e EnvironmentSpec
		if err := decodeStrict(raw, &e); err != nil {
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
		for name, q := range map[string]string{"cpu_request": e.Resources.CPURequest, "cpu_limit": e.Resources.CPULimit,
			"memory_request": e.Resources.MemoryRequest, "memory_limit": e.Resources.MemoryLimit, "volume_size": e.Resources.VolumeSize} {
			if q == "" {
				continue
			}
			if _, err := resource.ParseQuantity(q); err != nil {
				return nil, fmt.Errorf("%w: spec.resources.%s %q: %v", ErrInvalid, name, q, err)
			}
		}
		if e.Lifecycle.IdleTimeout != nil && *e.Lifecycle.IdleTimeout < 0 || e.Lifecycle.TTL != nil && *e.Lifecycle.TTL < 0 {
			return nil, fmt.Errorf("%w: spec.lifecycle values must be >= 0", ErrInvalid)
		}
		for k := range e.Env {
			if k == "" || strings.ContainsAny(k, "= \t\n") {
				return nil, fmt.Errorf("%w: spec.env: %q is not a variable name", ErrInvalid, k)
			}
		}
		return json.Marshal(e)
	case model.KindAgent:
		var a AgentSpec
		if err := decodeStrict(raw, &a); err != nil {
			return nil, err
		}
		if !nameRe.MatchString(a.Policy) {
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
		name, rev, err := parseRef(a.Environment)
		if err != nil {
			return nil, fmt.Errorf("%w: spec.environment: %v", ErrInvalid, err)
		}
		if _, err := s.lookup(ctx, model.KindEnvironment, tenant, name, rev); err != nil {
			return nil, fmt.Errorf("%w: spec.environment %q: %v", ErrInvalid, a.Environment, err)
		}
		for _, c := range a.Connections {
			if !nameRe.MatchString(c) {
				return nil, fmt.Errorf("%w: spec.connections: %q is not a connection name", ErrInvalid, c)
			}
		}
		return json.Marshal(a)
	}
	return nil, fmt.Errorf("%w: unknown kind %q", ErrInvalid, kind)
}

// parseRef splits "name" or "name@N".
func parseRef(ref string) (string, int, error) {
	name, revStr, pinned := strings.Cut(ref, "@")
	if !nameRe.MatchString(name) {
		return "", 0, fmt.Errorf("%q is not a name or name@revision", ref)
	}
	if !pinned {
		return name, 0, nil
	}
	n, err := strconv.Atoi(revStr)
	if err != nil || n <= 0 {
		return "", 0, fmt.Errorf("%q: revision must be a positive integer", ref)
	}
	return name, n, nil
}

// lookup finds an item in the tenant's scope, then among the shared ones. Another tenant's
// items are invisible: they are simply not found.
func (s *Service) lookup(ctx context.Context, kind, tenant, name string, revision int) (*model.CatalogItem, error) {
	it, err := s.Store.GetItem(ctx, kind, tenant, name, revision)
	if errors.Is(err, store.ErrNotFound) && tenant != "" {
		it, err = s.Store.GetItem(ctx, kind, "", name, revision)
	}
	return it, err
}

// Get returns one item visible from tenant (own, else shared); revision 0 = latest.
func (s *Service) Get(ctx context.Context, kind, tenant, name string, revision int) (*model.CatalogItem, error) {
	return s.lookup(ctx, kind, tenant, name, revision)
}

// List returns the latest revisions visible from tenant: its own items and the shared ones
// it does not shadow.
func (s *Service) List(ctx context.Context, kind, tenant string) ([]*model.CatalogItem, error) {
	own, err := s.Store.ListItems(ctx, kind, tenant)
	if err != nil {
		return nil, err
	}
	if tenant == "" {
		return own, nil
	}
	shared, err := s.Store.ListItems(ctx, kind, "")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, it := range own {
		seen[it.Name] = true
	}
	for _, it := range shared {
		if !seen[it.Name] {
			own = append(own, it)
		}
	}
	return own, nil
}

// Revisions lists an item's history (own scope only: history of shared items is read as "").
func (s *Service) Revisions(ctx context.Context, kind, tenant, name string) ([]*model.CatalogItem, error) {
	revs, err := s.Store.ListRevisions(ctx, kind, tenant, name)
	if errors.Is(err, store.ErrNotFound) && tenant != "" {
		revs, err = s.Store.ListRevisions(ctx, kind, "", name)
	}
	return revs, err
}

// Delete removes an item from the given scope (a tenant cannot delete shared items).
func (s *Service) Delete(ctx context.Context, kind, tenant, name string) error {
	return s.Store.DeleteItem(ctx, kind, tenant, name)
}

// Resolved is what an agent reference turns into for a sandbox creation.
type Resolved struct {
	Agent       *model.CatalogItem
	Environment *model.CatalogItem
	AgentSpec   AgentSpec
	EnvSpec     EnvironmentSpec
	Launch      model.Launch
	Image       string // resolved image reference
}

// Resolve turns "agent" or "agent@N" into the agent revision, the environment revision it
// names (pinned, or the latest at this moment) and the Launch rendered from them.
func (s *Service) Resolve(ctx context.Context, tenant, ref string, admin bool) (*Resolved, error) {
	name, rev, err := parseRef(ref)
	if err != nil {
		return nil, fmt.Errorf("%w: agent_ref: %v", ErrInvalid, err)
	}
	agent, err := s.lookup(ctx, model.KindAgent, tenant, name, rev)
	if err != nil {
		return nil, fmt.Errorf("agent %s: %w", ref, err)
	}
	var as AgentSpec
	if err := json.Unmarshal(agent.Spec, &as); err != nil {
		return nil, err
	}
	envName, envRev, err := parseRef(as.Environment)
	if err != nil {
		return nil, fmt.Errorf("%w: agent %s environment: %v", ErrInvalid, ref, err)
	}
	// The environment is looked up in the agent's own scope: a shared agent may only use shared
	// environments, a tenant's agent its own or shared ones. Never another tenant's.
	env, err := s.lookup(ctx, model.KindEnvironment, agent.Tenant, envName, envRev)
	if err != nil {
		return nil, fmt.Errorf("agent %s environment %s: %w", ref, as.Environment, err)
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
	envVars := map[string]string{}
	for k, v := range es.Model.Env {
		envVars[k] = v
	}
	for k, v := range es.Env {
		envVars[k] = v
	}
	if es.Model.Name != "" {
		envVars["SANDBOX_MODEL"] = es.Model.Name
		envVars["ANTHROPIC_MODEL"] = es.Model.Name
	}
	if as.Instructions != "" {
		envVars["SANDBOX_INSTRUCTIONS"] = as.Instructions
	}
	if len(envVars) == 0 {
		envVars = nil
	}
	return &Resolved{
		Agent: agent, Environment: env, AgentSpec: as, EnvSpec: es, Image: image,
		Launch: model.Launch{
			Image: image, HarnessCommand: es.Harness.Command, HarnessResumeCommand: es.Harness.ResumeCommand,
			ResumePrompt: es.Harness.ResumePrompt, Model: es.Model.Name, Instructions: as.Instructions, Env: envVars,
			CPURequest: es.Resources.CPURequest, CPULimit: es.Resources.CPULimit,
			MemoryRequest: es.Resources.MemoryRequest, MemoryLimit: es.Resources.MemoryLimit,
			VolumeSize: es.Resources.VolumeSize, RuntimeClass: es.RuntimeClass,
		},
	}, nil
}
