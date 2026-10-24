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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// SharedPrefix marks a reference to a shared item: "shared/name".
const SharedPrefix = "shared/"

// HarnessSpec is how the agent process is started inside the pod.
type HarnessSpec struct {
	Command       string `yaml:"command,omitempty" json:"command,omitempty"`
	ResumeCommand string `yaml:"resume_command,omitempty" json:"resume_command,omitempty"`
	ResumePrompt  string `yaml:"resume_prompt,omitempty" json:"resume_prompt,omitempty"`
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

// ParseYAML reads one declarative document (strict: unknown fields are errors). A file with
// several documents is refused: nothing is applied silently; use ParseYAMLAll for a batch.
func ParseYAML(raw []byte) (*Document, error) {
	docs, err := ParseYAMLAll(raw)
	if err != nil {
		return nil, err
	}
	switch len(docs) {
	case 0:
		return nil, fmt.Errorf("%w: no document", ErrInvalid)
	case 1:
		return docs[0], nil
	}
	return nil, fmt.Errorf("%w: %d documents in one input; apply them as a batch", ErrInvalid, len(docs))
}

// ParseYAMLAll reads every document of a YAML stream (--- separated), in order, each strict.
// Empty documents are skipped.
func ParseYAMLAll(raw []byte) ([]*Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var docs []*Document
	for n := 1; ; n++ {
		var generic map[string]any
		err := dec.Decode(&generic)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: document %d: %v", ErrInvalid, n, err)
		}
		if len(generic) == 0 {
			continue
		}
		// Round-trip through JSON so the spec is validated by the same strict decoder as the API.
		b, err := json.Marshal(generic)
		if err != nil {
			return nil, err
		}
		d, err := ParseJSON(b)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", n, err)
		}
		docs = append(docs, d)
	}
}

// ParseJSON reads one API body (strict): unknown fields and anything after the object are errors.
func ParseJSON(raw []byte) (*Document, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: unexpected data after the document", ErrInvalid)
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
		if err := validateResources(e.Resources); err != nil {
			return nil, err
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
		ref, err := parseRef(a.Environment)
		if err != nil {
			return nil, fmt.Errorf("%w: spec.environment: %v", ErrInvalid, err)
		}
		env, err := s.lookup(ctx, model.KindEnvironment, tenant, ref)
		if err != nil {
			return nil, fmt.Errorf("%w: spec.environment %q: %v", ErrInvalid, a.Environment, err)
		}
		// Fix the scope the reference resolved to: a shared environment stays "shared/..." however
		// the tenant names its own items later.
		a.Environment = ref.inScope(env, tenant)
		for _, c := range a.Connections {
			if !nameRe.MatchString(c) {
				return nil, fmt.Errorf("%w: spec.connections: %q is not a connection name", ErrInvalid, c)
			}
		}
		return json.Marshal(a)
	}
	return nil, fmt.Errorf("%w: unknown kind %q", ErrInvalid, kind)
}

// ref is a parsed reference: name, optional pinned revision, optional explicit shared scope.
type ref struct {
	Name   string
	Rev    int  // 0 = latest
	Shared bool // "shared/name": only the shared scope is searched
}

// parseRef splits "name", "name@N" or "shared/name[@N]".
func parseRef(raw string) (ref, error) {
	var r ref
	rest := raw
	if strings.HasPrefix(rest, SharedPrefix) {
		r.Shared = true
		rest = strings.TrimPrefix(rest, SharedPrefix)
	}
	name, revStr, pinned := strings.Cut(rest, "@")
	if !nameRe.MatchString(name) {
		return r, fmt.Errorf("%q is not a name, name@revision or shared/name", raw)
	}
	r.Name = name
	if !pinned {
		return r, nil
	}
	n, err := strconv.Atoi(revStr)
	if err != nil || n <= 0 {
		return r, fmt.Errorf("%q: revision must be a positive integer", raw)
	}
	r.Rev = n
	return r, nil
}

// inScope renders the reference in the form that names it unambiguously from tenant: the
// shared prefix when it resolved to a shared item seen from a tenant, the pinned revision kept.
func (r ref) inScope(it *model.CatalogItem, tenant string) string {
	out := r.Name
	if it.Tenant == "" && tenant != "" {
		out = SharedPrefix + out
	}
	if r.Rev > 0 {
		out += "@" + strconv.Itoa(r.Rev)
	}
	return out
}

// RefOf is the reference string that names an item from tenant's point of view: "name" for
// the tenant's own items, "shared/name" for shared ones (revision not included).
func RefOf(it *model.CatalogItem, tenant string) string {
	return ref{Name: it.Name}.inScope(it, tenant)
}

// lookup finds a reference from tenant: an explicitly shared one only among the shared items;
// a bare one in the tenant's scope, then among the shared ones. Another tenant's items are
// invisible: they are simply not found.
func (s *Service) lookup(ctx context.Context, kind, tenant string, r ref) (*model.CatalogItem, error) {
	if r.Shared || tenant == "" {
		return s.Store.GetItem(ctx, kind, "", r.Name, r.Rev)
	}
	it, err := s.Store.GetItem(ctx, kind, tenant, r.Name, r.Rev)
	if errors.Is(err, store.ErrNotFound) {
		it, err = s.Store.GetItem(ctx, kind, "", r.Name, r.Rev)
	}
	return it, err
}

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
	return s.lookup(ctx, kind, tenant, ref{Name: name, Rev: revision})
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

// Revisions lists an item's whole history, deleted revisions included (own scope, else shared).
func (s *Service) Revisions(ctx context.Context, kind, tenant, name string) ([]*model.CatalogItem, error) {
	revs, err := s.Store.ListRevisions(ctx, kind, tenant, name)
	if errors.Is(err, store.ErrNotFound) && tenant != "" {
		revs, err = s.Store.ListRevisions(ctx, kind, "", name)
	}
	return revs, err
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
	AgentRef       string // the agent as named from the caller's scope: "name" or "shared/name"
	EnvironmentRef string // the environment as named from the agent's scope
	AgentSpec      AgentSpec
	EnvSpec        EnvironmentSpec
	Launch         model.Launch
	Image          string // resolved image reference
}

// Resolve turns "agent", "agent@N" or "shared/agent[@N]" into the agent revision, the
// environment revision it names (pinned, or the latest at this moment, in the scope the agent
// was written with) and the Launch rendered from them.
func (s *Service) Resolve(ctx context.Context, tenant, agentRef string, admin bool) (*Resolved, error) {
	ar, err := parseRef(agentRef)
	if err != nil {
		return nil, fmt.Errorf("%w: agent_ref: %v", ErrInvalid, err)
	}
	agent, err := s.lookup(ctx, model.KindAgent, tenant, ar)
	if err != nil {
		return nil, fmt.Errorf("agent %s: %w", agentRef, err)
	}
	var as AgentSpec
	if err := json.Unmarshal(agent.Spec, &as); err != nil {
		return nil, err
	}
	er, err := parseRef(as.Environment)
	if err != nil {
		return nil, fmt.Errorf("%w: agent %s environment: %v", ErrInvalid, agentRef, err)
	}
	// The environment is looked up in the agent's own scope, exactly as stored: "shared/..."
	// only among the shared items, a bare name only among the agent's tenant's (the scope was
	// fixed when the agent was written). Never another tenant's.
	env, err := s.Store.GetItem(ctx, model.KindEnvironment, envScope(agent.Tenant, er), er.Name, er.Rev)
	if err != nil {
		return nil, fmt.Errorf("agent %s environment %s: %w", agentRef, as.Environment, err)
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
	return &Resolved{
		Agent: agent, Environment: env, AgentRef: RefOf(agent, tenant), EnvironmentRef: RefOf(env, agent.Tenant),
		AgentSpec: as, EnvSpec: es, Image: image,
		Launch: model.Launch{
			Image: image, HarnessCommand: es.Harness.Command, HarnessResumeCommand: es.Harness.ResumeCommand,
			ResumePrompt: es.Harness.ResumePrompt, Model: es.Model.Name, Instructions: as.Instructions, Env: envVars,
			CPURequest: es.Resources.CPURequest, CPULimit: es.Resources.CPULimit,
			MemoryRequest: es.Resources.MemoryRequest, MemoryLimit: es.Resources.MemoryLimit,
			VolumeSize: es.Resources.VolumeSize, RuntimeClass: es.RuntimeClass,
		},
	}, nil
}

// envScope is the tenant an agent's stored environment reference lives in.
func envScope(agentTenant string, r ref) string {
	if r.Shared {
		return ""
	}
	return agentTenant
}
