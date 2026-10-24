package httpapi

import (
	"errors"
	"fmt"
	"net/http"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/orchestrator"
)

// The catalogue routes (/v1/agents, /v1/environments) are mounted by configRoutes with the
// shape every versioned resource shares (resources.go). What is specific to the catalogue is
// here: the scope rule and how an agent reference becomes a creation request.

// catalogScope is the tenant the request works in. Tenants are confined to their own; the
// admin picks one with ?tenant= and defaults to the shared scope.
func (p *Platform) catalogScope(w http.ResponseWriter, r *http.Request) (string, bool) {
	pr := principalOf(r)
	if pr.admin() {
		return r.URL.Query().Get("tenant"), true
	}
	if t := r.URL.Query().Get("tenant"); t != "" && t != pr.Tenant {
		writeErr(w, http.StatusForbidden, errors.New("token is scoped to tenant "+pr.Tenant))
		return "", false
	}
	return pr.Tenant, true
}

// writeCatalogErr maps catalogue errors to status codes (same mapping as every resource).
func writeCatalogErr(w http.ResponseWriter, err error) { writeResourceErr(w, err) }

// resolveAgentRef fills a creation request from the catalogue. Explicit request fields win
// over the agent's defaults; slug must be absent or equal to the agent's policy.
func (p *Platform) resolveAgentRef(r *http.Request, req *orchestrator.CreateRequest) error {
	if p.Catalog == nil {
		return fmt.Errorf("%w: catalogue disabled", catalog.ErrInvalid)
	}
	pr := principalOf(r)
	scope := pr.Tenant
	if pr.admin() {
		scope = req.Tenant
		if scope == "" {
			scope = req.Owner
		}
	}
	res, err := p.Catalog.Resolve(r.Context(), scope, req.AgentRef, pr.admin())
	if err != nil {
		return err
	}
	if req.Slug != "" && req.Slug != res.AgentSpec.Policy {
		return fmt.Errorf("%w: slug %q conflicts with the agent's policy %q", catalog.ErrInvalid, req.Slug, res.AgentSpec.Policy)
	}
	req.Slug = res.AgentSpec.Policy
	if req.Repo == "" {
		req.Repo = res.AgentSpec.Repo
	}
	if req.IdleTimeout == nil {
		req.IdleTimeout = res.EnvSpec.Lifecycle.IdleTimeout
	}
	if req.TTL == nil {
		req.TTL = res.EnvSpec.Lifecycle.TTL
	}
	if req.WakeOnPreview == nil {
		req.WakeOnPreview = res.EnvSpec.Lifecycle.WakeOnPreview
	}
	// The image was resolved under the environment author's rights; the orchestrator takes it
	// as is when a launch is attached (policy ownership is still checked there for the caller).
	req.AgentVersion = res.Image
	req.AgentRef = res.AgentRef // "name" or "shared/name": the scope is part of the record
	req.AgentRevision = res.Agent.Revision
	req.EnvironmentRef = res.EnvironmentRef
	req.EnvironmentRevision = res.Environment.Revision
	launch := res.Launch
	req.Launch = &launch
	req.Connections = res.Connections
	return nil
}
