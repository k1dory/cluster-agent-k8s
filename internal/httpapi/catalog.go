package httpapi

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/store"
)

// catalogRoutes mounts /v1/agents and /v1/environments.
//
// Scope: a tenant token works in its own tenant and reads shared items; the admin works in
// the tenant named by ?tenant= (default: shared, tenant ""). Writes carry the document shape
// catalog.Document; reads return model.CatalogItem.
func (p *Platform) catalogRoutes(mux *http.ServeMux) {
	for path, kind := range map[string]string{"agents": model.KindAgent, "environments": model.KindEnvironment} {
		kind := kind
		mux.HandleFunc("GET /v1/"+path, p.auth(func(w http.ResponseWriter, r *http.Request) { p.catalogList(w, r, kind) }))
		mux.HandleFunc("GET /v1/"+path+"/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) { p.catalogGet(w, r, kind) }))
		mux.HandleFunc("GET /v1/"+path+"/{name}/revisions", p.auth(func(w http.ResponseWriter, r *http.Request) { p.catalogRevisions(w, r, kind) }))
		mux.HandleFunc("PUT /v1/"+path+"/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) { p.catalogPut(w, r, kind) }))
		mux.HandleFunc("DELETE /v1/"+path+"/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) { p.catalogDelete(w, r, kind) }))
	}
}

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

func (p *Platform) catalogList(w http.ResponseWriter, r *http.Request, kind string) {
	if p.Catalog == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("catalogue disabled"))
		return
	}
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return
	}
	items, err := p.Catalog.List(r.Context(), kind, tenant)
	if err != nil {
		writeCatalogErr(w, err)
		return
	}
	if items == nil {
		items = []*model.CatalogItem{}
	}
	writeJSON(w, http.StatusOK, items)
}

func (p *Platform) catalogGet(w http.ResponseWriter, r *http.Request, kind string) {
	if p.Catalog == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("catalogue disabled"))
		return
	}
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return
	}
	rev := 0
	if v := r.URL.Query().Get("revision"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, errors.New("revision must be a positive integer"))
			return
		}
		rev = n
	}
	it, err := p.Catalog.Get(r.Context(), kind, tenant, r.PathValue("name"), rev)
	if err != nil {
		writeCatalogErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, it)
}

func (p *Platform) catalogRevisions(w http.ResponseWriter, r *http.Request, kind string) {
	if p.Catalog == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("catalogue disabled"))
		return
	}
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return
	}
	revs, err := p.Catalog.Revisions(r.Context(), kind, tenant, r.PathValue("name"))
	if err != nil {
		writeCatalogErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, revs)
}

func (p *Platform) catalogPut(w http.ResponseWriter, r *http.Request, kind string) {
	if p.Catalog == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("catalogue disabled"))
		return
	}
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	d, err := catalog.ParseJSON(body)
	if err != nil {
		writeCatalogErr(w, err)
		return
	}
	pr := principalOf(r)
	if d.Tenant != nil {
		if !pr.admin() && *d.Tenant != pr.Tenant {
			writeErr(w, http.StatusForbidden, errors.New("token is scoped to tenant "+pr.Tenant))
			return
		}
		tenant = *d.Tenant
	}
	if d.Name == "" {
		d.Name = r.PathValue("name")
	} else if d.Name != r.PathValue("name") {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("name %q in the body does not match the path", d.Name))
		return
	}
	it, err := p.Catalog.Put(r.Context(), kind, tenant, d, pr.admin(), pr.Subject)
	if err != nil {
		writeCatalogErr(w, err)
		return
	}
	code := http.StatusOK
	if it.Revision == 1 {
		code = http.StatusCreated
	}
	writeJSON(w, code, it)
}

func (p *Platform) catalogDelete(w http.ResponseWriter, r *http.Request, kind string) {
	if p.Catalog == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("catalogue disabled"))
		return
	}
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return
	}
	if err := p.Catalog.Delete(r.Context(), kind, tenant, r.PathValue("name")); err != nil {
		writeCatalogErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeCatalogErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, catalog.ErrConflict):
		writeErr(w, http.StatusConflict, err)
	case errors.Is(err, catalog.ErrForbidden):
		writeErr(w, http.StatusForbidden, err)
	case errors.Is(err, catalog.ErrInvalid):
		writeErr(w, http.StatusUnprocessableEntity, err)
	default:
		writeErr(w, http.StatusInternalServerError, err)
	}
}

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
	req.AgentRef = res.Agent.Name
	req.AgentRevision = res.Agent.Revision
	req.EnvironmentRef = res.Environment.Name
	req.EnvironmentRevision = res.Environment.Revision
	launch := res.Launch
	req.Launch = &launch
	return nil
}
