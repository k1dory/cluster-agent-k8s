package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"agent-sandbox/internal/apply"
	"agent-sandbox/internal/bindings"
	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/connections"
	"agent-sandbox/internal/drift"
	"agent-sandbox/internal/gitrepo"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/tenants"
)

// versioned is what every tenant-scoped, revisioned resource offers the API. Each kind is its
// own service (catalogue, connections, bindings); the routes below are the one HTTP shape they
// share: GET list, GET/PUT/DELETE {name}, GET {name}/revisions.
type versioned interface {
	Put(ctx context.Context, tenant string, d *resource.Document, admin bool, who string) (*model.CatalogItem, error)
	Get(ctx context.Context, tenant, name string, revision int) (*model.CatalogItem, error)
	List(ctx context.Context, tenant string) ([]*model.CatalogItem, error)
	Revisions(ctx context.Context, tenant, name string) ([]*model.CatalogItem, error)
	Delete(ctx context.Context, tenant, name string) error
}

// kindService narrows the catalogue service to one kind.
type kindService struct {
	svc  *catalog.Service
	kind string
}

func (k kindService) Put(ctx context.Context, tenant string, d *resource.Document, admin bool, who string) (*model.CatalogItem, error) {
	return k.svc.Put(ctx, k.kind, tenant, d, admin, who)
}
func (k kindService) Get(ctx context.Context, tenant, name string, revision int) (*model.CatalogItem, error) {
	return k.svc.Get(ctx, k.kind, tenant, name, revision)
}
func (k kindService) List(ctx context.Context, tenant string) ([]*model.CatalogItem, error) {
	return k.svc.List(ctx, k.kind, tenant)
}
func (k kindService) Revisions(ctx context.Context, tenant, name string) ([]*model.CatalogItem, error) {
	return k.svc.Revisions(ctx, k.kind, tenant, name)
}
func (k kindService) Delete(ctx context.Context, tenant, name string) error {
	return k.svc.Delete(ctx, k.kind, tenant, name)
}

// resourceRoutes mounts one versioned resource under /v1/<path>. With adminWrites, only the
// admin may PUT or DELETE (tenants still read their own scope). get is evaluated per request:
// a platform without that service answers 503.
func (p *Platform) resourceRoutes(mux *http.ServeMux, path string, get func() versioned, adminWrites bool) {
	scope := func(w http.ResponseWriter, r *http.Request) (versioned, string, bool) {
		svc := get()
		if svc == nil {
			writeErr(w, http.StatusServiceUnavailable, errors.New(path+" disabled"))
			return nil, "", false
		}
		tenant, ok := p.catalogScope(w, r)
		return svc, tenant, ok
	}
	mux.HandleFunc("GET /v1/"+path, p.auth(func(w http.ResponseWriter, r *http.Request) {
		svc, tenant, ok := scope(w, r)
		if !ok {
			return
		}
		items, err := svc.List(r.Context(), tenant)
		if err != nil {
			writeResourceErr(w, err)
			return
		}
		if items == nil {
			items = []*model.CatalogItem{}
		}
		writeJSON(w, http.StatusOK, items)
	}))
	mux.HandleFunc("GET /v1/"+path+"/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) {
		svc, tenant, ok := scope(w, r)
		if !ok {
			return
		}
		rev, ok := revisionParam(w, r)
		if !ok {
			return
		}
		it, err := svc.Get(r.Context(), tenant, r.PathValue("name"), rev)
		if err != nil {
			writeResourceErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, it)
	}))
	mux.HandleFunc("GET /v1/"+path+"/{name}/revisions", p.auth(func(w http.ResponseWriter, r *http.Request) {
		svc, tenant, ok := scope(w, r)
		if !ok {
			return
		}
		revs, err := svc.Revisions(r.Context(), tenant, r.PathValue("name"))
		if err != nil {
			writeResourceErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, revs)
	}))
	mux.HandleFunc("PUT /v1/"+path+"/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) {
		pr := principalOf(r)
		if adminWrites && !pr.admin() {
			writeErr(w, http.StatusForbidden, errors.New("admin only"))
			return
		}
		svc, tenant, ok := scope(w, r)
		if !ok {
			return
		}
		d, ok := readDocument(w, r, &tenant)
		if !ok {
			return
		}
		it, err := svc.Put(r.Context(), tenant, d, pr.admin(), pr.Subject)
		if err != nil {
			writeResourceErr(w, err)
			return
		}
		code := http.StatusOK
		if it.Revision == 1 {
			code = http.StatusCreated
		}
		writeJSON(w, code, it)
	}))
	mux.HandleFunc("DELETE /v1/"+path+"/{name}", p.auth(func(w http.ResponseWriter, r *http.Request) {
		if adminWrites && !principalOf(r).admin() {
			writeErr(w, http.StatusForbidden, errors.New("admin only"))
			return
		}
		svc, tenant, ok := scope(w, r)
		if !ok {
			return
		}
		if err := svc.Delete(r.Context(), tenant, r.PathValue("name")); err != nil {
			writeResourceErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

// readDocument parses a strict document body; a tenant in the body must agree with the
// caller's rights (the admin may write into any scope, a tenant only into its own) and
// becomes the scope; a name in the body must agree with the path.
func readDocument(w http.ResponseWriter, r *http.Request, tenant *string) (*resource.Document, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return nil, false
	}
	d, err := resource.ParseJSON(body)
	if err != nil {
		writeResourceErr(w, err)
		return nil, false
	}
	pr := principalOf(r)
	if d.Tenant != nil {
		if !pr.admin() && *d.Tenant != pr.Tenant {
			writeErr(w, http.StatusForbidden, errors.New("token is scoped to tenant "+pr.Tenant))
			return nil, false
		}
		*tenant = *d.Tenant
	}
	if name := r.PathValue("name"); name != "" {
		if d.Name == "" {
			d.Name = name
		} else if d.Name != name {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("name %q in the body does not match the path", d.Name))
			return nil, false
		}
	}
	return d, true
}

func revisionParam(w http.ResponseWriter, r *http.Request) (int, bool) {
	v := r.URL.Query().Get("revision")
	if v == "" {
		return 0, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusBadRequest, errors.New("revision must be a positive integer"))
		return 0, false
	}
	return n, true
}

// tenantSettingsRoutes mounts /v1/tenants/{tenant}/settings: the admin writes, a tenant reads
// its own. DELETE returns the tenant to the server defaults.
func (p *Platform) tenantSettingsRoutes(mux *http.ServeMux) {
	svc := func() *tenants.Service { return p.TenantSettings }
	own := func(w http.ResponseWriter, r *http.Request, write bool) (string, bool) {
		if svc() == nil {
			writeErr(w, http.StatusServiceUnavailable, errors.New("tenant settings disabled"))
			return "", false
		}
		pr := principalOf(r)
		tenant := r.PathValue("tenant")
		if write && !pr.admin() {
			writeErr(w, http.StatusForbidden, errors.New("admin only"))
			return "", false
		}
		if !pr.admin() && tenant != pr.Tenant {
			writeErr(w, http.StatusForbidden, errors.New("token is scoped to tenant "+pr.Tenant))
			return "", false
		}
		return tenant, true
	}
	mux.HandleFunc("GET /v1/tenants/{tenant}/settings", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := own(w, r, false)
		if !ok {
			return
		}
		rev, ok := revisionParam(w, r)
		if !ok {
			return
		}
		it, err := svc().Get(r.Context(), tenant, rev)
		if err != nil {
			writeResourceErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, it)
	}))
	mux.HandleFunc("GET /v1/tenants/{tenant}/settings/revisions", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := own(w, r, false)
		if !ok {
			return
		}
		revs, err := svc().Revisions(r.Context(), tenant)
		if err != nil {
			writeResourceErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, revs)
	}))
	mux.HandleFunc("PUT /v1/tenants/{tenant}/settings", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := own(w, r, true)
		if !ok {
			return
		}
		scope := tenant
		d, ok := readDocument(w, r, &scope)
		if !ok {
			return
		}
		if scope != tenant {
			writeErr(w, http.StatusBadRequest, fmt.Errorf("tenant %q in the body does not match the path", scope))
			return
		}
		it, err := svc().Put(r.Context(), tenant, d, principalOf(r).Subject)
		if err != nil {
			writeResourceErr(w, err)
			return
		}
		code := http.StatusOK
		if it.Revision == 1 {
			code = http.StatusCreated
		}
		writeJSON(w, code, it)
	}))
	mux.HandleFunc("DELETE /v1/tenants/{tenant}/settings", p.auth(func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := own(w, r, true)
		if !ok {
			return
		}
		if err := svc().Delete(r.Context(), tenant); err != nil {
			writeResourceErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
}

// configRoutes mounts every versioned resource; services the platform is not wired with
// answer 503.
func (p *Platform) configRoutes(mux *http.ServeMux) {
	kind := func(k string) func() versioned {
		return func() versioned {
			if p.Catalog == nil {
				return nil
			}
			return kindService{p.Catalog, k}
		}
	}
	p.resourceRoutes(mux, "agents", kind(model.KindAgent), false)
	p.resourceRoutes(mux, "environments", kind(model.KindEnvironment), false)
	p.resourceRoutes(mux, "connections", func() versioned {
		if p.Connections == nil {
			return nil
		}
		return p.Connections
	}, false)
	p.resourceRoutes(mux, "bindings", func() versioned {
		if p.Bindings == nil {
			return nil
		}
		return p.Bindings
	}, true)
	p.tenantSettingsRoutes(mux)
	mux.HandleFunc("POST /v1/plan", p.auth(p.planBundle))
	p.resourceRoutes(mux, "gitrepos", func() versioned {
		if p.GitRepos == nil {
			return nil
		}
		return p.GitRepos
	}, false)
	mux.HandleFunc("POST /v1/gitrepos/{name}/check", p.auth(p.gitCheck))
	mux.HandleFunc("POST /v1/gitrepos/{name}/sync", p.auth(p.gitSyncRepo))
	mux.HandleFunc("GET /v1/gitrepos/{name}/status", p.auth(p.gitStatus))
	mux.HandleFunc("POST /v1/apply", p.auth(p.applyBundle))
	mux.HandleFunc("GET /v1/applies", p.auth(p.listApplies))
	mux.HandleFunc("GET /v1/applies/{id}", p.auth(p.getApply))
	mux.HandleFunc("POST /v1/applies/{id}/resume", p.auth(p.resumeApply))
	mux.HandleFunc("GET /v1/drift", p.auth(p.driftReport))
	mux.HandleFunc("POST /v1/rollback", p.auth(p.rollback))
}

// driftReport lists the items of the scope that moved away from what an apply last wrote:
// changed through the resource API, or deleted. Computed from the store alone.
func (p *Platform) driftReport(w http.ResponseWriter, r *http.Request) {
	if p.Applier == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("apply disabled"))
		return
	}
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return
	}
	rep, err := drift.Detect(r.Context(), p.Applier.Store, tenant, time.Now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// rollback restores what an apply wrote (to the revisions it replaced) or one item to a
// revision, as a new plan and apply under the caller's current rights. Grants are never
// restored. `dry_run` plans without writing; an invalid plan is 422 with the plan.
func (p *Platform) rollback(w http.ResponseWriter, r *http.Request) {
	if p.Applier == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("apply disabled"))
		return
	}
	pr := principalOf(r)
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return
	}
	var body struct {
		Apply    string `json:"apply"`
		Kind     string `json:"kind"`
		Tenant   string `json:"tenant"`
		Name     string `json:"name"`
		Revision int    `json:"revision"`
		Key      string `json:"key"`
		DryRun   bool   `json:"dry_run"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("%w: %v", resource.ErrInvalid, err))
		return
	}
	if body.Key == "" {
		body.Key = r.Header.Get("Idempotency-Key")
	}
	rb, err := p.Applier.Rollback(r.Context(), apply.RollbackRequest{Apply: body.Apply, Kind: body.Kind, Tenant: body.Tenant, Name: body.Name,
		Revision: body.Revision, Key: body.Key, DryRun: body.DryRun, Scope: plan.Scope{Tenant: tenant, Admin: pr.admin(), Subject: pr.Subject}})
	var invalid *apply.InvalidPlan
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, rb)
	case errors.As(err, &invalid):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "code": "invalid_plan", "rollback": rb})
	case errors.Is(err, apply.ErrNothingToRollBack):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "code": "nothing_to_roll_back", "rollback": rb})
	case errors.Is(err, resource.ErrInvalid):
		writeErr(w, http.StatusBadRequest, err)
	default:
		writeApply(w, nil, err)
	}
}

// applyBundle applies a planned bundle. The body is as for /v1/plan plus the plan fingerprint
// (`plan` in the JSON wrapper, or ?plan= for YAML); the idempotency key is `key` in the
// wrapper, ?key=, the Idempotency-Key header, or the plan fingerprint. The same key with the
// same bundle returns (and finishes) the same apply; another bundle under it is 409.
func (p *Platform) applyBundle(w http.ResponseWriter, r *http.Request) {
	if p.Applier == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("apply disabled"))
		return
	}
	pr := principalOf(r)
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req, err := parseApplyBody(r, body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	req.Scope = plan.Scope{Tenant: tenant, Admin: pr.admin(), Subject: pr.Subject}
	a, err := p.Applier.Submit(r.Context(), req)
	writeApply(w, a, err)
}

// applySource is the Git provenance a client may attach to an apply: in the JSON wrapper as
// `source`, or as ?repo= ?ref= ?commit= ?path= for a YAML body.
type applySource struct {
	Repo   string `json:"repo,omitempty"`
	Ref    string `json:"ref,omitempty"`
	Commit string `json:"commit,omitempty"`
	Path   string `json:"path,omitempty"`
}

func (s applySource) model() *model.Source {
	if s == (applySource{}) {
		return nil
	}
	return &model.Source{Repo: s.Repo, Ref: s.Ref, Commit: s.Commit, Path: s.Path}
}

func parseApplyBody(r *http.Request, body []byte) (apply.Request, error) {
	q := r.URL.Query()
	req := apply.Request{Plan: q.Get("plan"), Key: q.Get("key")}
	src := applySource{Repo: q.Get("repo"), Ref: q.Get("ref"), Commit: q.Get("commit"), Path: q.Get("path")}
	if h := r.Header.Get("Idempotency-Key"); h != "" && req.Key == "" {
		req.Key = h
	}
	ct := r.Header.Get("Content-Type")
	trimmed := bytes.TrimSpace(body)
	if !strings.Contains(ct, "yaml") && len(trimmed) > 0 && trimmed[0] == '{' {
		var wrapper struct {
			Documents []json.RawMessage `json:"documents"`
			Plan      string            `json:"plan"`
			Key       string            `json:"key"`
			Source    *applySource      `json:"source"`
		}
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&wrapper); err != nil {
			return req, fmt.Errorf("%w: %v", resource.ErrInvalid, err)
		}
		if wrapper.Plan != "" {
			req.Plan = wrapper.Plan
		}
		if wrapper.Key != "" {
			req.Key = wrapper.Key
		}
		if wrapper.Source != nil {
			src = *wrapper.Source
		}
		req.Docs = make([]*resource.Document, 0, len(wrapper.Documents))
		for i, raw := range wrapper.Documents {
			d, err := resource.ParseJSON(raw)
			if err != nil {
				return req, fmt.Errorf("document %d: %w", i+1, err)
			}
			req.Docs = append(req.Docs, d)
		}
	} else {
		var err error
		if req.Docs, err = parseBundle(ct, body); err != nil {
			return req, err
		}
	}
	req.Source = src.model()
	return req, nil
}

func writeApply(w http.ResponseWriter, a *model.Apply, err error) {
	var invalid *apply.InvalidPlan
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, a)
	case errors.As(err, &invalid):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "code": "invalid_plan", "plan": invalid.Plan})
	case errors.Is(err, apply.ErrPlanMismatch), errors.Is(err, apply.ErrKeyReused), errors.Is(err, store.ErrConflict):
		if a != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error(), "code": "conflict", "apply": a})
			return
		}
		writeErr(w, http.StatusConflict, err)
	case errors.Is(err, apply.ErrForbidden):
		writeErr(w, http.StatusForbidden, err)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, resource.ErrInvalid):
		writeErr(w, http.StatusBadRequest, err)
	default:
		writeErr(w, http.StatusInternalServerError, err)
	}
}

func (p *Platform) applyScope(r *http.Request) plan.Scope {
	pr := principalOf(r)
	return plan.Scope{Tenant: pr.Tenant, Admin: pr.admin(), Subject: pr.Subject}
}

func (p *Platform) getApply(w http.ResponseWriter, r *http.Request) {
	if p.Applier == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("apply disabled"))
		return
	}
	a, err := p.Applier.Get(r.Context(), r.PathValue("id"), p.applyScope(r))
	writeApply(w, a, err)
}

func (p *Platform) resumeApply(w http.ResponseWriter, r *http.Request) {
	if p.Applier == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("apply disabled"))
		return
	}
	a, err := p.Applier.Resume(r.Context(), r.PathValue("id"), p.applyScope(r))
	writeApply(w, a, err)
}

func (p *Platform) listApplies(w http.ResponseWriter, r *http.Request) {
	if p.Applier == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("apply disabled"))
		return
	}
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return
	}
	list, err := p.Applier.List(r.Context(), tenant, 100)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if list == nil {
		list = []*model.Apply{}
	}
	writeJSON(w, http.StatusOK, list)
}

// planBundle validates a bundle of documents and reports what applying it would change. The
// body is a YAML stream (Content-Type application/yaml or text/yaml) or JSON: an array of
// documents or {"documents": [...]}. Nothing is written; an invalid bundle is still a 200 plan
// with valid=false and the problems per document.
func (p *Platform) planBundle(w http.ResponseWriter, r *http.Request) {
	if p.Planner == nil {
		writeErr(w, http.StatusServiceUnavailable, errors.New("plan disabled"))
		return
	}
	pr := principalOf(r)
	tenant, ok := p.catalogScope(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	docs, err := parseBundle(r.Header.Get("Content-Type"), body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	out, err := p.Planner.Plan(r.Context(), docs, plan.Scope{Tenant: tenant, Admin: pr.admin(), Subject: pr.Subject})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// parseBundle reads the documents of a plan or apply request.
func parseBundle(contentType string, body []byte) ([]*resource.Document, error) {
	if strings.Contains(contentType, "yaml") {
		return resource.ParseYAMLAll(body)
	}
	var raw []json.RawMessage
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &raw); err != nil {
			return nil, fmt.Errorf("%w: %v", resource.ErrInvalid, err)
		}
	} else {
		var wrapper struct {
			Documents []json.RawMessage `json:"documents"`
		}
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&wrapper); err != nil {
			return nil, fmt.Errorf("%w: %v", resource.ErrInvalid, err)
		}
		raw = wrapper.Documents
	}
	docs := make([]*resource.Document, 0, len(raw))
	for i, r := range raw {
		d, err := resource.ParseJSON(r)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		docs = append(docs, d)
	}
	return docs, nil
}

// Compile-time checks: the services fit the shared route shape.
var (
	_ versioned = (*connections.Service)(nil)
	_ versioned = (*gitrepo.Service)(nil)
	_ versioned = (*bindings.Service)(nil)
)

func writeResourceErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, resource.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, resource.ErrConflict):
		writeErr(w, http.StatusConflict, err)
	case errors.Is(err, resource.ErrForbidden):
		writeErr(w, http.StatusForbidden, err)
	case errors.Is(err, resource.ErrInvalid):
		writeErr(w, http.StatusUnprocessableEntity, err)
	default:
		writeErr(w, http.StatusInternalServerError, err)
	}
}
