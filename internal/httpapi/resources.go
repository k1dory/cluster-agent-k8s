package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"agent-sandbox/internal/bindings"
	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/connections"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/resource"
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
}

// Compile-time checks: the services fit the shared route shape.
var (
	_ versioned = (*connections.Service)(nil)
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
