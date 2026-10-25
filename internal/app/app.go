// Package app assembles the platform's configuration services the one way sandboxd runs them,
// so integration tests exercise the real wiring rather than a copy of it: the ownership guard
// (policy repository + bindings), quotas (tenant settings + per-slug binding limits), the
// connections the gateway consults, and the catalogue that validates against all of them.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"agent-sandbox/internal/apply"
	"agent-sandbox/internal/bindings"
	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/connections"
	"agent-sandbox/internal/gitrepo"
	"agent-sandbox/internal/gitsync"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/services"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/tenants"
)

// Deps is what the services are built from.
type Deps struct {
	Store    store.Store
	Policies *policy.Set
	Secrets  secrets.Provider
	Orch     *orchestrator.Orchestrator
	Log      *slog.Logger
	Replica  string // this replica's name (lease owner for applies)
	// Fetch reads registered Git repositories (nil: the git binary over HTTPS).
	Fetch gitsync.Fetcher
}

// Services is the assembled set. Guard is what every ownership decision goes through.
type Services struct {
	Guard       *bindings.Guard
	Bindings    *bindings.Service
	Tenants     *tenants.Service
	Connections *connections.Service
	Catalog     *catalog.Service
	Planner     plan.Deps         // validates bundles against the same store, policies, images and secrets
	Applier     *apply.Controller // applies planned bundles, one step per transaction, continued by key
	GitRepos    *gitrepo.Service  // registered repositories (kind GitRepository)
	GitSync     *gitsync.Service  // checks and syncs them through Applier
}

// Wire builds the services, loads their snapshots and installs the guard and the quotas on the
// orchestrator. Call Watch to keep the snapshots fresh.
func Wire(ctx context.Context, d Deps) (*Services, error) {
	defaults := func(t string) tenants.Quota {
		q := d.Orch.Cfg.QuotaFor(t)
		return tenants.Quota{MaxSandboxes: q.MaxSandboxes, MaxAwake: q.MaxAwake}
	}
	svc := services.Assemble(d.Store, services.Options{Policies: d.Policies, Images: d.Orch.Cfg, Secrets: d.Secrets, Defaults: defaults, Sandboxes: d.Store})
	bind, tset, conns, guard := svc.Bindings, svc.Tenants, svc.Connections, svc.Guard
	for name, r := range map[string]interface{ Refresh(context.Context) error }{"bindings": bind, "tenant settings": tset, "connections": conns} {
		if err := r.Refresh(ctx); err != nil {
			return nil, fmt.Errorf("load %s: %w", name, err)
		}
	}
	d.Orch.Policies = guard
	d.Orch.Quotas = limits{tenants: tset, bindings: bind}
	planner := plan.Deps{Store: d.Store, Policies: d.Policies, Images: d.Orch.Cfg, Secrets: d.Secrets, Defaults: defaults}
	replica := d.Replica
	if replica == "" {
		replica = fmt.Sprintf("replica-%d", time.Now().UnixNano())
	}
	applier := &apply.Controller{Store: d.Store, Planner: planner, Replica: replica, Log: d.Log,
		Refresh: []func(context.Context) error{bind.Refresh, tset.Refresh, conns.Refresh}}
	fetch := d.Fetch
	if fetch == nil {
		fetch = gitsync.CLI{}
	}
	return &Services{
		Guard: guard, Bindings: bind, Tenants: tset, Connections: conns,
		Catalog:  svc.Catalog,
		Planner:  planner,
		Applier:  applier,
		GitRepos: svc.GitRepos,
		GitSync: &gitsync.Service{Store: d.Store, Jobs: d.Store, Lock: d.Store.WithTenantLock, Repos: svc.GitRepos, Secrets: d.Secrets, Fetch: fetch, Applier: applier,
			Reporter: gitsync.RESTReporter{}, Emit: emitter(d), Replica: replica, Log: d.Log},
	}, nil
}

// Watch runs the snapshot refresh loops and the webhook job worker until ctx ends.
func (s *Services) Watch(ctx context.Context, log *slog.Logger) {
	go s.Bindings.Watch(ctx, log)
	go s.Tenants.Watch(ctx, log)
	go s.Connections.Watch(ctx, log)
	go s.GitSync.Run(ctx)
}

// API is what the services are installed on (httpapi.Platform).
type API interface {
	SetServices(cat *catalog.Service, conns *connections.Service, bind *bindings.Service, tset *tenants.Service, planner *plan.Deps, applier *apply.Controller)
	SetGit(repos *gitrepo.Service, sync *gitsync.Service)
}

// Install mounts the services on the API.
func (s *Services) Install(p API) {
	planner := s.Planner
	p.SetServices(s.Catalog, s.Connections, s.Bindings, s.Tenants, &planner, s.Applier)
	p.SetGit(s.GitRepos, s.GitSync)
}

// limits composes the orchestrator's quotas from tenant settings and policy bindings.
type limits struct {
	tenants  *tenants.Service
	bindings *bindings.Service
}

func (l limits) QuotaFor(tenant string) orchestrator.Quota {
	q := l.tenants.QuotaFor(tenant)
	return orchestrator.Quota{MaxSandboxes: q.MaxSandboxes, MaxAwake: q.MaxAwake}
}

func (l limits) SlugQuota(slug, tenant string) orchestrator.Quota {
	if b, ok := l.bindings.Active(slug, tenant); ok {
		return orchestrator.Quota{MaxSandboxes: b.MaxSandboxes, MaxAwake: b.MaxAwake}
	}
	return orchestrator.Quota{}
}

// emitter records an event in the store and publishes it on the hub, the way the orchestrator
// does for sandbox events (the hub is fed by the store's listener instead when one runs).
func emitter(d Deps) func(context.Context, model.Event) {
	return func(ctx context.Context, e model.Event) {
		if err := d.Store.AppendEvent(ctx, &e); err != nil {
			if d.Log != nil {
				d.Log.Error("append event", "type", e.Type, "err", err)
			}
			return
		}
		if d.Orch != nil && d.Orch.Hub != nil && !d.Orch.ListenerPublishes {
			d.Orch.Hub.Publish(e)
		}
	}
}
