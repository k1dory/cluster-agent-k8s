// Package app assembles the platform's configuration services the one way sandboxd runs them,
// so integration tests exercise the real wiring rather than a copy of it: the ownership guard
// (policy repository + bindings), quotas (tenant settings + per-slug binding limits), the
// connections the gateway consults, and the catalogue that validates against all of them.
package app

import (
	"context"
	"fmt"
	"log/slog"

	"agent-sandbox/internal/bindings"
	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/connections"
	"agent-sandbox/internal/orchestrator"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
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
}

// Services is the assembled set. Guard is what every ownership decision goes through.
type Services struct {
	Guard       *bindings.Guard
	Bindings    *bindings.Service
	Tenants     *tenants.Service
	Connections *connections.Service
	Catalog     *catalog.Service
	Planner     plan.Deps // validates bundles against the same store, policies, images and secrets
}

// Wire builds the services, loads their snapshots and installs the guard and the quotas on the
// orchestrator. Call Watch to keep the snapshots fresh.
func Wire(ctx context.Context, d Deps) (*Services, error) {
	defaults := func(t string) tenants.Quota {
		q := d.Orch.Cfg.QuotaFor(t)
		return tenants.Quota{MaxSandboxes: q.MaxSandboxes, MaxAwake: q.MaxAwake}
	}
	bind := bindings.New(d.Store, d.Policies)
	tset := tenants.New(d.Store, defaults)
	conns := connections.New(d.Store, d.Secrets, d.Store)
	for name, r := range map[string]interface{ Refresh(context.Context) error }{"bindings": bind, "tenant settings": tset, "connections": conns} {
		if err := r.Refresh(ctx); err != nil {
			return nil, fmt.Errorf("load %s: %w", name, err)
		}
	}
	guard := &bindings.Guard{Set: d.Policies, Bindings: bind, Headers: conns}
	d.Orch.Policies = guard
	d.Orch.Quotas = limits{tenants: tset, bindings: bind}
	return &Services{
		Guard: guard, Bindings: bind, Tenants: tset, Connections: conns,
		Catalog: &catalog.Service{Store: d.Store, Images: d.Orch.Cfg, Policies: guard, Connections: conns, Tenants: tset},
		Planner: plan.Deps{Store: d.Store, Policies: d.Policies, Images: d.Orch.Cfg, Secrets: d.Secrets, Defaults: defaults},
	}, nil
}

// Watch runs the snapshot refresh loops until ctx ends.
func (s *Services) Watch(ctx context.Context, log *slog.Logger) {
	go s.Bindings.Watch(ctx, log)
	go s.Tenants.Watch(ctx, log)
	go s.Connections.Watch(ctx, log)
}

// API is what the services are installed on (httpapi.Platform).
type API interface {
	SetServices(cat *catalog.Service, conns *connections.Service, bind *bindings.Service, tset *tenants.Service, planner *plan.Deps)
}

// Install mounts the services on the API.
func (s *Services) Install(p API) {
	planner := s.Planner
	p.SetServices(s.Catalog, s.Connections, s.Bindings, s.Tenants, &planner)
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
