// Package bindings is the admin's grant of a policy slug to a tenant: a PolicyBinding. The
// policy repository's `tenants:` list stays the declarative source of ownership; a binding
// adds (never removes) a tenant at runtime, with the admin's limits and an expiry. Removing or
// expiring a binding revokes the slug: new sandboxes are refused, the gateway denies running
// agents at their next request and the reconciler stops their pods.
//
// Decisions happen on every gateway request, so the live bindings are kept in an in-memory
// snapshot: refreshed at once by the replica that writes, within Every on the others.
package bindings

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// Spec is a PolicyBinding: the item's tenant is the grantee, its name the policy slug.
type Spec struct {
	ExpiresAt    *time.Time `yaml:"expires_at,omitempty" json:"expires_at,omitempty"`       // the grant ends here (absent = until deleted)
	MaxSandboxes int        `yaml:"max_sandboxes,omitempty" json:"max_sandboxes,omitempty"` // records under this slug; 0 = tenant quota only
	MaxAwake     int        `yaml:"max_awake,omitempty" json:"max_awake,omitempty"`         // pods at once under this slug
}

// Slugs is what the service needs from the policy set: which slugs exist.
type Slugs interface {
	Slugs() []string
}

// Service validates, stores and answers bindings.
type Service struct {
	Store    store.Catalog
	Policies Slugs // optional: when set, a binding must name an existing policy
	Now      func() time.Time
	snap     res.Snapshot
}

// New returns a service over st; call Refresh (and Watch) before serving decisions.
func New(st store.Catalog, pols Slugs) *Service {
	return &Service{Store: st, Policies: pols, Now: time.Now, snap: res.Snapshot{Store: st, Kind: model.KindBinding}}
}

// Put writes a binding for tenant (the document's name is the policy slug). Admin only; the
// API enforces that.
func (s *Service) Put(ctx context.Context, tenant string, d *res.Document, admin bool, who string) (*model.CatalogItem, error) {
	it, err := s.Validate(ctx, tenant, d, admin, who)
	if err != nil {
		return nil, err
	}
	if err := s.Store.PutItem(ctx, it, d.Expected()); err != nil {
		return nil, err
	}
	return it, s.Refresh(ctx)
}

// Validate checks a document and returns the item it would become, without writing.
func (s *Service) Validate(_ context.Context, tenant string, d *res.Document, _ bool, who string) (*model.CatalogItem, error) {
	if err := res.CheckDocument(d, model.KindBinding); err != nil {
		return nil, err
	}
	if tenant == "" {
		return nil, fmt.Errorf("%w: a binding needs a tenant (?tenant= or the document's tenant)", res.ErrInvalid)
	}
	var sp Spec
	if err := res.DecodeStrict(d.Spec, &sp); err != nil {
		return nil, err
	}
	if sp.MaxSandboxes < 0 || sp.MaxAwake < 0 {
		return nil, fmt.Errorf("%w: limits must be >= 0", res.ErrInvalid)
	}
	if sp.ExpiresAt != nil && !sp.ExpiresAt.After(s.Now()) {
		return nil, fmt.Errorf("%w: expires_at is in the past", res.ErrInvalid)
	}
	if s.Policies != nil {
		known := false
		for _, sl := range s.Policies.Slugs() {
			known = known || sl == d.Name
		}
		if !known {
			return nil, fmt.Errorf("%w: no policy %q", res.ErrInvalid, d.Name)
		}
	}
	spec, err := res.Marshal(sp)
	if err != nil {
		return nil, err
	}
	return &model.CatalogItem{Kind: model.KindBinding, Tenant: tenant, Name: d.Name, Description: d.Description, Spec: spec, CreatedBy: who}, nil
}

// Get returns tenant's binding for slug (revision 0 = latest).
func (s *Service) Get(ctx context.Context, tenant, slug string, revision int) (*model.CatalogItem, error) {
	return s.Store.GetItem(ctx, model.KindBinding, tenant, slug, revision)
}

// List returns tenant's live bindings.
func (s *Service) List(ctx context.Context, tenant string) ([]*model.CatalogItem, error) {
	return s.Store.ListItems(ctx, model.KindBinding, tenant)
}

// Revisions lists a binding's history.
func (s *Service) Revisions(ctx context.Context, tenant, slug string) ([]*model.CatalogItem, error) {
	return s.Store.ListRevisions(ctx, model.KindBinding, tenant, slug)
}

// Delete revokes the grant: the history stays, the tenant loses the slug now.
func (s *Service) Delete(ctx context.Context, tenant, slug string) error {
	if err := s.Store.DeleteItem(ctx, model.KindBinding, tenant, slug); err != nil {
		return err
	}
	return s.Refresh(ctx)
}

// Refresh reloads the live bindings from the store.
func (s *Service) Refresh(ctx context.Context) error { return s.snap.Refresh(ctx) }

// Watch keeps the snapshot fresh until ctx ends.
func (s *Service) Watch(ctx context.Context, log *slog.Logger) {
	s.snap.Watch(ctx, func(err error) {
		if log != nil {
			log.Error("bindings refresh failed, keeping the previous set", "err", err)
		}
	})
}

// Active returns the binding that currently grants slug to tenant, if any.
func (s *Service) Active(slug, tenant string) (*Spec, bool) {
	it := s.snap.Get(tenant, slug)
	if it == nil {
		return nil, false
	}
	var sp Spec
	if err := res.DecodeStrict(it.Spec, &sp); err != nil {
		return nil, false
	}
	if sp.ExpiresAt != nil && !sp.ExpiresAt.After(s.Now()) {
		return nil, false
	}
	return &sp, true
}

// HeaderSource supplies the headers a sandbox's connections add for a host (the connections
// service).
type HeaderSource interface {
	HeadersFor(ctx context.Context, sandboxID, tenant, host string) (map[string]string, error)
}

// HostSource is what connections add to the policy repository's hosts: the hosts live
// connections serve on their own (the connections service's OwnHosts) and the rule a sandbox's
// connection gives it for such a host (RuleFor).
type HostSource interface {
	OwnHosts() ([]policy.Host, string)
	RuleFor(ctx context.Context, sandboxID, tenant, host, method, reqPath string) (*policy.Rule, bool, error)
}

// Guard is the effective policy the orchestrator, the gateway and the catalogue decide with:
// the repository's rules and ownership lists, the live bindings, and the connections' headers
// and self-service hosts. Every other policy question is answered by the embedded set.
type Guard struct {
	*policy.Set
	Bindings *Service
	Headers  HeaderSource // optional
}

// HeadersFor forwards to the connections service when one is wired (see authz.Connections).
func (g *Guard) HeadersFor(ctx context.Context, sandboxID, tenant, host string) (map[string]string, error) {
	if g.Headers == nil {
		return nil, nil
	}
	return g.Headers.HeadersFor(ctx, sandboxID, tenant, host)
}

func (g *Guard) hostSource() HostSource {
	hs, ok := g.Headers.(HostSource)
	if !ok {
		return nil
	}
	return hs
}

// Hosts is the repository's host list plus the hosts live connections serve on their own: what
// the gateway renders sites for, the DNS answers and the MCP proxy accepts. A repository host
// stays the repository's whatever a connection says.
func (g *Guard) Hosts() []policy.Host {
	hs := g.Set.Hosts()
	src := g.hostSource()
	if src == nil {
		return hs
	}
	own, _ := src.OwnHosts()
	seen := map[string]bool{}
	for _, h := range hs {
		seen[h.Name] = true
	}
	for _, h := range own {
		if !seen[h.Name] {
			hs = append(hs, h)
		}
	}
	return hs
}

// HostInfo looks a host up in Hosts.
func (g *Guard) HostInfo(name string) (policy.Host, bool) {
	for _, h := range g.Hosts() {
		if h.Name == name {
			return h, true
		}
	}
	return policy.Host{}, false
}

// Fingerprint changes when the repository or the connections' hosts change: the gateway syncer
// re-renders on either.
func (g *Guard) Fingerprint() string {
	fp := g.Set.Fingerprint()
	if src := g.hostSource(); src != nil {
		_, own := src.OwnHosts()
		fp += "+" + own
	}
	return fp
}

// RuleFor forwards to the connections service (see authz.ConnectionRules).
func (g *Guard) RuleFor(ctx context.Context, sandboxID, tenant, host, method, reqPath string) (*policy.Rule, bool, error) {
	src := g.hostSource()
	if src == nil {
		return nil, false, nil
	}
	return src.RuleFor(ctx, sandboxID, tenant, host, method, reqPath)
}

// AllowedFor: the repository grants it, or a live binding does.
func (g *Guard) AllowedFor(slug, tenant string) bool {
	if g.Set.AllowedFor(slug, tenant) {
		return true
	}
	if g.Bindings == nil {
		return false
	}
	if _, ok := g.Set.Get(slug); !ok {
		return false // a binding cannot grant a slug that has no policy
	}
	_, ok := g.Bindings.Active(slug, tenant)
	return ok
}

// Revoked: a policy grant lasts while AllowedFor holds (repository or binding); an admin
// grant follows the repository's rule.
func (g *Guard) Revoked(slug, tenant string, adminGrant bool) bool {
	if adminGrant {
		return g.Set.Revoked(slug, tenant, true)
	}
	return !g.AllowedFor(slug, tenant)
}
