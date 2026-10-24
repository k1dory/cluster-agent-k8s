// Package tenants holds TenantSettings: what the admin lets one tenant have. Quotas bound the
// tenant's sandboxes; Environments confines its agents to some environment profiles. Settings
// are one versioned item per tenant (name "settings"); a tenant reads its own, the admin
// writes. Decisions are served from an in-memory snapshot (see resource.Snapshot).
package tenants

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// Name is the fixed item name of a tenant's settings.
const Name = "settings"

// Quota bounds what one tenant may hold. Zero means unlimited.
type Quota struct {
	MaxSandboxes int `yaml:"max_sandboxes,omitempty" json:"max_sandboxes,omitempty"`
	MaxAwake     int `yaml:"max_awake,omitempty" json:"max_awake,omitempty"`
}

// Spec is a TenantSettings document.
type Spec struct {
	// Quota replaces the server's default quota for this tenant (0 = unlimited).
	Quota *Quota `yaml:"quota,omitempty" json:"quota,omitempty"`
	// Environments the tenant's agents may use: "name" (the tenant's own) or "shared/name".
	// Empty: every environment visible to the tenant.
	Environments []string `yaml:"environments,omitempty" json:"environments,omitempty"`
	// Hosts the tenant may reach through its own connections beyond what the policy repository
	// serves: exact names or "*.suffix". A connection for a host the repository already serves
	// only adds headers and needs no entry. Empty: no self-service hosts.
	Hosts []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
}

var hostPatternRe = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// Service stores settings and answers quota and environment questions from a snapshot.
type Service struct {
	Store store.Catalog
	// Defaults supplies the quota of a tenant without settings (the server configuration).
	Defaults func(tenant string) Quota
	snap     res.Snapshot
}

// New returns a service over st; call Refresh (and Watch) before serving decisions.
func New(st store.Catalog, defaults func(string) Quota) *Service {
	return &Service{Store: st, Defaults: defaults, snap: res.Snapshot{Store: st, Kind: model.KindTenantSettings}}
}

// Put writes tenant's settings as a new revision. Admin only; the API enforces that.
func (s *Service) Put(ctx context.Context, tenant string, d *res.Document, who string) (*model.CatalogItem, error) {
	it, err := s.Validate(ctx, tenant, d, who)
	if err != nil {
		return nil, err
	}
	if err := s.Store.PutItem(ctx, it, d.Expected()); err != nil {
		return nil, err
	}
	return it, s.Refresh(ctx)
}

// Validate checks a document and returns the item it would become, without writing.
func (s *Service) Validate(_ context.Context, tenant string, d *res.Document, who string) (*model.CatalogItem, error) {
	if tenant == "" {
		return nil, fmt.Errorf("%w: settings need a tenant", res.ErrInvalid)
	}
	if d.Name == "" {
		d.Name = Name
	}
	if d.Name != Name {
		return nil, fmt.Errorf("%w: name must be %q", res.ErrInvalid, Name)
	}
	if err := res.CheckDocument(d, model.KindTenantSettings); err != nil {
		return nil, err
	}
	var sp Spec
	if err := res.DecodeStrict(d.Spec, &sp); err != nil {
		return nil, err
	}
	if sp.Quota != nil && (sp.Quota.MaxSandboxes < 0 || sp.Quota.MaxAwake < 0) {
		return nil, fmt.Errorf("%w: quota values must be >= 0", res.ErrInvalid)
	}
	for _, e := range sp.Environments {
		r, err := res.ParseRef(e)
		if err != nil || r.Rev != 0 {
			return nil, fmt.Errorf("%w: environments: %q must be \"name\" or \"shared/name\"", res.ErrInvalid, e)
		}
	}
	for i, h := range sp.Hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if !hostPatternRe.MatchString(h) {
			return nil, fmt.Errorf("%w: hosts: %q must be a host name or \"*.suffix\"", res.ErrInvalid, sp.Hosts[i])
		}
		sp.Hosts[i] = h
	}
	spec, err := res.Marshal(sp)
	if err != nil {
		return nil, err
	}
	return &model.CatalogItem{Kind: model.KindTenantSettings, Tenant: tenant, Name: Name, Description: d.Description, Spec: spec, CreatedBy: who}, nil
}

// Get returns tenant's settings (revision 0 = latest); ErrNotFound when the defaults apply.
func (s *Service) Get(ctx context.Context, tenant string, revision int) (*model.CatalogItem, error) {
	return s.Store.GetItem(ctx, model.KindTenantSettings, tenant, Name, revision)
}

// Revisions lists the settings history.
func (s *Service) Revisions(ctx context.Context, tenant string) ([]*model.CatalogItem, error) {
	return s.Store.ListRevisions(ctx, model.KindTenantSettings, tenant, Name)
}

// Delete returns the tenant to the defaults (history kept).
func (s *Service) Delete(ctx context.Context, tenant string) error {
	if err := s.Store.DeleteItem(ctx, model.KindTenantSettings, tenant, Name); err != nil {
		return err
	}
	return s.Refresh(ctx)
}

// Refresh reloads the snapshot.
func (s *Service) Refresh(ctx context.Context) error { return s.snap.Refresh(ctx) }

// Watch keeps the snapshot fresh until ctx ends.
func (s *Service) Watch(ctx context.Context, log *slog.Logger) {
	s.snap.Watch(ctx, func(err error) {
		if log != nil {
			log.Error("tenant settings refresh failed, keeping the previous set", "err", err)
		}
	})
}

func (s *Service) current(tenant string) *Spec {
	it := s.snap.Get(tenant, Name)
	if it == nil {
		return nil
	}
	var sp Spec
	if err := res.DecodeStrict(it.Spec, &sp); err != nil {
		return nil
	}
	return &sp
}

// QuotaFor is the tenant's quota: its settings when they set one, else the defaults.
func (s *Service) QuotaFor(tenant string) Quota {
	if sp := s.current(tenant); sp != nil && sp.Quota != nil {
		return *sp.Quota
	}
	if s.Defaults != nil {
		return s.Defaults(tenant)
	}
	return Quota{}
}

// Restricted reports whether tenant's agents are confined to listed environments. A
// restricted tenant cannot create sandboxes by bare slug: that path runs the server's default
// environment, which is not one of the listed ones.
func (s *Service) Restricted(tenant string) bool {
	sp := s.current(tenant)
	return sp != nil && len(sp.Environments) > 0
}

// HostAllowed reports whether tenant may declare a connection for host on its own (tenant
// settings `hosts`). The admin's shared connections are not subject to it.
func (s *Service) HostAllowed(tenant, host string) bool {
	sp := s.current(tenant)
	if sp == nil {
		return false
	}
	host = strings.ToLower(host)
	for _, pat := range sp.Hosts {
		if pat == host || strings.HasPrefix(pat, "*.") && strings.HasSuffix(host, pat[1:]) && len(host) > len(pat)-1 {
			return true
		}
	}
	return false
}

// EnvironmentAllowed reports whether tenant may use the environment named by ref ("name" or
// "shared/name", as resource.RefOf renders it).
func (s *Service) EnvironmentAllowed(tenant, ref string) bool {
	sp := s.current(tenant)
	if sp == nil || len(sp.Environments) == 0 {
		return true
	}
	ref = strings.TrimSpace(ref)
	for _, e := range sp.Environments {
		if e == ref {
			return true
		}
	}
	return false
}
