// Package services assembles the configuration validators the one way, whatever store they
// read from: the live store for the API (app.Wire) and the read-only overlay of a bundle for
// plan and apply. A document is accepted or refused by the same rules on either path, so a
// bundle cannot pass what a PUT refuses, or the other way round.
package services

import (
	"time"

	"agent-sandbox/internal/bindings"
	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/citrust"
	"agent-sandbox/internal/connections"
	"agent-sandbox/internal/gitrepo"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/tenants"
)

// Options is what the validators decide against besides the store.
type Options struct {
	Policies  *policy.Set
	Images    catalog.Images
	Secrets   secrets.Provider
	Defaults  func(tenant string) tenants.Quota
	Sandboxes connections.Sandboxes // the gateway side only (HeadersFor, RuleFor); nil for planning
	Now       func() time.Time
	// CITrustMaxTTL caps the key lifetime a CITrust may grant (0: one hour).
	CITrustMaxTTL time.Duration
}

// Set is the assembled validators over one store.
type Set struct {
	Tenants     *tenants.Service
	Bindings    *bindings.Service
	Connections *connections.Service
	Guard       *bindings.Guard
	Catalog     *catalog.Service
	GitRepos    *gitrepo.Service
	CITrusts    *citrust.Service
}

// Assemble builds the set over st. Snapshots are not loaded: the caller refreshes.
func Assemble(st store.Catalog, o Options) *Set {
	tset := tenants.New(st, o.Defaults)
	bind := bindings.New(st, o.Policies)
	if o.Now != nil {
		bind.Now = o.Now
	}
	conns := connections.New(st, o.Secrets, o.Sandboxes)
	// Which hosts a connection may serve on its own: the repository's are the repository's, any
	// other needs the tenant's settings (read from the same store, so a bundle that lists the
	// host and declares the connection is accepted as a whole).
	conns.Hosts = HostPolicy{Repository: o.Policies, Settings: tset}
	guard := &bindings.Guard{Set: o.Policies, Bindings: bind, Headers: conns}
	cat := &catalog.Service{Store: st, Images: o.Images, Policies: guard, Connections: conns, Tenants: tset}
	return &Set{Tenants: tset, Bindings: bind, Connections: conns, Guard: guard, Catalog: cat, GitRepos: gitrepo.New(st, o.Secrets), CITrusts: citrust.New(st, o.CITrustMaxTTL)}
}

// HostPolicy answers which hosts a connection may serve on its own: the repository's hosts are
// the repository's (a connection adds headers only); any other host needs the tenant's
// settings to list it.
type HostPolicy struct {
	Repository *policy.Set
	Settings   *tenants.Service
}

func (h HostPolicy) HostInfo(name string) (policy.Host, bool) { return h.Repository.HostInfo(name) }
func (h HostPolicy) HostAllowed(tenant, host string) bool {
	return h.Settings.HostAllowed(tenant, host)
}
