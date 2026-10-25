// Package gitrepo is the versioned catalogue of Git repositories the platform reads bundles
// from itself (kind GitRepository): the URL, the ref to follow, the bundle paths and, by
// reference, the credential that opens the repository. Registering one replaces installing a
// workflow in that repository: the platform checks the ref and syncs a commit on request (see
// internal/gitsync), through the same plan and apply the workflow would run. A credential is
// never stored here: `credential` names a tenant credential (BYOK) or an operator secret, and
// the sync resolves it when it reads the repository.
package gitrepo

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"

	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// Spec is a GitRepository.
type Spec struct {
	// URL of the repository over HTTPS (http only for a loopback host, for tests). Never with
	// user information: the credential is a reference.
	URL string `yaml:"url" json:"url"`
	// Ref is the branch or tag the platform follows (a name, not a SHA): a sync applies the
	// ref's head, or an earlier commit reachable from it.
	Ref string `yaml:"ref" json:"ref"`
	// Paths are the bundle files, relative to the repository root; path patterns (`*`, `?`,
	// `[...]` within one segment) select several. Applied in path order.
	Paths []string `yaml:"paths" json:"paths"`
	// Credential names the secret that opens the repository: a token, or `user:token`. Empty
	// for a public repository. Resolved from the tenant's credentials, then the shared ones.
	Credential string `yaml:"credential,omitempty" json:"credential,omitempty"`
}

var (
	refRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
	pathRe       = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._*?\[\]/-]*$`)
	credentialRe = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
	shaRe        = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// MaxPaths bounds a repository's path list.
const MaxPaths = 32

// Service validates and stores repositories.
type Service struct {
	Store store.Catalog
	// Secrets: when set, a named credential must resolve for the tenant at write time, so a
	// repository is never registered against a secret that does not exist.
	Secrets secrets.Provider
}

// New returns a service over st.
func New(st store.Catalog, sec secrets.Provider) *Service {
	return &Service{Store: st, Secrets: sec}
}

// Put validates a document and appends it as a new revision in tenant's scope.
func (s *Service) Put(ctx context.Context, tenant string, d *res.Document, admin bool, who string) (*model.CatalogItem, error) {
	it, err := s.Validate(ctx, tenant, d, admin, who)
	if err != nil {
		return nil, err
	}
	return it, s.Store.PutItem(ctx, it, d.Expected())
}

// Validate checks a document and returns the item it would become, without writing.
func (s *Service) Validate(ctx context.Context, tenant string, d *res.Document, _ bool, who string) (*model.CatalogItem, error) {
	if err := res.CheckDocument(d, model.KindGitRepository); err != nil {
		return nil, err
	}
	var sp Spec
	if err := res.DecodeStrict(d.Spec, &sp); err != nil {
		return nil, err
	}
	if err := CheckURL(sp.URL); err != nil {
		return nil, fmt.Errorf("%w: spec.url: %v", res.ErrInvalid, err)
	}
	if err := CheckRef(sp.Ref); err != nil {
		return nil, fmt.Errorf("%w: spec.ref: %v", res.ErrInvalid, err)
	}
	if len(sp.Paths) == 0 {
		return nil, fmt.Errorf("%w: spec.paths must name at least one bundle file", res.ErrInvalid)
	}
	if len(sp.Paths) > MaxPaths {
		return nil, fmt.Errorf("%w: spec.paths: at most %d entries", res.ErrInvalid, MaxPaths)
	}
	for i, p := range sp.Paths {
		if err := CheckPath(p); err != nil {
			return nil, fmt.Errorf("%w: spec.paths[%d]: %v", res.ErrInvalid, i, err)
		}
	}
	if sp.Credential != "" {
		if !credentialRe.MatchString(sp.Credential) {
			return nil, fmt.Errorf("%w: spec.credential must be a secret name, not a value", res.ErrInvalid)
		}
		if s.Secrets != nil {
			if _, err := s.Secrets.Get(ctx, tenant, sp.Credential); err != nil {
				return nil, fmt.Errorf("%w: spec.credential: secret %q is not available to tenant %q", res.ErrInvalid, sp.Credential, tenant)
			}
		}
	}
	spec, err := json.Marshal(sp) // the canonical form: field order fixed, unknown fields gone
	if err != nil {
		return nil, err
	}
	return &model.CatalogItem{Kind: model.KindGitRepository, Tenant: tenant, Name: d.Name, Description: d.Description, Spec: spec, CreatedBy: who}, nil
}

// Decode returns the spec of a stored item.
func Decode(it *model.CatalogItem) (Spec, error) {
	var sp Spec
	err := res.DecodeStrict(it.Spec, &sp)
	return sp, err
}

// CheckURL accepts an https URL without user information (http for a loopback host only).
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.User != nil {
		return fmt.Errorf("must not carry user information; name a credential instead")
	}
	if u.Host == "" || u.Opaque != "" || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("must be the repository's URL (scheme, host, path)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("http is accepted for a loopback host only; use https")
		}
	default:
		return fmt.Errorf("scheme must be https")
	}
	return nil
}

// CheckRef accepts a branch or tag name; never a SHA (the sync pins commits, the ref follows).
func CheckRef(ref string) error {
	switch {
	case ref == "":
		return fmt.Errorf("a branch or tag is required")
	case !refRe.MatchString(ref), strings.Contains(ref, ".."), strings.HasSuffix(ref, ".lock"), strings.HasSuffix(ref, "/"), strings.Contains(ref, "//"):
		return fmt.Errorf("%q is not a branch or tag name", ref)
	case shaRe.MatchString(ref):
		return fmt.Errorf("a ref names a branch or tag; a commit is chosen at sync")
	}
	return nil
}

// CheckPath accepts a relative file path or pattern inside the repository.
func CheckPath(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("empty")
	case !pathRe.MatchString(p), strings.Contains(p, ".."), strings.HasSuffix(p, "/"), strings.Contains(p, "//"):
		return fmt.Errorf("%q is not a relative file path or pattern", p)
	}
	if _, err := path.Match(p, ""); err != nil {
		return fmt.Errorf("%q: %v", p, err)
	}
	return nil
}

// Get returns a repository visible from tenant (own, or shared) at a revision (0 = latest).
func (s *Service) Get(ctx context.Context, tenant, name string, revision int) (*model.CatalogItem, error) {
	return res.Lookup(ctx, s.Store, model.KindGitRepository, tenant, res.Ref{Name: name, Rev: revision})
}

// List returns the latest revisions visible from tenant.
func (s *Service) List(ctx context.Context, tenant string) ([]*model.CatalogItem, error) {
	return res.ListVisible(ctx, s.Store, model.KindGitRepository, tenant)
}

// Revisions lists a repository's history.
func (s *Service) Revisions(ctx context.Context, tenant, name string) ([]*model.CatalogItem, error) {
	return res.Revisions(ctx, s.Store, model.KindGitRepository, tenant, name)
}

// Delete hides a repository; its applies and the revisions they wrote stay.
func (s *Service) Delete(ctx context.Context, tenant, name string) error {
	return s.Store.DeleteItem(ctx, model.KindGitRepository, tenant, name)
}
