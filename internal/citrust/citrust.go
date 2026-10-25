// Package citrust is the versioned catalogue of CI trusts (kind CITrust): what a CI provider
// asserts about a job, trusted to act as a tenant for a short while. A job presents the
// provider's OpenID Connect ID token (GitHub Actions, GitLab CI, a Forgejo that issues them);
// the platform verifies it against the issuer's keys and, when a trust of the tenant matches
// its claims (the repository, the ref, whatever the trust names), issues a tenant API key that
// expires in minutes (see internal/ciauth). Nothing long-lived is stored in the CI provider:
// the trust is the credential, and it names what may act, not a secret.
package citrust

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// Spec is a CITrust.
type Spec struct {
	// Issuer is the token issuer, exactly as the `iss` claim names it: GitHub Actions is
	// https://token.actions.githubusercontent.com, GitLab is the instance URL
	// (https://gitlab.com), a Forgejo that issues ID tokens is its URL.
	Issuer string `yaml:"issuer" json:"issuer"`
	// Audience is the value the job requests its token for (the `aud` claim); by convention
	// the platform's URL. A token for another audience is refused, so a token meant for
	// another service never opens this one.
	Audience string `yaml:"audience" json:"audience"`
	// Claims name what the token must say, each one exactly or as a pattern (`*`, `?`, `[...]`
	// within one segment, path.Match): GitHub's `repository: acme/config` and
	// `ref: refs/heads/main`, GitLab's `project_path: acme/config` and `ref: main`. At least
	// one; a trust that names only the issuer would let any job of that provider in.
	Claims map[string]string `yaml:"claims" json:"claims"`
	// TTL is the lifetime of the key a matching job gets (default 15m, at least 1m, capped by
	// the server's ci_auth.max_ttl).
	TTL string `yaml:"ttl,omitempty" json:"ttl,omitempty"`
}

// DefaultTTL is the key lifetime when the trust names none.
const DefaultTTL = 15 * time.Minute

// MaxClaims bounds a trust's claim list.
const MaxClaims = 16

var (
	claimRe = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]{0,63}$`)
	// reserved are the claims the verification itself decides: never a trust's to match.
	reserved = map[string]bool{"iss": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true}
)

// Service validates and stores trusts.
type Service struct {
	Store store.Catalog
	// MaxTTL caps spec.ttl (0: one hour).
	MaxTTL time.Duration
}

// New returns a service over st.
func New(st store.Catalog, maxTTL time.Duration) *Service {
	return &Service{Store: st, MaxTTL: maxTTL}
}

func (s *Service) maxTTL() time.Duration {
	if s.MaxTTL > 0 {
		return s.MaxTTL
	}
	return time.Hour
}

// Put validates a document and appends it as a new revision in tenant's scope.
func (s *Service) Put(ctx context.Context, tenant string, d *res.Document, admin bool, who string) (*model.CatalogItem, error) {
	it, err := s.Validate(ctx, tenant, d, admin, who)
	if err != nil {
		return nil, err
	}
	return it, s.Store.PutItem(ctx, it, d.Expected())
}

// Validate checks a document and returns the item it would become, without writing. A trust
// belongs to a tenant: the shared scope has none (an admin's job keeps the admin token).
func (s *Service) Validate(_ context.Context, tenant string, d *res.Document, _ bool, who string) (*model.CatalogItem, error) {
	if err := res.CheckDocument(d, model.KindCITrust); err != nil {
		return nil, err
	}
	if tenant == "" {
		return nil, fmt.Errorf("%w: a CITrust belongs to a tenant; the shared scope has none", res.ErrInvalid)
	}
	var sp Spec
	if err := res.DecodeStrict(d.Spec, &sp); err != nil {
		return nil, err
	}
	if err := CheckIssuer(sp.Issuer); err != nil {
		return nil, fmt.Errorf("%w: spec.issuer: %v", res.ErrInvalid, err)
	}
	if strings.TrimSpace(sp.Audience) == "" || len(sp.Audience) > 256 || strings.ContainsAny(sp.Audience, " \t\r\n") {
		return nil, fmt.Errorf("%w: spec.audience is required: the value the job requests its token for (the platform's URL), up to 256 characters without spaces", res.ErrInvalid)
	}
	if len(sp.Claims) == 0 {
		return nil, fmt.Errorf("%w: spec.claims must name at least one claim (the repository the job runs for)", res.ErrInvalid)
	}
	if len(sp.Claims) > MaxClaims {
		return nil, fmt.Errorf("%w: spec.claims: at most %d claims", res.ErrInvalid, MaxClaims)
	}
	for name, want := range sp.Claims {
		if !claimRe.MatchString(name) {
			return nil, fmt.Errorf("%w: spec.claims: %q is not a claim name", res.ErrInvalid, name)
		}
		if reserved[name] {
			return nil, fmt.Errorf("%w: spec.claims: %s is checked by the verification itself (issuer and audience are the trust's own fields)", res.ErrInvalid, name)
		}
		if want == "" || len(want) > 512 {
			return nil, fmt.Errorf("%w: spec.claims.%s must be a value or a pattern of up to 512 characters", res.ErrInvalid, name)
		}
		if _, err := path.Match(want, ""); err != nil {
			return nil, fmt.Errorf("%w: spec.claims.%s: %v", res.ErrInvalid, name, err)
		}
	}
	if _, err := s.TTLOf(sp); err != nil {
		return nil, fmt.Errorf("%w: spec.ttl: %v", res.ErrInvalid, err)
	}
	spec, err := json.Marshal(sp) // the canonical form: field order fixed, unknown fields gone
	if err != nil {
		return nil, err
	}
	return &model.CatalogItem{Kind: model.KindCITrust, Tenant: tenant, Name: d.Name, Description: d.Description, Spec: spec, CreatedBy: who}, nil
}

// TTLOf is the key lifetime a trust grants: its ttl, the default without one, within the cap.
func (s *Service) TTLOf(sp Spec) (time.Duration, error) {
	ttl := DefaultTTL
	if sp.TTL != "" {
		d, err := time.ParseDuration(sp.TTL)
		if err != nil {
			return 0, fmt.Errorf("%q is not a duration (15m, 1h)", sp.TTL)
		}
		ttl = d
	}
	if ttl < time.Minute {
		return 0, fmt.Errorf("at least 1m")
	}
	if ttl > s.maxTTL() {
		return 0, fmt.Errorf("at most %s (ci_auth.max_ttl)", s.maxTTL())
	}
	return ttl, nil
}

// Decode returns the spec of a stored item.
func Decode(it *model.CatalogItem) (Spec, error) {
	var sp Spec
	err := res.DecodeStrict(it.Spec, &sp)
	return sp, err
}

// CheckIssuer accepts an https URL without user information, query or fragment (http for a
// loopback host only, for tests), as an issuer names itself.
func CheckIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.User != nil || u.Host == "" || u.Opaque != "" || u.Fragment != "" || u.RawQuery != "" {
		return fmt.Errorf("must be the issuer's URL (scheme, host, path)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("http is accepted for a loopback host only; use https")
		}
	default:
		return fmt.Errorf("scheme %q is not https", u.Scheme)
	}
	if strings.HasSuffix(u.Path, "/") {
		return fmt.Errorf("must not end with a slash: the iss claim is compared exactly")
	}
	return nil
}

// Matches reports whether the token's claims satisfy every claim the trust names: a string
// claim exactly or by pattern; a list claim when one entry does; anything else never. The
// names are sorted so a mismatch is reported deterministically.
func Matches(sp Spec, claims map[string]any) (bool, string) {
	names := make([]string, 0, len(sp.Claims))
	for n := range sp.Claims {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		want := sp.Claims[n]
		switch got := claims[n].(type) {
		case string:
			if !matchOne(want, got) {
				return false, fmt.Sprintf("%s is %q, the trust wants %q", n, got, want)
			}
		case []any:
			found := false
			for _, e := range got {
				if s, ok := e.(string); ok && matchOne(want, s) {
					found = true
					break
				}
			}
			if !found {
				return false, fmt.Sprintf("%s has no entry matching %q", n, want)
			}
		default:
			return false, fmt.Sprintf("%s is absent or not a string", n)
		}
	}
	return true, ""
}

func matchOne(want, got string) bool {
	if want == got {
		return true
	}
	ok, err := path.Match(want, got)
	return err == nil && ok
}

// Get returns a trust of the tenant at a revision (0 = latest).
func (s *Service) Get(ctx context.Context, tenant, name string, revision int) (*model.CatalogItem, error) {
	return res.Lookup(ctx, s.Store, model.KindCITrust, tenant, res.Ref{Name: name, Rev: revision})
}

// List returns the latest revisions visible from tenant.
func (s *Service) List(ctx context.Context, tenant string) ([]*model.CatalogItem, error) {
	return res.ListVisible(ctx, s.Store, model.KindCITrust, tenant)
}

// Revisions lists a trust's history.
func (s *Service) Revisions(ctx context.Context, tenant, name string) ([]*model.CatalogItem, error) {
	return res.Revisions(ctx, s.Store, model.KindCITrust, tenant, name)
}

// Delete hides a trust: no job matches it from then on.

func (s *Service) Delete(ctx context.Context, tenant, name string) error {
	return s.Store.DeleteItem(ctx, model.KindCITrust, tenant, name)
}
