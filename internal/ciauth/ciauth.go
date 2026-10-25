// Package ciauth exchanges a CI provider's OpenID Connect ID token for a short-lived tenant
// API key, under a CITrust (internal/citrust). The job proves who it is with the token its
// provider issued to it for this run (GitHub Actions, GitLab CI, a Forgejo that issues them);
// the platform verifies the token against the issuer's published keys, finds the trust of a
// tenant whose issuer, audience and claims the token satisfies, uses the token once, and
// issues a key that expires minutes later. Nothing long-lived is stored in the CI provider.
package ciauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/citrust"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Errors the API maps to status codes.
var (
	// ErrRefused: the token is not one a trust accepts (401). The reason is logged, not told:
	// the caller learns nothing about which trusts exist.
	ErrRefused = errors.New("the token is not accepted by any CI trust")
	// ErrIssuer: the issuer could not be reached for its keys (503).
	ErrIssuer = errors.New("the issuer's keys are not available")
	// ErrDisabled: no key service to issue from (503).
	ErrDisabled = errors.New("CI authentication is disabled")
)

// Grant is the outcome of an exchange: the key, its secret, and what matched.
type Grant struct {
	Key     *model.APIKey `json:"key"`
	Secret  string        `json:"secret"`
	Trust   string        `json:"trust"`
	Tenant  string        `json:"tenant"`
	Subject string        `json:"subject"` // the token's sub, for the audit trail
}

// Service exchanges tokens. Trusts are read from the catalogue on every exchange: a trust
// added or deleted is in effect on the next job, on every replica.
type Service struct {
	Trusts store.Catalog
	Keys   *apikeys.Service
	Uses   store.TokenUses
	// MaxTTL caps a trust's ttl (0: one hour); the trust service validates against the same.
	MaxTTL time.Duration
	// Client fetches discovery and keys (nil: http.DefaultClient).
	Client *http.Client
	Now    func() time.Time
	Log    *slog.Logger

	mu        sync.Mutex
	providers map[string]*gooidc.Provider
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// MaxTokenBytes bounds the ID token a job may present.
const MaxTokenBytes = 16 * 1024

// Exchange verifies raw and issues a key under the matching trust.
func (s *Service) Exchange(ctx context.Context, raw string) (*Grant, error) {
	if s.Keys == nil || s.Uses == nil || s.Trusts == nil {
		return nil, ErrDisabled
	}
	if len(raw) == 0 || len(raw) > MaxTokenBytes {
		return nil, fmt.Errorf("%w: a token is 1 to %d bytes", ErrRefused, MaxTokenBytes)
	}
	// The issuer, read before anything is trusted, selects the trusts and the keys.
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA})
	if err != nil {
		return nil, s.refuse("not a signed JWT", err)
	}
	var unverified jwt.Claims
	if err := parsed.UnsafeClaimsWithoutVerification(&unverified); err != nil || unverified.Issuer == "" {
		return nil, s.refuse("no issuer claim", err)
	}
	trusts, err := s.trustsOf(ctx, unverified.Issuer)
	if err != nil {
		return nil, err
	}
	if len(trusts) == 0 {
		return nil, s.refuse("no CITrust names issuer "+unverified.Issuer, nil)
	}
	provider, err := s.provider(ctx, unverified.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIssuer, err)
	}
	// Signature, issuer and expiry are the verifier's; the audience is each trust's own.
	tok, err := provider.Verifier(&gooidc.Config{SkipClientIDCheck: true}).Verify(ctx, raw)
	if err != nil {
		return nil, s.refuse("verification failed", err)
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return nil, s.refuse("claims unreadable", err)
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, s.refuse("no jti claim: the token could not be used once", nil)
	}
	var matched []trust
	for _, t := range trusts {
		if !contains(tok.Audience, t.spec.Audience) {
			continue
		}
		if ok, _ := citrust.Matches(t.spec, claims); ok {
			matched = append(matched, t)
		}
	}
	if len(matched) == 0 {
		return nil, s.refuse(fmt.Sprintf("no trust of issuer %s matches the token's audience and claims", unverified.Issuer), nil)
	}
	for _, t := range matched[1:] {
		if t.item.Tenant != matched[0].item.Tenant {
			return nil, s.refuse(fmt.Sprintf("trusts of tenants %s and %s both match: the token would have two identities", matched[0].item.Tenant, t.item.Tenant), nil)
		}
	}
	chosen := matched[0]
	ttl, err := (&citrust.Service{MaxTTL: s.MaxTTL}).TTLOf(chosen.spec)
	if err != nil {
		return nil, s.refuse("the trust's ttl is not valid", err)
	}
	// Once: a token presented twice (replayed, or leaked from the job's log) opens nothing.
	exp := tok.Expiry
	if exp.IsZero() {
		exp = s.now().Add(time.Hour)
	}
	if err := s.Uses.UseToken(ctx, unverified.Issuer+"#"+jti, exp); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, s.refuse("the token was exchanged already", nil)
		}
		return nil, err
	}
	name := "ci." + chosen.item.Name // a key name: the trust it came from
	by := "ci:" + tok.Subject
	key, secret, err := s.Keys.CreateTrusted(ctx, chosen.item.Tenant, name, ttl, by, chosen.item.Name)
	if err != nil {
		return nil, err
	}
	if n, perr := s.Keys.Store.PruneTrustedAPIKeys(ctx, s.now().Add(-24*time.Hour)); perr != nil && s.Log != nil {
		s.Log.Warn("ci auth: prune keys", "err", perr)
	} else if n > 0 && s.Log != nil {
		s.Log.Info("ci auth: pruned expired keys", "n", n)
	}
	if s.Log != nil {
		s.Log.Info("ci auth: key issued", "tenant", chosen.item.Tenant, "trust", chosen.item.Name, "subject", tok.Subject, "key", key.ID, "expires", key.ExpiresAt)
	}
	return &Grant{Key: key, Secret: secret, Trust: chosen.item.Name, Tenant: chosen.item.Tenant, Subject: tok.Subject}, nil
}

type trust struct {
	item *model.CatalogItem
	spec citrust.Spec
}

// trustsOf lists the trusts naming issuer, every tenant, in a stable order.
func (s *Service) trustsOf(ctx context.Context, issuer string) ([]trust, error) {
	items, err := s.Trusts.ListKind(ctx, model.KindCITrust)
	if err != nil {
		return nil, err
	}
	var out []trust
	for _, it := range items {
		if it.DeletedAt != nil {
			continue
		}
		sp, err := citrust.Decode(it)
		if err != nil || sp.Issuer != issuer {
			continue
		}
		out = append(out, trust{item: it, spec: sp})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].item.Tenant != out[j].item.Tenant {
			return out[i].item.Tenant < out[j].item.Tenant
		}
		return out[i].item.Name < out[j].item.Name
	})
	return out, nil
}

// provider is the issuer's discovery and keys, fetched once and kept (go-oidc refreshes the
// keys on an unknown key id).
func (s *Service) provider(ctx context.Context, issuer string) (*gooidc.Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.providers[issuer]; ok {
		return p, nil
	}
	if s.Client != nil {
		ctx = gooidc.ClientContext(ctx, s.Client)
	}
	p, err := gooidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	if s.providers == nil {
		s.providers = map[string]*gooidc.Provider{}
	}
	s.providers[issuer] = p
	return p, nil
}

func (s *Service) refuse(reason string, cause error) error {
	if s.Log != nil {
		s.Log.Warn("ci auth: refused", "reason", reason, "err", cause)
	}
	return ErrRefused
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}
