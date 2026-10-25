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
	// ErrIssuer: the issuer's discovery document or keys could not be fetched, or are not the
	// issuer's (503: the platform cannot tell whether the token is good).
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
	// Client fetches discovery documents and keys (nil: a client with a 10s timeout).
	Client *http.Client
	Now    func() time.Time
	Log    *slog.Logger

	mu      sync.Mutex // guards the map only; each issuer has its own lock
	issuers map[string]*issuerKeys
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// MaxTokenBytes bounds the ID token a job may present.
const MaxTokenBytes = 16 * 1024

// signatureAlgorithms a token may carry: asymmetric only (a shared secret would make the
// platform able to mint the provider's tokens).
var signatureAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA}

// Exchange verifies raw and issues a key under the matching trust. The token is counted as
// used only once its key is stored: a key the store could not write leaves the token for the
// job's retry, and a key stored for a token that turns out used already is removed before
// anything learns its secret.
func (s *Service) Exchange(ctx context.Context, raw string) (*Grant, error) {
	if s.Keys == nil || s.Uses == nil || s.Trusts == nil {
		return nil, ErrDisabled
	}
	if len(raw) == 0 || len(raw) > MaxTokenBytes {
		return nil, fmt.Errorf("%w: a token is 1 to %d bytes", ErrRefused, MaxTokenBytes)
	}
	// The issuer, read before anything is trusted, selects the trusts and the keys.
	parsed, err := jwt.ParseSigned(raw, signatureAlgorithms)
	if err != nil || len(parsed.Headers) != 1 {
		return nil, s.refuse("not a JWT with one signature", err)
	}
	var unverified jwt.Claims
	if err := parsed.UnsafeClaimsWithoutVerification(&unverified); err != nil || unverified.Issuer == "" {
		return nil, s.refuse("no issuer claim", err)
	}
	issuer := unverified.Issuer
	trusts, err := s.trustsOf(ctx, issuer)
	if err != nil {
		return nil, err
	}
	if len(trusts) == 0 {
		return nil, s.refuse("no CITrust names issuer "+issuer, nil)
	}
	// The issuer's keys: unavailable keys are the issuer's problem, not the token's.
	kid := parsed.Headers[0].KeyID
	keys, err := s.keysFor(ctx, issuer, kid)
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("ci auth: issuer unavailable", "issuer", issuer, "err", err)
		}
		return nil, fmt.Errorf("%w: %v", ErrIssuer, err)
	}
	if len(keys) == 0 {
		return nil, s.refuse(fmt.Sprintf("issuer %s has no signing key %q", issuer, kid), nil)
	}
	var (
		std    jwt.Claims
		claims map[string]any
	)
	verified := false
	for i := range keys {
		if err = parsed.Claims(&keys[i], &std, &claims); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, s.refuse("signature not verified by the issuer's keys", err)
	}
	// Issuer, expiry and not-before are the token's own; the audience is each trust's.
	if std.Expiry == nil {
		return nil, s.refuse("no exp claim", nil)
	}
	if err := std.Validate(jwt.Expected{Issuer: issuer, Time: s.now()}); err != nil {
		return nil, s.refuse("claims not valid", err)
	}
	jti := std.ID
	if jti == "" {
		return nil, s.refuse("no jti claim: the token could not be used once", nil)
	}
	var matched []trust
	for _, t := range trusts {
		if !contains(std.Audience, t.spec.Audience) {
			continue
		}
		if ok, _ := citrust.Matches(t.spec, claims); ok {
			matched = append(matched, t)
		}
	}
	if len(matched) == 0 {
		return nil, s.refuse(fmt.Sprintf("no trust of issuer %s matches the token's audience and claims", issuer), nil)
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
	// The key first, then the token's one use: a key the store refused leaves the token
	// unused for the job's retry. Once: a token presented twice (replayed, or leaked from the
	// job's log) opens nothing, and the key stored for the second presentation is removed
	// before its secret leaves this call.
	key, secret, err := s.Keys.CreateTrusted(ctx, chosen.item.Tenant, keyName(chosen.item.Name), ttl, "ci:"+std.Subject, chosen.item.Name)
	if err != nil {
		return nil, err
	}
	if err := s.Uses.UseToken(ctx, issuer+"#"+jti, std.Expiry.Time()); err != nil {
		if derr := s.Keys.Store.DeleteAPIKey(ctx, key.ID); derr != nil && s.Log != nil {
			s.Log.Warn("ci auth: key of a refused exchange not removed", "key", key.ID, "err", derr)
		}
		if errors.Is(err, store.ErrConflict) {
			return nil, s.refuse("the token was exchanged already", nil)
		}
		return nil, err
	}
	if n, perr := s.Keys.Store.PruneTrustedAPIKeys(ctx, s.now().Add(-24*time.Hour)); perr != nil && s.Log != nil {
		s.Log.Warn("ci auth: prune keys", "err", perr)
	} else if n > 0 && s.Log != nil {
		s.Log.Info("ci auth: pruned expired keys", "n", n)
	}
	if s.Log != nil {
		s.Log.Info("ci auth: key issued", "tenant", chosen.item.Tenant, "trust", chosen.item.Name, "subject", std.Subject, "key", key.ID, "expires", key.ExpiresAt)
	}
	return &Grant{Key: key, Secret: secret, Trust: chosen.item.Name, Tenant: chosen.item.Tenant, Subject: std.Subject}, nil
}

// keyName labels a key with the trust it came from, within a key name's length; the key's
// trust field carries the whole name.
func keyName(trust string) string {
	n := "ci." + trust
	if len(n) > apikeys.MaxNameLen {
		n = n[:apikeys.MaxNameLen]
	}
	return n
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
