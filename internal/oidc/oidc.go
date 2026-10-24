// Package oidc authenticates platform API calls with OpenID Connect tokens: the identity
// provider's discovery document and JWKS are fetched from the issuer, the JWT's signature,
// issuer, audience and expiry are verified, and the tenant and admin role are read from claims.
//
// The token's lifetime is the caller's lifetime on the API; with ttl_from_token the sandboxes
// it creates (and the agent certificates inside them) expire with it too.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"agent-sandbox/internal/httpapi"
)

// Config is the oidc section of sandboxd.yaml.
type Config struct {
	Issuer   string `yaml:"issuer"`    // https://login.example.com/realms/platform
	ClientID string `yaml:"client_id"` // expected audience; "" skips the audience check (not recommended)
	// TenantClaim names the claim holding the tenant (default "tenant"). With TenantPrefix the
	// claim may be a list (groups) and the tenant is the entry starting with the prefix, e.g.
	// groups ["sandbox-tenant:acme"] with prefix "sandbox-tenant:" → tenant "acme".
	TenantClaim  string `yaml:"tenant_claim"`
	TenantPrefix string `yaml:"tenant_prefix"`
	// AdminClaim / AdminValue: the caller is the admin when the claim (string or list) contains
	// AdminValue. Default claim "roles", value "sandbox-admin".
	AdminClaim string `yaml:"admin_claim"`
	AdminValue string `yaml:"admin_value"`
	// TTLFromToken caps sandboxes created with this token at the token's expiry (API, sandbox
	// and agent certificate share one lifetime).
	TTLFromToken bool `yaml:"ttl_from_token"`
	// Discovery is the issuer URL to fetch metadata from when it differs from the issuer in
	// tokens (some providers behind proxies). Default: Issuer.
	Discovery string `yaml:"discovery"`
}

func (c *Config) defaults() {
	if c.TenantClaim == "" {
		c.TenantClaim = "tenant"
	}
	if c.AdminClaim == "" {
		c.AdminClaim = "roles"
	}
	if c.AdminValue == "" {
		c.AdminValue = "sandbox-admin"
	}
	if c.Discovery == "" {
		c.Discovery = c.Issuer
	}
}

// Verifier implements httpapi.TokenVerifier. Discovery is lazy and retried: sandboxd starts
// even when the identity provider is down, and static tokens keep working meanwhile.
type Verifier struct {
	cfg Config

	mu       sync.Mutex
	verifier *gooidc.IDTokenVerifier
	lastErr  error
	lastTry  time.Time
}

// New builds a verifier for cfg. An empty issuer is a configuration error.
func New(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("oidc.issuer is required")
	}
	cfg.defaults()
	return &Verifier{cfg: cfg}, nil
}

func (v *Verifier) idTokenVerifier(ctx context.Context) (*gooidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}
	if time.Since(v.lastTry) < 5*time.Second && v.lastErr != nil {
		return nil, v.lastErr
	}
	v.lastTry = time.Now()
	dctx := ctx
	if v.cfg.Discovery != v.cfg.Issuer {
		dctx = gooidc.InsecureIssuerURLContext(ctx, v.cfg.Issuer)
	}
	provider, err := gooidc.NewProvider(dctx, v.cfg.Discovery)
	if err != nil {
		v.lastErr = fmt.Errorf("oidc discovery: %w", err)
		return nil, v.lastErr
	}
	v.verifier = provider.Verifier(&gooidc.Config{ClientID: v.cfg.ClientID, SkipClientIDCheck: v.cfg.ClientID == ""})
	v.lastErr = nil
	return v.verifier, nil
}

// Verify checks the token and maps its claims to a principal.
func (v *Verifier) Verify(ctx context.Context, raw string) (httpapi.Principal, error) {
	ver, err := v.idTokenVerifier(ctx)
	if err != nil {
		return httpapi.Principal{}, err
	}
	tok, err := ver.Verify(ctx, raw)
	if err != nil {
		return httpapi.Principal{}, err
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return httpapi.Principal{}, err
	}
	pr := httpapi.Principal{Subject: tok.Subject, Expires: tok.Expiry}
	pr.Admin = contains(claims[v.cfg.AdminClaim], v.cfg.AdminValue)
	pr.Tenant = v.tenantOf(claims)
	if pr.Tenant == "" && !pr.Admin {
		return httpapi.Principal{}, fmt.Errorf("token carries no tenant (claim %q) and no admin role", v.cfg.TenantClaim)
	}
	return pr, nil
}

func (v *Verifier) tenantOf(claims map[string]any) string {
	raw := claims[v.cfg.TenantClaim]
	if v.cfg.TenantPrefix == "" {
		if s, ok := raw.(string); ok {
			return s
		}
		if xs, ok := raw.([]any); ok && len(xs) == 1 {
			s, _ := xs[0].(string)
			return s
		}
		return ""
	}
	for _, s := range strs(raw) {
		if strings.HasPrefix(s, v.cfg.TenantPrefix) {
			return strings.TrimPrefix(s, v.cfg.TenantPrefix)
		}
	}
	return ""
}

func strs(raw any) []string {
	switch x := raw.(type) {
	case string:
		return strings.Fields(x)
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	}
	return nil
}

func contains(raw any, want string) bool {
	for _, s := range strs(raw) {
		if s == want {
			return true
		}
	}
	return false
}
