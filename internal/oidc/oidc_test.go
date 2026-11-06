package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/httpapi"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIdP serves discovery and a JWKS for one RSA key and signs tokens with it.
type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "jwks_uri": p.srv.URL + "/keys", "authorization_endpoint": p.srv.URL + "/auth",
			"token_endpoint": p.srv.URL + "/token", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeIdP) token(t *testing.T, claims map[string]any, ttl time.Duration) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	std := jwt.Claims{Issuer: p.srv.URL, Subject: "u1", Audience: jwt.Audience{"sandboxd"}, Expiry: jwt.NewNumericDate(time.Now().Add(ttl)), IssuedAt: jwt.NewNumericDate(time.Now())}
	raw, err := jwt.Signed(signer).Claims(std).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerify(t *testing.T) {
	idp := newIdP(t)
	v, err := New(Config{Issuer: idp.srv.URL, ClientID: "sandboxd", TenantClaim: "groups", TenantPrefix: "sandbox-tenant:", TTLFromToken: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pr, err := v.Verify(ctx, idp.token(t, map[string]any{"groups": []string{"dev", "sandbox-tenant:acme"}}, time.Hour))
	if err != nil || pr.Tenant != "acme" || pr.Admin || pr.Subject != "u1" || pr.Expires == nil || time.Until(*pr.Expires) < 50*time.Minute {
		t.Fatalf("tenant token: %+v %v", pr, err)
	}
	pr, err = v.Verify(ctx, idp.token(t, map[string]any{"roles": []string{"sandbox-admin"}}, time.Hour))
	if err != nil || !pr.Admin || pr.Tenant != "" {
		t.Fatalf("admin token: %+v %v", pr, err)
	}
	if _, err := v.Verify(ctx, idp.token(t, map[string]any{"groups": []string{"dev"}}, time.Hour)); err == nil {
		t.Fatal("token without tenant or admin role must be refused")
	}
	if _, err := v.Verify(ctx, idp.token(t, map[string]any{"groups": []string{"sandbox-tenant:acme"}}, -time.Minute)); err == nil {
		t.Fatal("expired token must be refused")
	}
	other := newIdP(t)
	if _, err := v.Verify(ctx, other.token(t, map[string]any{"groups": []string{"sandbox-tenant:acme"}}, time.Hour)); err == nil {
		t.Fatal("token from another issuer must be refused")
	}
	if _, err := v.Verify(ctx, "not.a.jwt"); err == nil {
		t.Fatal("garbage must be refused")
	}
	// Flat tenant claim.
	v2, _ := New(Config{Issuer: idp.srv.URL, ClientID: "sandboxd"})
	if pr, err := v2.Verify(ctx, idp.token(t, map[string]any{"tenant": "beta"}, time.Hour)); err != nil || pr.Tenant != "beta" {
		t.Fatalf("flat tenant claim: %+v %v", pr, err)
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("issuer is required")
	}
}

// An identity provider that does not answer (its discovery document, or later its keys) is
// ErrVerifierUnavailable; a token that is simply bad is not.
func TestVerifyTellsAnOutageFromABadToken(t *testing.T) {
	ctx := context.Background()
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	v, _ := New(Config{Issuer: gone.URL, ClientID: "sandboxd"})
	if _, err := v.Verify(ctx, "a.b.c"); !errors.Is(err, httpapi.ErrVerifierUnavailable) {
		t.Fatalf("discovery down: %v", err)
	}

	idp := newIdP(t)
	var keysDown atomic.Bool
	orig := idp.srv.Config.Handler
	idp.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/keys" && keysDown.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		orig.ServeHTTP(w, r)
	})
	keysDown.Store(true)
	v, _ = New(Config{Issuer: idp.srv.URL, ClientID: "sandboxd"})
	good := idp.token(t, map[string]any{"tenant": "acme"}, time.Hour)
	if _, err := v.Verify(ctx, good); !errors.Is(err, httpapi.ErrVerifierUnavailable) {
		t.Fatalf("keys down: %v", err)
	}
	keysDown.Store(false)
	if pr, err := v.Verify(ctx, good); err != nil || pr.Tenant != "acme" {
		t.Fatalf("keys back: %+v %v", pr, err)
	}
	other := newIdP(t)
	for _, bad := range []string{"not.a.jwt", other.token(t, map[string]any{"tenant": "acme"}, time.Hour), idp.token(t, map[string]any{"tenant": "acme"}, -time.Minute)} {
		if _, err := v.Verify(ctx, bad); err == nil || errors.Is(err, httpapi.ErrVerifierUnavailable) {
			t.Fatalf("a bad token must be refused as such: %v", err)
		}
	}
}
