package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/app"
	"agent-sandbox/internal/ciauth"
	"agent-sandbox/internal/secrets"
)

// ciIssuer stands for a CI provider's token service.
type ciIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	n   int
}

func newCIIssuer(t *testing.T) *ciIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &ciIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.srv.URL, "jwks_uri": p.srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *ciIssuer) token(t *testing.T, aud, repository, ref string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	p.n++
	std := jwt.Claims{Issuer: p.srv.URL, Subject: "repo:" + repository + ":ref:" + ref, Audience: jwt.Audience{aud}, ID: "jti-" + time.Now().Format("150405.000000") + "-" + string(rune('a'+p.n%26)),
		Expiry: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(time.Now())}
	raw, err := jwt.Signed(signer).Claims(std).Claims(map[string]any{"repository": repository, "ref": ref}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A tenant registers a CITrust for its repository; a job of that repository exchanges its ID
// token for a key that acts as the tenant and expires with the trust's ttl; the token works
// once; another repository, another audience and the other tenant's scope get nothing.
func TestCITrustExchangeOnTheRealStack(t *testing.T) {
	s := newStack(t)
	st := s.orch.Store
	// The same assembly sandboxd runs: plan, the CITrust service and the key service come from it.
	services, err := app.Wire(context.Background(), app.Deps{Store: st, Policies: s.p.Policies, Secrets: secrets.Static{}, Orch: s.orch})
	if err != nil {
		t.Fatal(err)
	}
	services.Install(s.p)
	s.p.Keys = &apikeys.Service{Store: st}
	s.p.CIAuth = &ciauth.Service{Trusts: st, Keys: s.p.Keys, Uses: st}
	api := s.platform.URL
	idp := newCIIssuer(t)
	aud := "https://sandbox.example.com"
	// Registration is a resource of the tenant: PUT appends a revision, bob sees none of it.
	code, it := putDoc(t, api, "alice-tok", "citrusts", "github-config", `{"spec":{"issuer":"`+idp.srv.URL+`","audience":"`+aud+`","claims":{"repository":"acme/config","ref":"refs/heads/main"},"ttl":"10m"}}`)
	if code != 201 || it.Tenant != "alice" || it.Kind != "CITrust" {
		t.Fatalf("register: %d %+v", code, it)
	}
	if resp, body := call(t, "GET", api+"/v1/citrusts", "bob-tok", nil, nil); resp.StatusCode != 200 || strings.Contains(string(body), "github-config") {
		t.Fatalf("bob sees alice's trust: %d %s", resp.StatusCode, body)
	}
	if code, _ := putDoc(t, api, "bob-tok", "citrusts", "stolen", `{"spec":{"issuer":"`+idp.srv.URL+`","audience":"`+aud+`","claims":{"repository":"acme/config"}}}`); code != 201 {
		t.Fatalf("bob registering a trust of his own: %d", code) // his own scope; it will make the job ambiguous below
	}
	// Two tenants trusting the same job: the job gets nothing until bob's trust is gone.
	exchange := func(raw string) (int, ciGrant, []byte) {
		resp, body := call(t, "POST", api+"/v1/auth/ci", "", map[string]string{"token": raw}, nil)
		var g ciGrant
		_ = json.Unmarshal(body, &g)
		return resp.StatusCode, g, body
	}
	if code, _, body := exchange(idp.token(t, aud, "acme/config", "refs/heads/main")); code != 401 {
		t.Fatalf("ambiguous: %d %s", code, body)
	}
	if resp, _ := call(t, "DELETE", api+"/v1/citrusts/stolen", "bob-tok", nil, nil); resp.StatusCode != 204 {
		t.Fatalf("delete bob's trust: %d", resp.StatusCode)
	}
	raw := idp.token(t, aud, "acme/config", "refs/heads/main")
	code, g, body := exchange(raw)
	if code != 201 || !strings.HasPrefix(g.Secret, "sbk_") || g.Tenant != "alice" || g.Trust != "github-config" || !strings.Contains(g.Subject, "repo:acme/config") {
		t.Fatalf("exchange: %d %s", code, body)
	}
	if g.ExpiresAt == nil || time.Until(*g.ExpiresAt) > 10*time.Minute {
		t.Fatalf("expiry: %v", g.ExpiresAt)
	}
	// The key is alice's principal, with the trust's expiry on it.
	resp, body := call(t, "GET", api+"/v1/whoami", g.Secret, nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"tenant":"alice"`) || !strings.Contains(string(body), `"subject":"key:`+g.ID) || !strings.Contains(string(body), `"expires"`) {
		t.Fatalf("whoami with the CI key: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "GET", api+"/v1/tenants/alice/keys", "alice-tok", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), `"trust":"github-config"`) || strings.Contains(string(body), g.Secret) {
		t.Fatalf("keys list: %d %s", resp.StatusCode, body)
	}
	// Once.
	if code, _, _ := exchange(raw); code != 401 {
		t.Fatalf("replay: %d", code)
	}
	// Another repository, another ref, another audience: refused alike.
	for name, raw := range map[string]string{
		"other_repository": idp.token(t, aud, "acme/other", "refs/heads/main"),
		"other_ref":        idp.token(t, aud, "acme/config", "refs/heads/feature"),
		"other_audience":   idp.token(t, "https://elsewhere.example", "acme/config", "refs/heads/main"),
	} {
		if code, _, body := exchange(raw); code != 401 {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	// Bad requests and the switch.
	if resp, _ := call(t, "POST", api+"/v1/auth/ci", "", map[string]string{"tokn": "x"}, nil); resp.StatusCode != 400 {
		t.Fatalf("unknown field: %d", resp.StatusCode)
	}
	s.p.CIAuth = nil
	if code, _, _ := exchange(idp.token(t, aud, "acme/config", "refs/heads/main")); code != 503 {
		t.Fatalf("disabled: %d", code)
	}
	// A trust is a document like any other: plan and apply take it in a bundle, and the shared
	// scope refuses it.
	s.p.CIAuth = &ciauth.Service{Trusts: st, Keys: s.p.Keys, Uses: st}
	bundle := map[string]any{"documents": []map[string]any{{"kind": "CITrust", "name": "prs", "spec": map[string]any{"issuer": idp.srv.URL, "audience": aud, "claims": map[string]string{"repository": "acme/config", "ref": "refs/pull/*/merge"}}}}}
	if resp, body := call(t, "POST", api+"/v1/plan", "alice-tok", bundle, nil); resp.StatusCode != 200 || !strings.Contains(string(body), `"action":"create"`) {
		t.Fatalf("plan: %d %s", resp.StatusCode, body)
	}
	if code, body := putDoc(t, api, "t0k", "citrusts", "shared", `{"spec":{"issuer":"`+idp.srv.URL+`","audience":"`+aud+`","claims":{"repository":"acme/config"}}}`); code != 422 {
		t.Fatalf("a shared trust: %d %+v", code, body)
	}
}
