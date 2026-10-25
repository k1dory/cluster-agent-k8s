package ciauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/citrust"
	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// issuer is a CI provider's token service: discovery, a JWKS, and tokens it signs.
type issuer struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	n        int
	kid      string        // the key id tokens name (k1: the published key)
	keysDown atomic.Bool   // the key set answers 503
	hold     chan struct{} // when set, discovery blocks until it is closed, reporting on blocked
	blocked  chan struct{}
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &issuer{key: key, kid: "k1", blocked: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if h := p.hold; h != nil {
			p.blocked <- struct{}{}
			<-h
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": p.srv.URL, "jwks_uri": p.srv.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		if p.keysDown.Load() {
			http.Error(w, "keys are being rotated", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// token signs a job token: GitHub's shape (repository, ref, sha, job_workflow_ref) with the
// given audience, a fresh jti each time.
func (p *issuer) token(t *testing.T, aud string, claims map[string]any, ttl time.Duration) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, (&jose.SignerOptions{}).WithHeader("kid", p.kid))
	if err != nil {
		t.Fatal(err)
	}
	p.n++
	std := jwt.Claims{Issuer: p.srv.URL, Subject: "repo:acme/config:ref:refs/heads/main", Audience: jwt.Audience{aud},
		Expiry: jwt.NewNumericDate(time.Now().Add(ttl)), IssuedAt: jwt.NewNumericDate(time.Now()), ID: "jti-" + time.Now().Format("150405.000000") + "-" + string(rune('a'+p.n%26))}
	all := map[string]any{"repository": "acme/config", "ref": "refs/heads/main", "sha": "0123456789012345678901234567890123456789", "job_workflow_ref": "acme/config/.github/workflows/sandbox-config.yml@refs/heads/main"}
	for k, v := range claims {
		all[k] = v
	}
	raw, err := jwt.Signed(signer).Claims(std).Claims(all).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func putTrust(t *testing.T, svc *citrust.Service, tenant, name string, sp citrust.Spec) {
	t.Helper()
	spec, _ := json.Marshal(sp)
	if _, err := svc.Put(context.Background(), tenant, &res.Document{Kind: model.KindCITrust, Name: name, Spec: spec}, false, "tester"); err != nil {
		t.Fatalf("trust %s/%s: %v", tenant, name, err)
	}
}

func newService(t *testing.T) (*Service, *store.Memory, *citrust.Service) {
	t.Helper()
	st := store.NewMemory()
	trusts := citrust.New(st, 0)
	s := &Service{Trusts: st, Keys: &apikeys.Service{Store: st}, Uses: st, Client: http.DefaultClient}
	return s, st, trusts
}

const aud = "https://sandbox.example.com"

// A job of the trusted repository gets a key of the trust's tenant and lifetime, usable at
// once; the token works once; the key names the trust and the token's subject.
func TestExchangeIssuesAShortLivedTenantKeyOnce(t *testing.T) {
	ctx := context.Background()
	idp := newIssuer(t)
	s, st, trusts := newService(t)
	putTrust(t, trusts, "acme", "github-config", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config", "ref": "refs/heads/main"}, TTL: "10m"})
	raw := idp.token(t, aud, nil, 5*time.Minute)
	g, err := s.Exchange(ctx, raw)
	if err != nil || g.Tenant != "acme" || g.Trust != "github-config" || !strings.HasPrefix(g.Secret, apikeys.Prefix) || g.Key.Trust != "github-config" || g.Key.Name != "ci.github-config" || !strings.HasPrefix(g.Key.CreatedBy, "ci:repo:acme/config") {
		t.Fatalf("exchange: %v %+v", err, g)
	}
	if g.Key.ExpiresAt == nil || time.Until(*g.Key.ExpiresAt) > 10*time.Minute || time.Until(*g.Key.ExpiresAt) < 9*time.Minute {
		t.Fatalf("the key must live the trust's ttl: %v", g.Key.ExpiresAt)
	}
	if k, err := s.Keys.Authenticate(ctx, g.Secret); err != nil || k.Tenant != "acme" {
		t.Fatalf("the issued key must authenticate as the tenant: %v %+v", err, k)
	}
	if _, err := s.Exchange(ctx, raw); !errors.Is(err, ErrRefused) {
		t.Fatalf("the same token again must be refused: %v", err)
	}
	if list, _ := st.ListAPIKeys(ctx, "acme"); len(list) != 1 || list[0].Trust != "github-config" {
		t.Fatalf("keys: %+v", list)
	}
}

// What is refused: another audience, a repository or ref the trust does not name, an expired
// token, an issuer with no trust, a token without jti, garbage; a trust that matches from
// two tenants (an ambiguous identity); a deleted trust.
func TestExchangeRefusesWhatNoTrustAccepts(t *testing.T) {
	ctx := context.Background()
	idp := newIssuer(t)
	other := newIssuer(t)
	s, st, trusts := newService(t)
	putTrust(t, trusts, "acme", "github-config", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config", "ref": "refs/heads/main"}})
	for name, raw := range map[string]string{
		"other_audience":     idp.token(t, "https://elsewhere.example", nil, time.Minute),
		"other_repository":   idp.token(t, aud, map[string]any{"repository": "acme/other"}, time.Minute),
		"other_ref":          idp.token(t, aud, map[string]any{"ref": "refs/heads/feature"}, time.Minute),
		"expired":            idp.token(t, aud, nil, -time.Minute),
		"unknown_issuer":     other.token(t, aud, nil, time.Minute),
		"repository_missing": idp.token(t, aud, map[string]any{"repository": 7}, time.Minute),
		"garbage":            "not.a.token",
		"empty":              "",
	} {
		if _, err := s.Exchange(ctx, raw); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A token without jti cannot be used once: refused.
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: idp.key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	noJTI, _ := jwt.Signed(signer).Claims(jwt.Claims{Issuer: idp.srv.URL, Subject: "x", Audience: jwt.Audience{aud}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute))}).Claims(map[string]any{"repository": "acme/config", "ref": "refs/heads/main"}).Serialize()
	if _, err := s.Exchange(ctx, noJTI); !errors.Is(err, ErrRefused) {
		t.Fatalf("no jti: %v", err)
	}
	// Two tenants trusting the same job: nobody gets it.
	putTrust(t, trusts, "beta", "same-repo", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	if _, err := s.Exchange(ctx, idp.token(t, aud, nil, time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("ambiguous: %v", err)
	}
	if err := trusts.Delete(ctx, "beta", "same-repo"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(ctx, idp.token(t, aud, nil, time.Minute)); err != nil {
		t.Fatalf("after the other tenant's trust is gone: %v", err)
	}
	if err := trusts.Delete(ctx, "acme", "github-config"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(ctx, idp.token(t, aud, nil, time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("a deleted trust must not match: %v", err)
	}
	if n, _ := st.ListAPIKeys(ctx, "acme"); len(n) != 1 {
		t.Fatalf("keys issued: %d", len(n))
	}
}

// Patterns and list claims: a trust for every pull request of a repository (`refs/pull/*/merge`)
// and for a GitLab project path; the ttl is capped by the server; long-expired CI keys are
// pruned on the next exchange.
func TestExchangePatternsCapAndPrune(t *testing.T) {
	ctx := context.Background()
	idp := newIssuer(t)
	s, st, trusts := newService(t)
	trusts.MaxTTL, s.MaxTTL = 20*time.Minute, 20*time.Minute
	putTrust(t, trusts, "acme", "prs", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config", "ref": "refs/pull/*/merge"}, TTL: "20m"})
	if _, err := s.Exchange(ctx, idp.token(t, aud, map[string]any{"ref": "refs/pull/12/merge"}, time.Minute)); err != nil {
		t.Fatalf("a pull request ref: %v", err)
	}
	if _, err := s.Exchange(ctx, idp.token(t, aud, map[string]any{"ref": "refs/heads/main"}, time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("main is not a pull request: %v", err)
	}
	// A list claim (GitLab's or a custom one) matches on any entry.
	putTrust(t, trusts, "acme", "groups", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config", "groups": "platform-*"}})
	if _, err := s.Exchange(ctx, idp.token(t, aud, map[string]any{"groups": []string{"devs", "platform-ops"}}, time.Minute)); err != nil {
		t.Fatalf("a list claim: %v", err)
	}
	// A trust whose ttl exceeds the cap (written before the cap was lowered) issues nothing.
	spec, _ := json.Marshal(citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}, TTL: "2h"})
	if err := st.PutItem(ctx, &model.CatalogItem{Kind: model.KindCITrust, Tenant: "acme", Name: "too-long", Spec: spec}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(ctx, idp.token(t, aud, nil, time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("an over-long ttl must refuse, not issue: %v", err)
	}
	// Prune: a CI key that expired more than a day ago is gone after an exchange; a person's
	// expired key stays (its history is theirs).
	old := time.Now().Add(-48 * time.Hour)
	exp := old.Add(time.Minute)
	for _, k := range []*model.APIKey{
		{ID: "key_oldci", Tenant: "acme", Name: "ci:x", Hash: "h", CreatedAt: old, ExpiresAt: &exp, Trust: "x"},
		{ID: "key_oldhuman", Tenant: "acme", Name: "laptop", Hash: "h", CreatedAt: old, ExpiresAt: &exp},
	} {
		if err := st.CreateAPIKey(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.DeleteItem(ctx, model.KindCITrust, "acme", "too-long"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Exchange(ctx, idp.token(t, aud, map[string]any{"groups": []string{"platform-ops"}}, time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAPIKey(ctx, "key_oldci"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the old CI key must be pruned: %v", err)
	}
	if _, err := st.GetAPIKey(ctx, "key_oldhuman"); err != nil {
		t.Fatalf("a person's key must stay: %v", err)
	}
}

// An issuer that cannot be reached is a 503-class error, not a refusal, and nothing is issued.
func TestExchangeReportsAnUnreachableIssuer(t *testing.T) {
	ctx := context.Background()
	idp := newIssuer(t)
	s, _, trusts := newService(t)
	putTrust(t, trusts, "acme", "t", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	raw := idp.token(t, aud, nil, time.Minute)
	idp.srv.Close()
	if _, err := s.Exchange(ctx, raw); !errors.Is(err, ErrIssuer) {
		t.Fatalf("unreachable issuer: %v", err)
	}
}

// The issuer's keys unavailable is the issuer's failure, not the token's: 503, never 401.
// Keys fetched before are kept, so a rotation outage leaves tokens under known keys working;
// a token under a key the set does not hold asks the issuer again and reports its outage.
func TestExchangeReportsKeysItCannotFetch(t *testing.T) {
	ctx := context.Background()
	idp := newIssuer(t)
	s, _, trusts := newService(t)
	putTrust(t, trusts, "acme", "t", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	idp.keysDown.Store(true)
	if _, err := s.Exchange(ctx, idp.token(t, aud, nil, 5*time.Minute)); !errors.Is(err, ErrIssuer) {
		t.Fatalf("keys unavailable at the first exchange: %v", err)
	}
	idp.keysDown.Store(false)
	if _, err := s.Exchange(ctx, idp.token(t, aud, nil, 5*time.Minute)); err != nil {
		t.Fatalf("keys back: %v", err)
	}
	idp.keysDown.Store(true)
	if _, err := s.Exchange(ctx, idp.token(t, aud, nil, 5*time.Minute)); err != nil {
		t.Fatalf("a known key is served from the cache during an outage: %v", err)
	}
	// A key id the set does not hold, a minute later: the issuer is asked and is down.
	idp.kid = "k2"
	s.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := s.Exchange(ctx, idp.token(t, aud, nil, 5*time.Minute)); !errors.Is(err, ErrIssuer) {
		t.Fatalf("an unknown key during an outage: %v", err)
	}
	// Issuer back, the set still has no k2: the token is refused, the issuer is not asked
	// again within the minute.
	idp.keysDown.Store(false)
	if _, err := s.Exchange(ctx, idp.token(t, aud, nil, 5*time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("a key the issuer does not publish: %v", err)
	}
	s.Now = func() time.Time { return time.Now().Add(4 * time.Minute) }
	if _, err := s.Exchange(ctx, idp.token(t, aud, nil, 5*time.Minute)); !errors.Is(err, ErrRefused) {
		t.Fatalf("a key the issuer does not publish, after a refetch: %v", err)
	}
}

type failingKeys struct {
	store.APIKeys
	fail atomic.Bool
}

func (f *failingKeys) CreateAPIKey(ctx context.Context, k *model.APIKey) error {
	if f.fail.Load() {
		return errors.New("api_keys: disk full")
	}
	return f.APIKeys.CreateAPIKey(ctx, k)
}

// A key the store could not write leaves the token unused: the job's retry with the same
// token gets its key. A replayed token leaves no key behind.
func TestExchangeLeavesTheTokenUnusedWhenTheKeyIsNotStored(t *testing.T) {
	ctx := context.Background()
	idp := newIssuer(t)
	s, st, trusts := newService(t)
	keys := &failingKeys{APIKeys: st}
	s.Keys = &apikeys.Service{Store: keys}
	putTrust(t, trusts, "acme", "t", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	raw := idp.token(t, aud, nil, 5*time.Minute)
	keys.fail.Store(true)
	if _, err := s.Exchange(ctx, raw); err == nil || errors.Is(err, ErrRefused) || errors.Is(err, ErrIssuer) {
		t.Fatalf("a store failure is reported as such: %v", err)
	}
	keys.fail.Store(false)
	g, err := s.Exchange(ctx, raw)
	if err != nil {
		t.Fatalf("the same token after the store recovered: %v", err)
	}
	if _, err := s.Exchange(ctx, raw); !errors.Is(err, ErrRefused) {
		t.Fatalf("the token a third time: %v", err)
	}
	list, _ := st.ListAPIKeys(ctx, "acme")
	if len(list) != 1 || list[0].ID != g.Key.ID {
		t.Fatalf("a replay must leave no key behind: %+v", list)
	}
}

// A slow issuer holds up the tokens it issued and no other: another issuer, cached or not,
// is served meanwhile.
func TestASlowIssuerDoesNotDelayOthers(t *testing.T) {
	ctx := context.Background()
	fast, slow := newIssuer(t), newIssuer(t)
	s, _, trusts := newService(t)
	putTrust(t, trusts, "acme", "fast", citrust.Spec{Issuer: fast.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	putTrust(t, trusts, "acme", "slow", citrust.Spec{Issuer: slow.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	if _, err := s.Exchange(ctx, fast.token(t, aud, nil, 5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	slow.hold = make(chan struct{})
	slowDone := make(chan error, 1)
	go func() {
		_, err := s.Exchange(ctx, slow.token(t, aud, nil, 5*time.Minute))
		slowDone <- err
	}()
	<-slow.blocked // the slow issuer's discovery is in flight and will not answer
	fastDone := make(chan error, 1)
	go func() {
		_, err := s.Exchange(ctx, fast.token(t, aud, nil, 5*time.Minute))
		fastDone <- err
	}()
	select {
	case err := <-fastDone:
		if err != nil {
			t.Fatalf("the cached issuer: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the cached issuer waited for the slow issuer's fetch")
	}
	close(slow.hold)
	if err := <-slowDone; err != nil {
		t.Fatalf("the slow issuer, once it answered: %v", err)
	}
}

// A trust may carry the longest catalog name; the key it issues is labelled within a key
// name's length and carries the whole trust name in its trust field.
func TestExchangeIssuesForTheLongestTrustName(t *testing.T) {
	ctx := context.Background()
	idp := newIssuer(t)
	s, _, trusts := newService(t)
	name := strings.Repeat("t", 63)
	putTrust(t, trusts, "acme", name, citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	g, err := s.Exchange(ctx, idp.token(t, aud, nil, 5*time.Minute))
	if err != nil || g.Trust != name || g.Key.Trust != name || len(g.Key.Name) != apikeys.MaxNameLen || !strings.HasPrefix(g.Key.Name, "ci."+name[:10]) {
		t.Fatalf("exchange under a long trust name: %v %+v", err, g)
	}
}
