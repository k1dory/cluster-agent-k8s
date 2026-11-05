package ciauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/citrust"
	"agent-sandbox/internal/model"
)

// The transport error of the issuer fetch went back verbatim on an unauthenticated request:
// a connect, TLS or HTTP-status oracle for any host a tenant names as issuer.
func TestReviewIssuerFailureDoesNotLeakTheTransportError(t *testing.T) {
	idp := newIssuer(t)
	s, _, trusts := newService(t)
	putTrust(t, trusts, "acme", "gh", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}, TTL: "10m"})
	idp.keysDown.Store(true)
	_, err := s.Exchange(context.Background(), idp.token(t, aud, nil, 5*time.Minute))
	if !errors.Is(err, ErrIssuer) {
		t.Fatalf("want ErrIssuer, got %v", err)
	}
	if err.Error() != ErrIssuer.Error() || strings.Contains(err.Error(), "503") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("the client must get a generic error, got %q", err)
	}
}

// A trust stored before loopback http issuers were refused in production still made the
// exchange fetch from its issuer: validation now runs before any network access.
func TestReviewStoredLoopbackHTTPTrustIsNotFetchedInProduction(t *testing.T) {
	idp := newIssuer(t)
	s, st, _ := newService(t)
	spec, _ := json.Marshal(citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}, TTL: "10m"})
	// Written straight to the store, as an older release accepted it.
	if err := st.PutItem(context.Background(), &model.CatalogItem{Kind: model.KindCITrust, Tenant: "acme", Name: "old", Revision: 1, Spec: spec, CreatedAt: time.Now()}, 0); err != nil {
		t.Fatal(err)
	}
	defer citrust.LoopbackHTTPForTest(false)()
	_, err := s.Exchange(context.Background(), idp.token(t, aud, nil, 5*time.Minute))
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("a stored loopback http trust must be refused in production: %v", err)
	}
	if n := idp.fetches.Load(); n != 0 {
		t.Fatalf("the issuer must not be contacted, got %d key fetches", n)
	}
}
