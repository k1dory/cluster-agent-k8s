package httpapi

import (
	"net/http"
	"testing"
)

func TestReviewOIDCWithoutStaticTokens(t *testing.T) {
	s := newStack(t)
	s.p.Token, s.p.Tenants, s.p.Verifier = "", nil, fakeVerifier{}
	resp, body := call(t, http.MethodGet, s.platform.URL+"/v1/whoami", "jwt.acme.300", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("OIDC-only configuration returned %d: %s", resp.StatusCode, body)
	}
}
