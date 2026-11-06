package citrust

import "testing"

// sandboxd accepted http://127.0.0.1:<port> as a tenant's issuer "for tests", so an
// unauthenticated POST /v1/auth/ci made the platform fetch from its own loopback services.
func TestReviewLoopbackHTTPIssuerIsRefusedOutsideTests(t *testing.T) {
	defer func(old bool) { allowLoopbackHTTP = old }(allowLoopbackHTTP)
	allowLoopbackHTTP = false
	for _, raw := range []string{"http://127.0.0.1:8443", "http://localhost", "http://[::1]:9000", "http://issuer.example.com"} {
		if err := CheckIssuer(raw); err == nil {
			t.Errorf("%s must be refused in a production binary", raw)
		}
	}
	if err := CheckIssuer("https://token.actions.githubusercontent.com"); err != nil {
		t.Fatal(err)
	}
	allowLoopbackHTTP = true
	if err := CheckIssuer("http://127.0.0.1:8443"); err != nil {
		t.Fatalf("test binaries keep loopback http: %v", err)
	}
	if err := CheckIssuer("http://issuer.example.com"); err == nil {
		t.Fatal("http to a non-loopback host is never accepted")
	}
}
