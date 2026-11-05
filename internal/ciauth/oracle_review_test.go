package ciauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/citrust"
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
