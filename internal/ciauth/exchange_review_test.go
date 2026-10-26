package ciauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/citrust"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// All identities, tokens and HTTP endpoints in these checks are local fixtures.
// No provider credentials or external services are used.
type reviewCITransport func(*http.Request) (*http.Response, error)

func (f reviewCITransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type reviewCIKeyWriteFailure struct {
	store.TokenUses
	fail bool
}

var reviewCIWriteErr = errors.New("fixture: key write unavailable")

func (s *reviewCIKeyWriteFailure) IssueForToken(ctx context.Context, id string, expiry time.Time, k *model.APIKey) error {
	if s.fail {
		s.fail = false
		return reviewCIWriteErr
	}
	return s.TokenUses.IssueForToken(ctx, id, expiry, k)
}

// A failed key write must not consume the only token GitLab gave this job.
// The retry should issue one key; only a successful exchange prevents reuse.
func TestReviewCIExchangeCanRetryAnUncommittedKey(t *testing.T) {
	idp := newIssuer(t)
	s, st, trusts := newService(t)
	putTrust(t, trusts, "acme", "config", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	s.Uses = &reviewCIKeyWriteFailure{TokenUses: st, fail: true}
	raw := idp.token(t, aud, nil, time.Minute)
	if _, err := s.Exchange(t.Context(), raw); !errors.Is(err, reviewCIWriteErr) {
		t.Fatalf("fixture did not reach the failed key write: %v", err)
	}
	if keys, err := st.ListAPIKeys(t.Context(), "acme"); err != nil || len(keys) != 0 {
		t.Fatalf("failed write left keys: count=%d err=%v", len(keys), err)
	}
	if _, err := s.Exchange(t.Context(), raw); err != nil {
		t.Fatalf("retry after a key write that committed nothing must succeed: %v", err)
	}
	if _, err := s.Exchange(t.Context(), raw); !errors.Is(err, ErrRefused) {
		t.Fatalf("reuse after success must be refused: %v", err)
	}
	if keys, err := st.ListAPIKeys(t.Context(), "acme"); err != nil || len(keys) != 1 {
		t.Fatalf("retry must produce exactly one key: count=%d err=%v", len(keys), err)
	}
}

// Resource names accepted by the catalog must remain usable when a CITrust
// becomes the name of an issued key (including the key's extra "ci." prefix).
func TestReviewCITrustAcceptedNamesCanIssueKeys(t *testing.T) {
	idp := newIssuer(t)
	for _, name := range []string{strings.Repeat("n", 61), strings.Repeat("n", 62), strings.Repeat("n", 63)} {
		t.Run(name, func(t *testing.T) {
			s, _, trusts := newService(t)
			putTrust(t, trusts, "acme", name, citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
			g, err := s.Exchange(t.Context(), idp.token(t, aud, nil, time.Minute))
			if err != nil {
				t.Fatalf("accepted CITrust name of %d bytes cannot issue a key: %v", len(name), err)
			}
			if g.Key.Trust != name {
				t.Fatal("the issued key must retain the complete trust name")
			}
		})
	}
}

// An unavailable JWKS is a temporary issuer failure, just like unavailable
// discovery. Restoring the endpoint should allow the same job to retry.
func TestReviewCIJWKSOutageIsAnIssuerFailure(t *testing.T) {
	idp := newIssuer(t)
	s, st, trusts := newService(t)
	putTrust(t, trusts, "acme", "config", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	var mu sync.Mutex
	unavailable := true
	s.Client = &http.Client{Timeout: 3 * time.Second, Transport: reviewCITransport(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		fail := unavailable && r.URL.Path == "/keys"
		mu.Unlock()
		if fail {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("fixture: keys temporarily unavailable")), Request: r}, nil
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	raw := idp.token(t, aud, nil, time.Minute)
	if _, err := s.Exchange(t.Context(), raw); !errors.Is(err, ErrIssuer) {
		t.Errorf("temporary JWKS outage must map to the issuer-unavailable response, not invalid credentials: %v", err)
	}
	if keys, err := st.ListAPIKeys(t.Context(), "acme"); err != nil || len(keys) != 0 {
		t.Fatalf("an unavailable key set must issue nothing: count=%d err=%v", len(keys), err)
	}
	mu.Lock()
	unavailable = false
	mu.Unlock()
	if _, err := s.Exchange(t.Context(), raw); err != nil {
		t.Fatalf("exchange after JWKS recovery: %v", err)
	}
}

// One issuer waiting for discovery must not prevent another tenant's cached,
// healthy issuer from authenticating. The gate is always released for cleanup.
func TestReviewCIDiscoveryDoesNotBlockAnotherIssuer(t *testing.T) {
	slow, healthy := newIssuer(t), newIssuer(t)
	s, _, trusts := newService(t)
	for tenant, idp := range map[string]*issuer{"acme": slow, "beta": healthy} {
		putTrust(t, trusts, tenant, "config", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	openGate := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(openGate)
	s.Client = &http.Client{Timeout: 8 * time.Second, Transport: reviewCITransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == slow.srv.URL+"/.well-known/openid-configuration" {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	if _, err := s.Exchange(t.Context(), healthy.token(t, aud, nil, time.Minute)); err != nil {
		t.Fatalf("warm healthy issuer: %v", err)
	}
	slowToken := slow.token(t, aud, nil, time.Minute)
	slowDone := make(chan error, 1)
	go func() { _, err := s.Exchange(t.Context(), slowToken); slowDone <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("fixture did not reach slow discovery")
	}
	healthyToken := healthy.token(t, aud, nil, time.Minute)
	healthyDone := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	go func() { _, err := s.Exchange(ctx, healthyToken); healthyDone <- err }()
	finished := false
	select {
	case err := <-healthyDone:
		finished = true
		if err != nil {
			t.Errorf("healthy cached issuer must still authenticate: %v", err)
		}
	case <-ctx.Done():
		t.Error("healthy cached issuer was blocked by another issuer's discovery")
	}
	openGate()
	for _, done := range []<-chan error{slowDone, healthyDone} {
		if done == healthyDone && finished {
			continue
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("exchange did not finish after the fixture was released")
		}
	}
}

// Two replicas sharing the store must issue only one key for one job token,
// even when the initial requests arrive together.
func TestReviewCIExchangeOnceAcrossReplicas(t *testing.T) {
	for _, backend := range []string{"memory", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			st := reviewCIBackend(t, backend == "postgres")
			s, idp := reviewCIService(t, st)
			other := &Service{Trusts: st, Keys: &apikeys.Service{Store: st}, Uses: st, Client: http.DefaultClient}
			raw := idp.token(t, aud, nil, time.Minute)
			start, done := make(chan struct{}), make(chan error, 2)
			for _, svc := range []*Service{s, other} {
				go func() { <-start; _, err := svc.Exchange(t.Context(), raw); done <- err }()
			}
			close(start)
			success := 0
			for range 2 {
				if err := <-done; err == nil {
					success++
				} else if !errors.Is(err, ErrRefused) {
					t.Errorf("unexpected exchange failure: %v", err)
				}
			}
			keys, err := st.ListAPIKeys(t.Context(), "acme")
			if err != nil || success != 1 || len(keys) != 1 {
				t.Fatalf("one token must yield one key: success=%d keys=%d err=%v", success, len(keys), err)
			}
		})
	}
}
