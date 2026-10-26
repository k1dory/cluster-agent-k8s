package ciauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/citrust"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// A separate test schema keeps these exchange contracts independent of the
// store package's contracts when go test runs the packages concurrently.
func reviewCIBackend(t *testing.T, postgres bool) store.Store {
	t.Helper()
	if !postgres {
		return store.NewMemory()
	}
	dsn := os.Getenv("SANDBOX_TEST_POSTGRES_URL")
	if dsn == "" {
		if os.Getenv("SANDBOX_TEST_REQUIRE_EXTERNAL") != "" {
			t.Fatal("SANDBOX_TEST_POSTGRES_URL is required")
		}
		t.Skip("set SANDBOX_TEST_POSTGRES_URL for the PostgreSQL exchange contract")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	schema := "ci_review_" + hex.EncodeToString(nonce[:])
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("drop review schema: %v", err)
		}
		admin.Close(cleanup)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	st, err := store.OpenPostgres(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func reviewCIService(t *testing.T, st store.Store) (*Service, *issuer) {
	t.Helper()
	idp := newIssuer(t)
	s := &Service{Trusts: st, Keys: &apikeys.Service{Store: st}, Uses: st, Client: &http.Client{Timeout: 3 * time.Second}}
	putTrust(t, citrust.New(st, 0), "acme", "config", citrust.Spec{Issuer: idp.srv.URL, Audience: aud, Claims: map[string]string{"repository": "acme/config"}})
	return s, idp
}

// Verification and storage must agree about the entire accepted lifetime of a
// token. Either refuse a token past exp, or retain its use through clock leeway.
func TestReviewCIExpiryWindowStillAllowsOnlyOneExchange(t *testing.T) {
	for _, backend := range []string{"memory", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			st := reviewCIBackend(t, backend == "postgres")
			s, idp := reviewCIService(t, st)
			raw := idp.token(t, aud, map[string]any{"iat": time.Now().Add(-2 * time.Minute).Unix()}, -10*time.Second)
			_, err := s.Exchange(t.Context(), raw)
			if errors.Is(err, ErrRefused) {
				if keys, err := st.ListAPIKeys(t.Context(), "acme"); err != nil || len(keys) != 0 {
					t.Fatalf("refused expired token must issue nothing: keys=%d err=%v", len(keys), err)
				}
				return // Strict expiry is also a valid way to preserve the invariant.
			}
			if err != nil {
				t.Fatalf("first exchange: %v", err)
			}
			if _, err := s.Exchange(t.Context(), raw); !errors.Is(err, ErrRefused) {
				t.Errorf("an accepted token must remain single-use through the expiry allowance: %v", err)
			}
			if keys, err := st.ListAPIKeys(t.Context(), "acme"); err != nil || len(keys) != 1 {
				t.Errorf("one job token must leave one issued key: keys=%d err=%v", len(keys), err)
			}
		})
	}
}

type reviewCILostUseAck struct {
	store.TokenUses
	once bool
}

var reviewCIUseAckError = errors.New("fixture: token-use write committed, confirmation unavailable")

func (s *reviewCILostUseAck) IssueForToken(ctx context.Context, id string, expiry time.Time, key *model.APIKey) error {
	if err := s.TokenUses.IssueForToken(ctx, id, expiry, key); err != nil {
		return err
	}
	if !s.once {
		s.once = true
		return reviewCIUseAckError
	}
	return nil
}

// Losing a store acknowledgement must not delete the only key while leaving
// the job token consumed. Read back the committed exchange, or leave it retryable.
func TestReviewCILostUseAcknowledgementDoesNotStrandTheJob(t *testing.T) {
	for _, backend := range []string{"memory", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			st := reviewCIBackend(t, backend == "postgres")
			s, idp := reviewCIService(t, st)
			s.Uses = &reviewCILostUseAck{TokenUses: st}
			raw := idp.token(t, aud, nil, 5*time.Minute)
			g, err := s.Exchange(t.Context(), raw)
			if err != nil {
				if !errors.Is(err, reviewCIUseAckError) {
					t.Fatalf("unexpected initial result: %v", err)
				}
				g, err = s.Exchange(t.Context(), raw)
			}
			if err != nil || g == nil {
				keys, readErr := st.ListAPIKeys(t.Context(), "acme")
				t.Fatalf("neither the original exchange nor its retry returned a key: err=%v keys=%d readErr=%v", err, len(keys), readErr)
			}
			if _, err := s.Keys.Authenticate(t.Context(), g.Secret); err != nil {
				t.Fatalf("recovered key must authenticate: %v", err)
			}
			if _, err := s.Exchange(t.Context(), raw); !errors.Is(err, ErrRefused) {
				t.Fatalf("after recovery the token must remain single-use: %v", err)
			}
			if keys, err := st.ListAPIKeys(t.Context(), "acme"); err != nil || len(keys) != 1 {
				t.Fatalf("exchange recovery must leave one key: keys=%d err=%v", len(keys), err)
			}
		})
	}
}

// A provider may replace its signing key without changing the kid, or issue
// tokens without a kid. Once refresh is allowed, the new published key must be
// considered on signature mismatch; a fresh replica must not be the only remedy.
func TestReviewCISigningKeyRotationRefreshesTheCache(t *testing.T) {
	for _, kid := range []string{"stable", ""} {
		name := "same_kid"
		if kid == "" {
			name = "no_kid"
		}
		t.Run(name, func(t *testing.T) {
			st := store.NewMemory()
			s, idp := reviewCIService(t, st)
			idp.kid = kid
			now := time.Now()
			s.Now = func() time.Time { return now }
			var mu sync.Mutex
			published := &idp.key.PublicKey
			fetches := 0
			s.Client = &http.Client{Timeout: 3 * time.Second, Transport: reviewCITransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != idp.srv.URL+"/keys" {
					return http.DefaultTransport.RoundTrip(r)
				}
				mu.Lock()
				fetches++
				body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: published, KeyID: "stable", Algorithm: "RS256", Use: "sig"}}})
				mu.Unlock()
				if err != nil {
					return nil, err
				}
				return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
			})}
			if _, err := s.Exchange(t.Context(), idp.token(t, aud, nil, 10*time.Minute)); err != nil {
				t.Fatalf("exchange before rotation: %v", err)
			}
			replacement, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			idp.mu.Lock()
			idp.key = replacement
			idp.mu.Unlock()
			mu.Lock()
			published = &replacement.PublicKey
			mu.Unlock()
			now = now.Add(2 * time.Minute) // Past the configured refresh throttle; no sleeping.
			raw := idp.token(t, aud, nil, 10*time.Minute)
			if _, err := s.Exchange(t.Context(), raw); err != nil {
				mu.Lock()
				n := fetches
				mu.Unlock()
				t.Errorf("published replacement key was not accepted after rotation: %v (JWKS fetches=%d)", err, n)
				fresh := &Service{Trusts: st, Keys: s.Keys, Uses: st, Client: s.Client, Now: s.Now}
				if _, err := fresh.Exchange(t.Context(), raw); err != nil {
					t.Fatalf("fixture token must verify on a fresh replica: %v", err)
				}
			}
		})
	}
}
