package ciauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// issuerKeys is one issuer's discovery document and signing keys: fetched on first use,
// kept, and fetched again when a token names a key id the set does not hold (at most once a
// minute, so a flood of tokens with made-up key ids cannot hammer the issuer). Each issuer
// has its own lock: a slow or unreachable issuer delays the tokens it issued and no other,
// and a cached issuer answers without waiting for anyone's fetch.
type issuerKeys struct {
	mu      sync.Mutex
	jwksURL string
	keys    []jose.JSONWebKey
	fetched time.Time
}

const (
	// fetchTimeout bounds one request to an issuer when the service has no client of its own.
	fetchTimeout = 10 * time.Second
	// refreshInterval is the least time between two fetches of a key set for an unknown key id.
	refreshInterval = time.Minute
	// maxDocBytes bounds a discovery document or a key set.
	maxDocBytes = 1 << 20
)

var defaultClient = &http.Client{Timeout: fetchTimeout}

func (s *Service) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return defaultClient
}

// keysFor returns the issuer's keys a signature with key id kid may be checked against (every
// signing key when the token names none). An error is the issuer's: discovery or keys could
// not be fetched, or the discovery document is not the issuer's.
func (s *Service) keysFor(ctx context.Context, issuer, kid string) ([]jose.JSONWebKey, error) {
	s.mu.Lock()
	e := s.issuers[issuer]
	if e == nil {
		if s.issuers == nil {
			s.issuers = map[string]*issuerKeys{}
		}
		e = &issuerKeys{}
		s.issuers[issuer] = e
	}
	s.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.jwksURL == "" {
		u, err := s.discover(ctx, issuer)
		if err != nil {
			return nil, err
		}
		e.jwksURL = u
	}
	if found := pick(e.keys, kid); len(found) > 0 {
		return found, nil
	}
	if e.fetched.IsZero() || s.now().Sub(e.fetched) >= refreshInterval {
		keys, err := s.fetchKeys(ctx, e.jwksURL)
		if err != nil {
			return nil, err
		}
		e.keys, e.fetched = keys, s.now()
	}
	return pick(e.keys, kid), nil
}

// pick selects the signing keys with key id kid, or every signing key when kid is empty.
func pick(keys []jose.JSONWebKey, kid string) []jose.JSONWebKey {
	var out []jose.JSONWebKey
	for _, k := range keys {
		if (k.Use == "" || k.Use == "sig") && (kid == "" || k.KeyID == kid) && k.Valid() && k.IsPublic() {
			out = append(out, k)
		}
	}
	return out
}

// discover reads the issuer's OpenID configuration and returns its jwks_uri. The document
// must name the issuer it was fetched from: a token's iss decides whose keys are asked, and
// the keys must be that issuer's.
func (s *Service) discover(ctx context.Context, issuer string) (string, error) {
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURL string `json:"jwks_uri"`
	}
	if err := s.getJSON(ctx, issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	if doc.Issuer != issuer {
		return "", fmt.Errorf("discovery of %s names issuer %q", issuer, doc.Issuer)
	}
	if doc.JWKSURL == "" {
		return "", fmt.Errorf("discovery of %s has no jwks_uri", issuer)
	}
	return doc.JWKSURL, nil
}

func (s *Service) fetchKeys(ctx context.Context, url string) ([]jose.JSONWebKey, error) {
	var set jose.JSONWebKeySet
	if err := s.getJSON(ctx, url, &set); err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	return set.Keys, nil
}

func (s *Service) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocBytes+1))
	if err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	if len(body) > maxDocBytes {
		return fmt.Errorf("%s: document over %d bytes", url, maxDocBytes)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%s: %w", url, errors.Unwrap(err))
	}
	return nil
}
