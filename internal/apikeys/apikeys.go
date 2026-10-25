// Package apikeys issues, rotates and revokes tenant API keys through the platform API, so a
// new tenant, a new CI pipeline or a leaked credential never means a change to the server's
// configuration or to a cluster manifest. A key is `sbk_<id>_<secret>`; the store keeps the
// id and a hash, the secret is shown once. Every request looks the key up, so a revocation
// is effective on every replica at once.
package apikeys

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Prefix opens every key the service issues.
const Prefix = "sbk_"

// Errors.
var (
	ErrNotFound  = store.ErrNotFound
	ErrInvalid   = errors.New("invalid")
	ErrBadKey    = errors.New("bad key")
	ErrForbidden = errors.New("forbidden")
)

// MaxNameLen bounds a key's name.
const MaxNameLen = 64

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// MaxTTL caps a key's lifetime when the caller names one longer; 0 = no cap.
type Service struct {
	Store  store.APIKeys
	MaxTTL time.Duration
	Now    func() time.Time
	// TouchEvery bounds how often a use is recorded (last_used_at): one write per key per
	// interval, not one per request. 0 = a minute.
	TouchEvery time.Duration
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Create issues a key for tenant. The returned secret is the only time it is visible.
func (s *Service) Create(ctx context.Context, tenant, name string, ttl time.Duration, by string) (*model.APIKey, string, error) {
	return s.create(ctx, tenant, name, ttl, by, "")
}

// CreateTrusted issues a key on behalf of a CITrust (internal/ciauth): the same key, marked
// with the trust that issued it, so it is listed as such and pruned once long expired.
func (s *Service) CreateTrusted(ctx context.Context, tenant, name string, ttl time.Duration, by, trust string) (*model.APIKey, string, error) {
	if trust == "" {
		return nil, "", fmt.Errorf("%w: a trusted key names its trust", ErrInvalid)
	}
	return s.create(ctx, tenant, name, ttl, by, trust)
}

func (s *Service) create(ctx context.Context, tenant, name string, ttl time.Duration, by, trust string) (*model.APIKey, string, error) {
	if tenant == "" {
		return nil, "", fmt.Errorf("%w: a key belongs to a tenant", ErrInvalid)
	}
	if !nameRe.MatchString(name) {
		return nil, "", fmt.Errorf("%w: name must be 1-64 characters: letters, digits, space, '.', '_' or '-'", ErrInvalid)
	}
	if ttl < 0 {
		return nil, "", fmt.Errorf("%w: ttl must not be negative", ErrInvalid)
	}
	if s.MaxTTL > 0 && (ttl == 0 || ttl > s.MaxTTL) {
		ttl = s.MaxTTL
	}
	id, secret, hash, err := mint()
	if err != nil {
		return nil, "", err
	}
	k := &model.APIKey{ID: id, Tenant: tenant, Name: name, Hash: hash, CreatedBy: by, CreatedAt: s.now(), Trust: trust}
	if ttl > 0 {
		exp := k.CreatedAt.Add(ttl)
		k.ExpiresAt = &exp
	}
	if err := s.Store.CreateAPIKey(ctx, k); err != nil {
		return nil, "", err
	}
	return k, secret, nil
}

// Rotate issues a replacement for key id (same tenant and name, a fresh expiry of ttl; 0
// keeps the old key's remaining lifetime) and retires the old one: at once when grace is 0,
// else after grace, so a pipeline can switch over without a gap.
func (s *Service) Rotate(ctx context.Context, id string, ttl, grace time.Duration, by string) (*model.APIKey, string, error) {
	old, err := s.Store.GetAPIKey(ctx, id)
	if err != nil {
		return nil, "", err
	}
	now := s.now()
	if !old.Active(now) {
		return nil, "", fmt.Errorf("%w: key %s is revoked or expired; create a new one", ErrInvalid, id)
	}
	if grace < 0 || ttl < 0 {
		return nil, "", fmt.Errorf("%w: ttl and grace must not be negative", ErrInvalid)
	}
	if ttl == 0 && old.ExpiresAt != nil {
		ttl = old.ExpiresAt.Sub(now)
	}
	next, secret, err := s.Create(ctx, old.Tenant, old.Name, ttl, by)
	if err != nil {
		return nil, "", err
	}
	// One atomic store operation; a revocation that landed meanwhile stands.
	if err := s.Store.RetireAPIKey(ctx, old.ID, next.ID, now, grace); err != nil {
		return nil, "", err
	}
	return next, secret, nil
}

// Revoke ends a key now. Revoking an already revoked key is fine (the earlier time stands).
func (s *Service) Revoke(ctx context.Context, id string) (*model.APIKey, error) {
	if err := s.Store.RevokeAPIKey(ctx, id, s.now()); err != nil {
		return nil, err
	}
	return s.Store.GetAPIKey(ctx, id)
}

// Get returns one key (never its hash: the model hides it).
func (s *Service) Get(ctx context.Context, id string) (*model.APIKey, error) {
	return s.Store.GetAPIKey(ctx, id)
}

// List returns a tenant's keys, newest first.
func (s *Service) List(ctx context.Context, tenant string) ([]*model.APIKey, error) {
	return s.Store.ListAPIKeys(ctx, tenant)
}

// IsKey reports whether a bearer token has the shape of a key this service issues.
func IsKey(token string) bool { return strings.HasPrefix(token, Prefix) }

// Authenticate resolves a bearer token to its active key, or ErrBadKey (the reason is not
// distinguished: an unknown id, a wrong secret, a revoked or an expired key all read the same
// to the caller). The hash comparison is constant-time.
func (s *Service) Authenticate(ctx context.Context, token string) (*model.APIKey, error) {
	id, ok := idOf(token)
	if !ok {
		return nil, ErrBadKey
	}
	k, err := s.Store.GetAPIKey(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrBadKey
	}
	if err != nil {
		return nil, err
	}
	sum := hashOf(token)
	if subtle.ConstantTimeCompare([]byte(sum), []byte(k.Hash)) != 1 {
		return nil, ErrBadKey
	}
	now := s.now()
	if !k.Active(now) {
		return nil, ErrBadKey
	}
	every := s.TouchEvery
	if every == 0 {
		every = time.Minute
	}
	if k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) >= every {
		// Only the use is recorded, never the record we read: a revocation that landed between
		// our read and this write is not undone. A lost touch is not an authentication failure.
		if err := s.Store.TouchAPIKey(ctx, k.ID, now); err == nil {
			k.LastUsedAt = &now
		}
	}
	return k, nil
}

// mint makes an id, a secret that embeds it, and the secret's hash.
func mint() (id, secret, hash string, err error) {
	var b [28]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", "", err
	}
	id = "key_" + hex.EncodeToString(b[:6])
	secret = Prefix + strings.TrimPrefix(id, "key_") + "_" + hex.EncodeToString(b[6:])
	return id, secret, hashOf(secret), nil
}

func hashOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// idOf extracts the key id from a secret: sbk_<12 hex>_<44 hex>.
func idOf(token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, Prefix)
	if !ok {
		return "", false
	}
	idPart, _, ok := strings.Cut(rest, "_")
	if !ok || len(idPart) != 12 {
		return "", false
	}
	return "key_" + idPart, true
}
