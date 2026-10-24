// Package credentials lets a tenant bring its own secrets through the API: an LLM key, an MCP
// token, a Git credential. A value goes in once (add or replace), is encrypted at rest under
// the server's key, and from then on exists only where the gateway resolves `secret:NAME` for
// that tenant. The API returns metadata (version, fingerprint, who and when), never a value.
// Removing a credential revokes it: the next request that needs it fails at the gateway.
//
// The service is a secrets.Provider: wired in front of the operator's provider, so a tenant's
// own credential wins over what the operator configured under the same name, and a reference
// the operator never heard of still resolves.
package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/store"
)

// Errors.
var (
	ErrInvalid  = errors.New("invalid")
	ErrNotFound = store.ErrNotFound
	ErrDisabled = errors.New("credentials are disabled: the server has no credentials.key")
)

// MaxValue bounds a credential's size.
const MaxValue = 64 << 10

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// Service stores and resolves tenant credentials.
type Service struct {
	Store store.Credentials
	aead  cipher.AEAD
}

// New returns a service encrypting under key (32 bytes: AES-256-GCM).
func New(st store.Credentials, key []byte) (*Service, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("credentials key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Service{Store: st, aead: aead}, nil
}

// ParseKey reads the server key from its configured form: 64 hex characters or the base64 of
// 32 bytes. Empty means the feature is off.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("credentials.key must be 64 hex characters or the base64 of 32 bytes (openssl rand -hex 32)")
}

// Put adds or replaces a credential. The value is never returned or logged.
func (s *Service) Put(ctx context.Context, tenant, name, value, by string) (*model.Credential, bool, error) {
	if !nameRe.MatchString(name) {
		return nil, false, fmt.Errorf("%w: name must be 1-64 characters: letters, digits, '.', '_' or '-'", ErrInvalid)
	}
	if value == "" {
		return nil, false, fmt.Errorf("%w: value is empty", ErrInvalid)
	}
	if len(value) > MaxValue {
		return nil, false, fmt.Errorf("%w: value is larger than %d bytes", ErrInvalid, MaxValue)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, false, err
	}
	// The scope and the name are authenticated with the value: a ciphertext moved to another
	// tenant's row or renamed does not decrypt.
	ciphertext := s.aead.Seal(nonce, nonce, []byte(value), []byte(tenant+"\x00"+name))
	c := &model.Credential{Tenant: tenant, Name: name, Fingerprint: fingerprint(value), CreatedBy: by}
	created, err := s.Store.PutCredential(ctx, c, ciphertext)
	if err != nil {
		return nil, false, err
	}
	return c, created, nil
}

// Get returns a credential's metadata.
func (s *Service) Get(ctx context.Context, tenant, name string) (*model.Credential, error) {
	c, _, err := s.Store.GetCredential(ctx, tenant, name)
	return c, err
}

// List returns a scope's credentials, by name.
func (s *Service) List(ctx context.Context, tenant string) ([]*model.Credential, error) {
	return s.Store.ListCredentials(ctx, tenant)
}

// Delete revokes a credential: the next request that needs it fails to resolve.
func (s *Service) Delete(ctx context.Context, tenant, name string) error {
	return s.Store.DeleteCredential(ctx, tenant, name)
}

// Resolver is the service as a secrets.Provider (the gateway side): a tenant's own
// credential first, then a shared one under the same name.
type Resolver struct{ *Service }

func (r Resolver) Get(ctx context.Context, tenant, name string) (string, error) {
	if tenant != "" {
		if v, err := r.open(ctx, tenant, name); !errors.Is(err, secrets.ErrNotFound) {
			return v, err
		}
	}
	return r.open(ctx, "", name)
}

func (r Resolver) open(ctx context.Context, tenant, name string) (string, error) {
	_, ciphertext, err := r.Store.GetCredential(ctx, tenant, name)
	if errors.Is(err, store.ErrNotFound) {
		return "", secrets.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	n := r.aead.NonceSize()
	if len(ciphertext) < n {
		return "", fmt.Errorf("credential %s/%s: ciphertext too short", tenant, name)
	}
	plain, err := r.aead.Open(nil, ciphertext[:n], ciphertext[n:], []byte(tenant+"\x00"+name))
	if err != nil {
		return "", fmt.Errorf("credential %s/%s: cannot decrypt (wrong credentials.key?)", tenant, name)
	}
	return string(plain), nil
}

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

// Compile-time: the resolver is a provider.
var _ secrets.Provider = Resolver{}
