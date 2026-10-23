// Package secrets resolves `secret:NAME` references in inject headers per tenant.
//
// FileProvider layout (a mounted Kubernetes Secret or a directory synced from Vault):
//
//	<dir>/tenants/<tenant>/<name>   tenant-specific value (own LLM key, own Git token)
//	<dir>/shared/<name>             fallback shared by all tenants
//
// The agent never sees these values: they exist only in the gateway's response to Caddy.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrNotFound means the reference could not be resolved for this tenant.
var ErrNotFound = errors.New("secret not found")

// Provider resolves a named secret for a tenant.
type Provider interface {
	Get(ctx context.Context, tenant, name string) (string, error)
}

var refRe = regexp.MustCompile(`secret:([A-Za-z0-9_./-]+)`)

// Expand replaces every `secret:NAME` in value. Plain values pass through unchanged.
func Expand(ctx context.Context, p Provider, tenant, value string) (string, error) {
	var firstErr error
	out := refRe.ReplaceAllStringFunc(value, func(m string) string {
		name := strings.TrimPrefix(m, "secret:")
		v, err := p.Get(ctx, tenant, name)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s for tenant %q: %w", m, tenant, err)
		}
		return v
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}

// FileProvider reads secrets from a directory tree.
type FileProvider struct{ Dir string }

func (f FileProvider) Get(_ context.Context, tenant, name string) (string, error) {
	if strings.Contains(name, "..") {
		return "", ErrNotFound
	}
	candidates := []string{}
	if tenant != "" {
		candidates = append(candidates, filepath.Join(f.Dir, "tenants", tenant, name))
	}
	candidates = append(candidates, filepath.Join(f.Dir, "shared", name))
	for _, c := range candidates {
		b, err := os.ReadFile(c)
		if err == nil {
			return strings.TrimRight(string(b), "\r\n"), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
	}
	return "", ErrNotFound
}

// Static is an in-memory provider for tests: key "tenant/name" or "shared/name".
type Static map[string]string

func (s Static) Get(_ context.Context, tenant, name string) (string, error) {
	if v, ok := s[tenant+"/"+name]; ok {
		return v, nil
	}
	if v, ok := s["shared/"+name]; ok {
		return v, nil
	}
	return "", ErrNotFound
}
