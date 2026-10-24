package authz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
)

// The second lookup fails regardless of Go's map iteration order.
type reviewPartialSecrets struct{ calls int }

func (p *reviewPartialSecrets) Get(context.Context, string, string) (string, error) {
	p.calls++
	if p.calls == 1 {
		return "review-dummy-secret", nil
	}
	return "", secrets.ErrNotFound
}

func TestReviewPartialSecretFailure(t *testing.T) {
	provider := &reviewPartialSecrets{}
	h := &Handler{Policies: policy.FromPolicies(&policy.Policy{Slug: "dev", Allow: []policy.Rule{{
		Host: "service.test", Paths: []string{"/**"},
		Inject: map[string]string{"Authorization": "secret:first", "X-Api-Key": "secret:second"},
	}}}), Secrets: provider}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req("spiffe://sandbox/agent/dev/1,spiffe://sandbox/tenant/acme,spiffe://sandbox/sandbox/sb1", "service.test", "POST", "/request"))
	if w.Code != http.StatusBadGateway || provider.calls != 2 {
		t.Fatalf("expected failure after two secret lookups, code=%d calls=%d", w.Code, provider.calls)
	}
	if strings.Contains(w.Body.String(), "review-dummy-secret") || strings.Contains(w.Header().Get("Authorization"), "review-dummy-secret") || strings.Contains(w.Header().Get("X-Api-Key"), "review-dummy-secret") {
		t.Fatal("an unsuccessful authorization response exposed a resolved credential")
	}
}

func TestReviewRunningAgentPolicyRevocation(t *testing.T) {
	for _, tc := range []struct {
		name, replacement string
	}{
		{"other_tenant", "slug: dev\ntenants: [other]\nallow:\n  - host: service.test\n    paths: ['/**']\n"},
		{"last_tenant_removed", "slug: dev\ntenants: []\nallow:\n  - host: service.test\n    paths: ['/**']\n"},
		{"slug_deleted", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, contents string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write("default.yaml", "slug: default\ntenants: ['*']\nallow:\n  - host: service.test\n    paths: ['/**']\n")
			write("dev.yaml", "slug: dev\ntenants: [acme]\nallow:\n  - host: service.test\n    paths: ['/**']\n")
			load := func() *policy.Set {
				t.Helper()
				ps, err := policy.Load(dir)
				if err != nil {
					t.Fatal(err)
				}
				ps.Strict = true
				return ps
			}
			h := &Handler{Policies: load()}
			request := func() int {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, req("spiffe://sandbox/agent/dev/1,spiffe://sandbox/tenant/acme,spiffe://sandbox/sandbox/sb1", "service.test", "GET", "/data"))
				return w.Code
			}
			if code := request(); code != http.StatusOK {
				t.Fatalf("initial grant returned %d", code)
			}
			if tc.replacement == "" {
				if err := os.Remove(filepath.Join(dir, "dev.yaml")); err != nil {
					t.Fatal(err)
				}
			} else {
				write("dev.yaml", tc.replacement)
			}
			h.Policies = load()
			if h.Policies.AllowedFor("dev", "acme") {
				t.Fatal("test setup must revoke new sandbox creation")
			}
			if code := request(); code != http.StatusForbidden {
				t.Fatalf("revoked running agent retained access: HTTP %d", code)
			}
		})
	}
}
