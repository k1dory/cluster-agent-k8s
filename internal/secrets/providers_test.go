package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestVaultProvider(t *testing.T) {
	var logins, reads int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/auth/kubernetes/login":
			atomic.AddInt32(&logins, 1)
			var in map[string]string
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["role"] != "sandboxd" || in["jwt"] != "sa-jwt" {
				http.Error(w, "bad login", 400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "tok-1", "lease_duration": 3600}})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/kv/data/"):
			atomic.AddInt32(&reads, 1)
			if r.Header.Get("X-Vault-Token") != "tok-1" || r.Header.Get("X-Vault-Namespace") != "team" {
				http.Error(w, "forbidden", 403)
				return
			}
			switch strings.TrimPrefix(r.URL.Path, "/v1/kv/data/") {
			case "agent-sandbox/tenants/acme":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"anthropic": "sk-acme"}}})
			case "agent-sandbox/shared":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"forgejo": "shared-git", "anthropic": "sk-shared"}}})
			default:
				http.Error(w, "{}", 404)
			}
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, 500)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "token"), []byte("sa-jwt\n"), 0o600)
	v, err := NewVault(VaultConfig{Addr: srv.URL, KubernetesRole: "sandboxd", TokenFile: filepath.Join(dir, "token"), Mount: "kv", Namespace: "team"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, err := v.Get(ctx, "acme", "anthropic"); err != nil || got != "sk-acme" {
		t.Fatalf("tenant secret: %q %v", got, err)
	}
	if got, err := v.Get(ctx, "acme", "forgejo"); err != nil || got != "shared-git" {
		t.Fatalf("shared fallback: %q %v", got, err)
	}
	if got, err := v.Get(ctx, "other", "anthropic"); err != nil || got != "sk-shared" {
		t.Fatalf("other tenant falls back to shared: %q %v", got, err)
	}
	if _, err := v.Get(ctx, "acme", "nope"); err != ErrNotFound {
		t.Fatalf("missing: %v", err)
	}
	if logins != 1 {
		t.Fatalf("one login expected, got %d", logins)
	}
	// Cache: repeated reads do not hit the backend.
	c := NewCached(v, time.Minute)
	before := atomic.LoadInt32(&reads)
	for i := 0; i < 5; i++ {
		if got, _ := c.Get(ctx, "acme", "anthropic"); got != "sk-acme" {
			t.Fatal("cached value")
		}
		_, _ = c.Get(ctx, "acme", "nope")
	}
	if atomic.LoadInt32(&reads)-before > 3 {
		t.Fatalf("cache must absorb repeated reads, backend saw %d", atomic.LoadInt32(&reads)-before)
	}
	if _, err := NewVault(VaultConfig{Addr: srv.URL}); err == nil {
		t.Fatal("vault without credentials must be refused")
	}
}

func TestInfisicalProvider(t *testing.T) {
	var logins int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/auth/universal-auth/login":
			atomic.AddInt32(&logins, 1)
			_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "at-1", "expiresIn": 3600})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/v3/secrets/raw/"):
			if r.Header.Get("Authorization") != "Bearer at-1" || r.URL.Query().Get("workspaceId") != "proj" || r.URL.Query().Get("environment") != "prod" {
				http.Error(w, "unauthorized", 401)
				return
			}
			name := strings.TrimPrefix(r.URL.Path, "/api/v3/secrets/raw/")
			switch r.URL.Query().Get("secretPath") + ":" + name {
			case "/tenants/acme:anthropic":
				_ = json.NewEncoder(w).Encode(map[string]any{"secret": map[string]any{"secretValue": "sk-acme"}})
			case "/shared:forgejo":
				_ = json.NewEncoder(w).Encode(map[string]any{"secret": map[string]any{"secretValue": "git-shared"}})
			default:
				http.Error(w, "not found", 404)
			}
		default:
			http.Error(w, "unexpected", 500)
		}
	}))
	defer srv.Close()
	i, err := NewInfisical(InfisicalConfig{SiteURL: srv.URL, ClientID: "id", ClientSecret: "sec", ProjectID: "proj", Environment: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, err := i.Get(ctx, "acme", "anthropic"); err != nil || got != "sk-acme" {
		t.Fatalf("tenant: %q %v", got, err)
	}
	if got, err := i.Get(ctx, "acme", "forgejo"); err != nil || got != "git-shared" {
		t.Fatalf("shared: %q %v", got, err)
	}
	if _, err := i.Get(ctx, "acme", "nope"); err != ErrNotFound {
		t.Fatalf("missing: %v", err)
	}
	if logins != 1 {
		t.Fatalf("one login expected, got %d", logins)
	}
	// Expand works the same over any provider.
	if v, err := Expand(ctx, NewCached(i, time.Minute), "acme", "Basic secret:forgejo"); err != nil || v != "Basic git-shared" {
		t.Fatalf("expand: %q %v", v, err)
	}
}
