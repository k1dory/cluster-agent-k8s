package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// VaultConfig reads secrets from HashiCorp Vault or OpenBao (same API) KV version 2.
//
// Layout: one KV secret per tenant at TenantPath (with {tenant} substituted) whose keys are the
// secret names, and one shared secret at SharedPath. `secret:anthropic` for tenant acme reads
// key `anthropic` of `<mount>/data/agent-sandbox/tenants/acme`, then of the shared path.
type VaultConfig struct {
	Addr  string `yaml:"addr"`  // https://vault.example.com or https://openbao.example.com
	Token string `yaml:"token"` // static token (${VAULT_TOKEN}); or use Kubernetes auth below
	// Kubernetes auth: log in with the pod's ServiceAccount token under this role.
	KubernetesRole  string `yaml:"kubernetes_role"`
	KubernetesMount string `yaml:"kubernetes_mount"` // auth mount, default kubernetes
	TokenFile       string `yaml:"token_file"`       // default /var/run/secrets/kubernetes.io/serviceaccount/token
	Namespace       string `yaml:"namespace"`        // Vault Enterprise / OpenBao namespace header
	Mount           string `yaml:"mount"`            // KV v2 mount, default secret
	TenantPath      string `yaml:"tenant_path"`      // default agent-sandbox/tenants/{tenant}
	SharedPath      string `yaml:"shared_path"`      // default agent-sandbox/shared
}

func (c *VaultConfig) defaults() {
	if c.KubernetesMount == "" {
		c.KubernetesMount = "kubernetes"
	}
	if c.TokenFile == "" {
		c.TokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}
	if c.Mount == "" {
		c.Mount = "secret"
	}
	if c.TenantPath == "" {
		c.TenantPath = "agent-sandbox/tenants/{tenant}"
	}
	if c.SharedPath == "" {
		c.SharedPath = "agent-sandbox/shared"
	}
}

// Vault is a Provider over the Vault/OpenBao HTTP API.
type Vault struct {
	cfg  VaultConfig
	http *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewVault validates the configuration and returns a provider (no network until first use).
func NewVault(cfg VaultConfig) (*Vault, error) {
	if cfg.Addr == "" {
		return nil, errors.New("vault.addr is required")
	}
	if cfg.Token == "" && cfg.KubernetesRole == "" {
		return nil, errors.New("vault: set token or kubernetes_role")
	}
	cfg.defaults()
	return &Vault{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}, token: cfg.Token}, nil
}

func (v *Vault) auth(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.token != "" && (v.tokenExp.IsZero() || time.Now().Before(v.tokenExp)) {
		return v.token, nil
	}
	jwt, err := os.ReadFile(v.cfg.TokenFile)
	if err != nil {
		return "", fmt.Errorf("vault kubernetes auth: %w", err)
	}
	body, _ := json.Marshal(map[string]string{"role": v.cfg.KubernetesRole, "jwt": strings.TrimSpace(string(jwt))})
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := v.call(ctx, http.MethodPost, "/v1/auth/"+v.cfg.KubernetesMount+"/login", "", body, &out); err != nil {
		return "", fmt.Errorf("vault kubernetes auth: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("vault kubernetes auth: no client token in response")
	}
	v.token = out.Auth.ClientToken
	// Renew a little before the lease ends; a zero lease means a token without expiry.
	if out.Auth.LeaseDuration > 0 {
		v.tokenExp = time.Now().Add(time.Duration(out.Auth.LeaseDuration) * time.Second * 9 / 10)
	}
	return v.token, nil
}

func (v *Vault) call(ctx context.Context, method, path, token string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(v.cfg.Addr, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if v.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.cfg.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := v.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode == http.StatusForbidden && token != "" {
		// The token may have been revoked: forget it so the next call logs in again.
		v.mu.Lock()
		if v.cfg.Token == "" {
			v.token = ""
		}
		v.mu.Unlock()
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Get reads key name from the tenant's secret, then from the shared one.
func (v *Vault) Get(ctx context.Context, tenant, name string) (string, error) {
	token, err := v.auth(ctx)
	if err != nil {
		return "", err
	}
	paths := []string{}
	if tenant != "" {
		paths = append(paths, strings.ReplaceAll(v.cfg.TenantPath, "{tenant}", tenant))
	}
	paths = append(paths, v.cfg.SharedPath)
	for _, p := range paths {
		var out struct {
			Data struct {
				Data map[string]any `json:"data"`
			} `json:"data"`
		}
		err := v.call(ctx, http.MethodGet, "/v1/"+v.cfg.Mount+"/data/"+strings.Trim(p, "/"), token, nil, &out)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return "", err
		}
		if val, ok := out.Data.Data[name]; ok {
			if s, ok := val.(string); ok {
				return s, nil
			}
			b, _ := json.Marshal(val)
			return string(b), nil
		}
	}
	return "", ErrNotFound
}
