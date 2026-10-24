package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// InfisicalConfig reads secrets from Infisical (cloud or self-hosted) with a Machine Identity
// (universal auth). Secrets are looked up by name under the tenant folder, then the shared one.
type InfisicalConfig struct {
	SiteURL      string `yaml:"site_url"` // https://app.infisical.com or your instance
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"` // ${INFISICAL_CLIENT_SECRET}
	ProjectID    string `yaml:"project_id"`
	Environment  string `yaml:"environment"` // e.g. prod
	TenantPath   string `yaml:"tenant_path"` // default /tenants/{tenant}
	SharedPath   string `yaml:"shared_path"` // default /shared
}

func (c *InfisicalConfig) defaults() {
	if c.SiteURL == "" {
		c.SiteURL = "https://app.infisical.com"
	}
	if c.TenantPath == "" {
		c.TenantPath = "/tenants/{tenant}"
	}
	if c.SharedPath == "" {
		c.SharedPath = "/shared"
	}
}

// Infisical is a Provider over the Infisical REST API.
type Infisical struct {
	cfg  InfisicalConfig
	http *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// NewInfisical validates the configuration and returns a provider (no network until first use).
func NewInfisical(cfg InfisicalConfig) (*Infisical, error) {
	switch {
	case cfg.ClientID == "" || cfg.ClientSecret == "":
		return nil, errors.New("infisical: client_id and client_secret are required")
	case cfg.ProjectID == "" || cfg.Environment == "":
		return nil, errors.New("infisical: project_id and environment are required")
	}
	cfg.defaults()
	return &Infisical{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}, nil
}

func (i *Infisical) auth(ctx context.Context) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.token != "" && time.Now().Before(i.tokenExp) {
		return i.token, nil
	}
	body, _ := json.Marshal(map[string]string{"clientId": i.cfg.ClientID, "clientSecret": i.cfg.ClientSecret})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(i.cfg.SiteURL, "/")+"/api/v1/auth/universal-auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := i.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("infisical login: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("infisical login: %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	var out struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int    `json:"expiresIn"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("infisical login: no access token in response")
	}
	i.token = out.AccessToken
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	i.tokenExp = time.Now().Add(ttl * 9 / 10)
	return i.token, nil
}

// Get reads secret name from the tenant folder, then the shared folder.
func (i *Infisical) Get(ctx context.Context, tenant, name string) (string, error) {
	token, err := i.auth(ctx)
	if err != nil {
		return "", err
	}
	paths := []string{}
	if tenant != "" {
		paths = append(paths, strings.ReplaceAll(i.cfg.TenantPath, "{tenant}", tenant))
	}
	paths = append(paths, i.cfg.SharedPath)
	for _, p := range paths {
		q := url.Values{"workspaceId": {i.cfg.ProjectID}, "environment": {i.cfg.Environment}, "secretPath": {p}}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
			strings.TrimRight(i.cfg.SiteURL, "/")+"/api/v3/secrets/raw/"+url.PathEscape(name)+"?"+q.Encode(), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := i.http.Do(req)
		if err != nil {
			return "", err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound:
			continue
		case resp.StatusCode == http.StatusUnauthorized:
			i.mu.Lock()
			i.token = ""
			i.mu.Unlock()
			return "", fmt.Errorf("infisical: %s", resp.Status)
		case resp.StatusCode >= 300:
			return "", fmt.Errorf("infisical: %s: %s", resp.Status, strings.TrimSpace(string(data)))
		}
		var out struct {
			Secret struct {
				Value string `json:"secretValue"`
			} `json:"secret"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return "", err
		}
		return out.Secret.Value, nil
	}
	return "", ErrNotFound
}

// Cached wraps a Provider with a TTL cache: the gateway asks on every allowed request, the
// backend should not be. Misses are cached briefly too, so a missing name cannot hammer it.
type Cached struct {
	Provider Provider
	TTL      time.Duration

	mu    sync.Mutex
	items map[string]cacheItem
}

type cacheItem struct {
	value string
	err   error
	exp   time.Time
}

// NewCached returns a caching wrapper; ttl 0 means 60s.
func NewCached(p Provider, ttl time.Duration) *Cached {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &Cached{Provider: p, TTL: ttl, items: map[string]cacheItem{}}
}

func (c *Cached) Get(ctx context.Context, tenant, name string) (string, error) {
	key := tenant + "\x00" + name
	c.mu.Lock()
	it, ok := c.items[key]
	c.mu.Unlock()
	if ok && time.Now().Before(it.exp) {
		return it.value, it.err
	}
	v, err := c.Provider.Get(ctx, tenant, name)
	ttl := c.TTL
	if err != nil && !errors.Is(err, ErrNotFound) {
		ttl = 2 * time.Second // backend trouble: retry soon, but not on every request
	}
	c.mu.Lock()
	c.items[key] = cacheItem{value: v, err: err, exp: time.Now().Add(ttl)}
	c.mu.Unlock()
	return v, err
}
