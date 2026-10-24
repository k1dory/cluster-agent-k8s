package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
)

type issuedKey struct {
	model.APIKey
	Secret   string `json:"secret"`
	Replaces string `json:"replaces"`
}

func TestTenantKeysSelfService(t *testing.T) {
	s := newStack(t)
	s.p.Keys = &apikeys.Service{Store: s.orch.Store}
	api := s.platform.URL
	issue := func(token, tenant, name string, want int) issuedKey {
		t.Helper()
		resp, body := call(t, "POST", api+"/v1/tenants/"+tenant+"/keys", token, map[string]any{"name": name}, nil)
		if resp.StatusCode != want {
			t.Fatalf("issue %s/%s as %s: %d %s", tenant, name, token, resp.StatusCode, body)
		}
		var k issuedKey
		_ = json.Unmarshal(body, &k)
		return k
	}
	// The admin bootstraps a tenant: no configuration, no manifest, one request.
	k := issue("t0k", "carol", "ci", 201)
	if !strings.HasPrefix(k.Secret, "sbk_") || k.Tenant != "carol" || k.CreatedBy != "admin-token" {
		t.Fatalf("issued: %+v", k)
	}
	// The key is a tenant principal: whoami, scoped reads, and the secret is never echoed.
	resp, body := call(t, "GET", api+"/v1/whoami", k.Secret, nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"tenant":"carol"`) || !strings.Contains(string(body), `"subject":"key:`+k.ID) || strings.Contains(string(body), `"admin":true`) {
		t.Fatalf("whoami: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/tenants/carol/keys", k.Secret, nil, nil)
	if resp.StatusCode != 200 || strings.Contains(string(body), k.Secret) || strings.Contains(string(body), `"hash"`) || !strings.Contains(string(body), `"last_used_at"`) {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/tenants/carol/keys/"+k.ID, k.Secret, nil, nil); resp.StatusCode != 200 {
		t.Fatalf("get: %d", resp.StatusCode)
	}
	// Self-service: carol adds a key for a second pipeline with her own key.
	k2 := issue(k.Secret, "carol", "deploy", 201)
	if k2.CreatedBy != "key:"+k.ID {
		t.Fatalf("created_by: %+v", k2)
	}
	// Isolation: alice cannot read, mint, rotate or revoke carol's keys; carol's key ids are
	// not found from alice's scope, not forbidden.
	if resp, _ := call(t, "GET", api+"/v1/tenants/carol/keys", "alice-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("alice listing carol's keys: %d", resp.StatusCode)
	}
	issue("alice-tok", "carol", "evil", 403)
	if resp, _ := call(t, "DELETE", api+"/v1/tenants/alice/keys/"+k.ID, "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("alice revoking carol's key through her own path: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/tenants/alice/keys/"+k.ID+"/rotate", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("alice rotating carol's key: %d", resp.StatusCode)
	}
	// Rotation with a grace period: the old key keeps working until it ends.
	resp, body = call(t, "POST", api+"/v1/tenants/carol/keys/"+k2.ID+"/rotate", k.Secret, map[string]any{"grace": "1h"}, nil)
	var k3 issuedKey
	_ = json.Unmarshal(body, &k3)
	if resp.StatusCode != 201 || k3.Replaces != k2.ID || k3.Name != "deploy" || k3.Secret == k2.Secret {
		t.Fatalf("rotate: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/whoami", k2.Secret, nil, nil); resp.StatusCode != 200 {
		t.Fatalf("old key within grace: %d", resp.StatusCode)
	}
	resp, body = call(t, "GET", api+"/v1/tenants/carol/keys/"+k2.ID, k.Secret, nil, nil)
	var old model.APIKey
	_ = json.Unmarshal(body, &old)
	if old.RotatedTo != k3.ID || old.ExpiresAt == nil || time.Until(*old.ExpiresAt) > time.Hour {
		t.Fatalf("old key after rotation: %s", body)
	}
	// Revocation is immediate: the very next request with the key is refused.
	if resp, _ := call(t, "DELETE", api+"/v1/tenants/carol/keys/"+k3.ID, k.Secret, nil, nil); resp.StatusCode != 204 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/whoami", k3.Secret, nil, nil); resp.StatusCode != 401 {
		t.Fatalf("revoked key still accepted: %d", resp.StatusCode)
	}
	// Rotation without grace revokes the old key in the same call; a key can revoke itself
	// (and then nothing more).
	resp, body = call(t, "POST", api+"/v1/tenants/carol/keys/"+k.ID+"/rotate", k.Secret, nil, nil)
	var k4 issuedKey
	_ = json.Unmarshal(body, &k4)
	if resp.StatusCode != 201 {
		t.Fatalf("rotate without grace: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/whoami", k.Secret, nil, nil); resp.StatusCode != 401 {
		t.Fatalf("rotated-out key still accepted: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/whoami", k4.Secret, nil, nil); resp.StatusCode != 200 {
		t.Fatalf("replacement key: %d", resp.StatusCode)
	}
	// Bad requests.
	if resp, _ := call(t, "POST", api+"/v1/tenants/carol/keys", "t0k", map[string]any{"name": ""}, nil); resp.StatusCode != 422 {
		t.Fatalf("empty name: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/tenants/carol/keys", "t0k", map[string]any{"name": "x", "ttl": "soon"}, nil); resp.StatusCode != 400 {
		t.Fatalf("bad ttl: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/tenants/carol/keys", "t0k", map[string]any{"name": "x", "secret": "mine"}, nil); resp.StatusCode != 400 {
		t.Fatalf("unknown field: %d", resp.StatusCode)
	}
	// An expiring key bounds the sandboxes it creates when ttl_from_token is on.
	s.p.TTLFromToken = true
	resp, body = call(t, "POST", api+"/v1/tenants/carol/keys", "t0k", map[string]any{"name": "short", "ttl": "2h"}, nil)
	var short issuedKey
	_ = json.Unmarshal(body, &short)
	if resp.StatusCode != 201 || short.ExpiresAt == nil {
		t.Fatalf("short key: %d %s", resp.StatusCode, body)
	}
	carolPols := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Tenants: []string{"carol"}, Allow: []policy.Rule{{Host: "api.anthropic.com", Paths: []string{"/v1/**"}}}})
	s.p.Policies, s.orch.Policies = carolPols, carolPols
	resp, body = call(t, "POST", api+"/v1/sandboxes", short.Secret, map[string]any{"name": "shop", "slug": "backend-dev", "owner": "carol"}, nil)
	var sb model.Sandbox
	_ = json.Unmarshal(body, &sb)
	if resp.StatusCode != 201 || sb.ExpiresAt == nil || sb.ExpiresAt.After(*short.ExpiresAt) {
		t.Fatalf("sandbox from an expiring key: %d %s", resp.StatusCode, body)
	}
}
