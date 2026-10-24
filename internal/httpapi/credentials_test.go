package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"agent-sandbox/internal/app"
	"agent-sandbox/internal/authz"
	"agent-sandbox/internal/bindings"
	"agent-sandbox/internal/credentials"
	"agent-sandbox/internal/identity"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/secrets"
)

// BYOK end to end: alice brings her own token through the API, a connection references it,
// the gateway injects it, a replacement is picked up on the next request, a removal fails the
// next request; the API never shows the value.
func TestBringYourOwnCredentialsEndToEnd(t *testing.T) {
	s, guard, prov := configStackWithCredentials(t)
	api := s.platform.URL
	// Not there yet: a connection referencing it is refused at write time, like any unresolvable
	// reference.
	conn := `{"spec":{"type":"http","host":"api.github.com","headers":{"Authorization":"Bearer secret:my-token"}}}`
	if resp, _ := call(t, "PUT", api+"/v1/connections/gh", "alice-tok", conn, nil); resp.StatusCode != 422 {
		t.Fatalf("unresolvable reference accepted: %d", resp.StatusCode)
	}
	// Alice adds it. The response is metadata; the value appears nowhere.
	resp, body := call(t, "PUT", api+"/v1/credentials/my-token", "alice-tok", map[string]any{"value": "ghp_ALICE_ONE"}, nil)
	var c model.Credential
	_ = json.Unmarshal(body, &c)
	if resp.StatusCode != 201 || c.Version != 1 || c.Tenant != "alice" || strings.Contains(string(body), "ALICE") {
		t.Fatalf("add: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "GET", api+"/v1/credentials", "alice-tok", nil, nil); resp.StatusCode != 200 || strings.Contains(string(body), "ALICE") || !strings.Contains(string(body), `"my-token"`) {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/credentials/my-token", "bob-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("bob reading alice's credential: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/credentials?tenant=alice", "bob-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob listing alice's scope: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "PUT", api+"/v1/credentials/my-token", "alice-tok", `{"value":"x","extra":1}`, nil); resp.StatusCode != 400 {
		t.Fatalf("unknown field: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "PUT", api+"/v1/credentials/bad%2Fname", "alice-tok", map[string]any{"value": "x"}, nil); resp.StatusCode != 422 {
		t.Fatalf("bad name: %d", resp.StatusCode)
	}
	// A body with a second document or trailing garbage writes nothing.
	for _, bad := range []string{`{"value":"TRAILING"} {"value":"second"}`, `{"value":"TRAILING"}garbage`, `{"value":"TRAILING"}]`} {
		if resp, _ := call(t, "PUT", api+"/v1/credentials/trailing", "alice-tok", bad, nil); resp.StatusCode != 400 {
			t.Fatalf("trailing data accepted: %d for %s", resp.StatusCode, bad)
		}
	}
	if resp, _ := call(t, "GET", api+"/v1/credentials/trailing", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatal("a refused body wrote a credential")
	}
	// The largest allowed value passes the HTTP layer (the limit is on the value, not on the
	// JSON around it, escaping included); one byte more is refused by the service as 422.
	big := strings.Repeat("\"", credentials.MaxValue) // every byte escapes to two in JSON
	if resp, body := call(t, "PUT", api+"/v1/credentials/big", "alice-tok", map[string]any{"value": big}, nil); resp.StatusCode != 201 {
		t.Fatalf("max value: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "PUT", api+"/v1/credentials/big", "alice-tok", map[string]any{"value": big + "x"}, nil); resp.StatusCode != 422 {
		t.Fatalf("over max value: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "DELETE", api+"/v1/credentials/big", "alice-tok", nil, nil); resp.StatusCode != 204 {
		t.Fatal("cleanup")
	}
	// Now the connection validates, and the gateway injects the value for alice's sandbox.
	if resp, body := call(t, "PUT", api+"/v1/connections/gh", "alice-tok", conn, nil); resp.StatusCode != 201 {
		t.Fatalf("connection: %d %s", resp.StatusCode, body)
	}
	if code, _ := putDoc(t, api, "alice-tok", "environments", "py", `{"spec":{"image":"stable"}}`); code != 201 {
		t.Fatal("environment")
	}
	if code, _ := putDoc(t, api, "alice-tok", "agents", "backend", `{"spec":{"policy":"backend-dev","environment":"py","connections":["gh"]}}`); code != 201 {
		t.Fatal("agent")
	}
	resp, body = call(t, "POST", api+"/v1/sandboxes", "alice-tok", map[string]any{"name": "shop", "owner": "alice", "agent_ref": "backend"}, nil)
	var sb model.Sandbox
	_ = json.Unmarshal(body, &sb)
	if resp.StatusCode != 201 {
		t.Fatalf("sandbox: %d %s", resp.StatusCode, body)
	}
	az := &authz.Handler{Policies: guard, Secrets: prov}
	decide := func() (int, string) {
		r := httptest.NewRequest("GET", "/authz", nil)
		r.Header.Set(identity.HeaderSANs, "spiffe://sandbox/agent/backend-dev/1,spiffe://sandbox/tenant/alice,spiffe://sandbox/sandbox/"+sb.ID)
		r.Header.Set("X-Forwarded-Host", "api.github.com")
		r.Header.Set("X-Forwarded-Method", "GET")
		r.Header.Set("X-Forwarded-Uri", "/repos")
		w := httptest.NewRecorder()
		az.ServeHTTP(w, r)
		return w.Code, w.Header().Get("Authorization")
	}
	if code, auth := decide(); code != 200 || auth != "Bearer ghp_ALICE_ONE" {
		t.Fatalf("gateway with the tenant's credential: %d %q", code, auth)
	}
	// Replace: version 2, the next request carries the new value.
	resp, body = call(t, "PUT", api+"/v1/credentials/my-token", "alice-tok", map[string]any{"value": "ghp_ALICE_TWO"}, nil)
	_ = json.Unmarshal(body, &c)
	if resp.StatusCode != 200 || c.Version != 2 {
		t.Fatalf("replace: %d %s", resp.StatusCode, body)
	}
	if code, auth := decide(); code != 200 || auth != "Bearer ghp_ALICE_TWO" {
		t.Fatalf("after replace: %d %q", code, auth)
	}
	// The tenant's credential wins over the operator's value of the same name; the operator's
	// other secrets still resolve.
	resp, body = call(t, "PUT", api+"/v1/connections/gh", "alice-tok", `{"spec":{"type":"http","host":"api.github.com","headers":{"Authorization":"Bearer secret:github","X-Token":"secret:my-token"}}}`, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("connection v2: %d %s", resp.StatusCode, body)
	}
	resp, _ = call(t, "PUT", api+"/v1/credentials/github", "alice-tok", map[string]any{"value": "ghp_MINE"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("override: %d", resp.StatusCode)
	}
	if code, auth := decide(); code != 200 || auth != "Bearer ghp_MINE" {
		t.Fatalf("tenant credential over the operator's: %d %q", code, auth)
	}
	if resp, _ := call(t, "DELETE", api+"/v1/credentials/github", "alice-tok", nil, nil); resp.StatusCode != 204 {
		t.Fatal("remove override")
	}
	if code, auth := decide(); code != 200 || auth != "Bearer "+leaked {
		t.Fatalf("operator's value again: %d %q", code, auth)
	}
	// Revoke: the next request that needs the credential fails at the gateway (502, nothing
	// partial), and the record is gone from the API.
	if resp, _ := call(t, "DELETE", api+"/v1/credentials/my-token", "alice-tok", nil, nil); resp.StatusCode != 204 {
		t.Fatal("revoke")
	}
	if code, auth := decide(); code != 502 || auth != "" {
		t.Fatalf("after revoke: %d %q", code, auth)
	}
	if resp, _ := call(t, "GET", api+"/v1/credentials/my-token", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatal("revoked credential still listed")
	}
	// The admin manages a tenant's scope and the shared one.
	if resp, _ := call(t, "PUT", api+"/v1/credentials/shared-key", "t0k", map[string]any{"value": "s"}, nil); resp.StatusCode != 201 {
		t.Fatal("shared credential")
	}
	if resp, body := call(t, "GET", api+"/v1/credentials?tenant=alice", "t0k", nil, nil); resp.StatusCode != 200 || strings.Contains(string(body), "shared-key") {
		t.Fatalf("admin reading alice's scope: %d %s", resp.StatusCode, body)
	}
	// Disabled server: 503 with the reason.
	s.p.Credentials = nil
	if resp, body := call(t, "GET", api+"/v1/credentials", "alice-tok", nil, nil); resp.StatusCode != 503 || !strings.Contains(string(body), "credentials.key") {
		t.Fatalf("disabled: %d %s", resp.StatusCode, body)
	}
}

// configStackWithCredentials is configStack with the BYOK store chained in front of the
// operator's secrets, as sandboxd wires it.
func configStackWithCredentials(t *testing.T) (*stack, *bindings.Guard, secrets.Provider) {
	t.Helper()
	s := newStack(t)
	pols := policy.FromPolicies(
		&policy.Policy{Slug: "backend-dev", Tenants: []string{"alice"}, Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}},
	)
	pols.Strict = true
	s.p.Policies = pols
	s.orch.Cfg.Versions = map[string]string{"stable": "reg/agent:1.0"}
	key, _ := credentials.ParseKey(strings.Repeat("ab", 32))
	creds, err := credentials.New(s.orch.Store, key)
	if err != nil {
		t.Fatal(err)
	}
	prov := secrets.Chain{credentials.Resolver{Service: creds}, secrets.Static{"alice/github": leaked, "bob/github": "bob-" + leaked}}
	services, err := app.Wire(context.Background(), app.Deps{Store: s.orch.Store, Policies: pols, Secrets: prov, Orch: s.orch})
	if err != nil {
		t.Fatal(err)
	}
	services.Install(s.p)
	s.p.Credentials = creds
	return s, services.Guard, prov
}
