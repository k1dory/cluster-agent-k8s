package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"gopkg.in/yaml.v3"

	"agent-sandbox/api"
	"agent-sandbox/internal/apikeys"
	"agent-sandbox/internal/ca"
	"agent-sandbox/internal/registrar"
)

func documented(t *testing.T, method, route string, status int) {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal(api.OpenAPI, &root); err != nil {
		t.Fatal(err)
	}
	op, _ := root["paths"].(map[string]any)[route].(map[string]any)[method].(map[string]any)
	responses, _ := op["responses"].(map[string]any)
	if _, ok := responses[fmt.Sprint(status)]; !ok {
		t.Errorf("OpenAPI %s %s omits the actual response %d", method, route, status)
	}
}

// The responses the rotate and bootstrap handlers really give are the ones OpenAPI lists.
func TestReviewRotateAndBootstrapResponsesAreDocumented(t *testing.T) {
	s := newStack(t)
	s.p.Keys = &apikeys.Service{Store: s.orch.Store}
	base := s.platform.URL
	resp, body := call(t, "POST", base+"/v1/tenants/carol/keys", "t0k", map[string]any{"name": "ci"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("issue: %d %s", resp.StatusCode, body)
	}
	var k issuedKey
	mustJSON(t, body, &k)
	rotate := base + "/v1/tenants/carol/keys/" + k.ID + "/rotate"
	const route = "/v1/tenants/{tenant}/keys/{id}/rotate"
	resp, body = call(t, "POST", rotate, "t0k", map[string]any{"grace": "1h"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("rotate: %d %s", resp.StatusCode, body)
	}
	var next issuedKey
	mustJSON(t, body, &next)
	// The successor is used, then the old key is rotated again: refused.
	if r, _ := call(t, "GET", base+"/v1/whoami", next.Secret, nil, nil); r.StatusCode != 200 {
		t.Fatalf("successor: %d", r.StatusCode)
	}
	resp, body = call(t, "POST", rotate, "t0k", map[string]any{"grace": "1h"}, nil)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("rotating a key whose successor is in use: %d %s, want 422", resp.StatusCode, body)
	}
	documented(t, "post", route, resp.StatusCode)
	resp, _ = call(t, "POST", rotate, "t0k", "{", nil)
	documented(t, "post", route, resp.StatusCode)

	// Bootstrap: a malformed CSR is a 400, an outage on the platform's side a 503.
	s.tokens["pod-token"] = registrar.PodInfo{Name: "agent-x", SandboxID: "sb_none", Slug: "backend-dev", Tenant: "alice"}
	resp, _ = call(t, "POST", s.gateway.URL+"/bootstrap", "pod-token", registrar.BootstrapRequest{CSR: "junk"}, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("bad bootstrap: %d", resp.StatusCode)
	}
	documented(t, "post", "/bootstrap", resp.StatusCode)
	s.reg.Store = bootstrapStoreDown{Store: s.reg.Store}
	_, csr, _ := ca.NewCSR("backend-dev")
	resp, _ = call(t, "POST", s.gateway.URL+"/bootstrap", "pod-token", registrar.BootstrapRequest{CSR: string(csr)}, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("bootstrap during an outage: %d", resp.StatusCode)
	}
	documented(t, "post", "/bootstrap", resp.StatusCode)
}

func mustJSON(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
}
