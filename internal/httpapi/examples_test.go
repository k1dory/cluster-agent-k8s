package httpapi

import (
	"os"
	"strings"
	"testing"

	"agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
)

// The shipped connection, binding and settings examples apply as they are through the API.
func TestShippedConfigExamples(t *testing.T) {
	s, _ := configStack(t)
	api := s.platform.URL
	s.p.Tenants["acme-tok"] = "acme"
	// The provider is shared by the connections service and the planner: add to it in place.
	sec := s.p.Connections.Secrets.(secrets.Static)
	sec["acme/github-token"], sec["alice/github-token"] = "ghp_example", "ghp_example"
	for _, tc := range []struct{ file, token, path string }{
		{"connection-github.yaml", "acme-tok", "/v1/connections/github"},
		{"binding-backend.yaml", "t0k", "/v1/bindings/backend-dev?tenant=acme"},
		{"tenant-settings.yaml", "t0k", "/v1/tenants/acme/settings"},
	} {
		raw, err := os.ReadFile("../../examples/catalog/" + tc.file)
		if err != nil {
			t.Fatal(err)
		}
		d, err := resource.ParseYAML(raw)
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		resp, body := call(t, "PUT", api+tc.path, tc.token, d, nil)
		if resp.StatusCode != 201 {
			t.Fatalf("%s: %d %s", tc.file, resp.StatusCode, body)
		}
		if strings.Contains(string(body), "ghp_") {
			t.Fatalf("%s: a value in the response", tc.file)
		}
	}
	if _, ok := s.p.Bindings.Active("backend-dev", "acme"); !ok {
		t.Fatal("the example binding must be live")
	}
	if q := s.p.TenantSettings.QuotaFor("acme"); q.MaxSandboxes != 20 || !s.p.TenantSettings.EnvironmentAllowed("acme", "shared/base") || s.p.TenantSettings.EnvironmentAllowed("acme", "other") {
		t.Fatalf("example settings: %+v", q)
	}
	// The example bundle plans cleanly for a tenant that may use the policy.
	raw, err := os.ReadFile("../../examples/catalog/bundle.yaml")
	if err != nil {
		t.Fatal(err)
	}
	resp, body := call(t, "POST", api+"/v1/plan", "alice-tok", string(raw), map[string]string{"Content-Type": "application/yaml"})
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"valid":true`) {
		t.Fatalf("example bundle plan: %d %s", resp.StatusCode, body)
	}
}
