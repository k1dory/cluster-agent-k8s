package httpapi

import (
	"os"
	"strings"
	"testing"

	"agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
)

func secretsWith(keys ...string) secrets.Static {
	st := secrets.Static{}
	for _, k := range keys {
		st[k] = "ghp_example"
	}
	return st
}

// The shipped connection, binding and settings examples apply as they are through the API.
func TestShippedConfigExamples(t *testing.T) {
	s, _ := configStack(t)
	api := s.platform.URL
	s.p.Tenants["acme-tok"] = "acme"
	s.p.Connections.Secrets = secretsWith("acme/github-token")
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
}
