package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"agent-sandbox/internal/credentials"
	"gopkg.in/yaml.v3"
)

func TestReviewCredentialsHTTPAcceptsDocumentedValueSize(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"ascii_at_limit", strings.Repeat("a", credentials.MaxValue)},
		{"json_escaping_below_limit", strings.Repeat("\n", credentials.MaxValue/2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := configStackWithCredentials(t)
			resp, _ := call(t, "PUT", s.platform.URL+"/v1/credentials/boundary", "alice-tok", map[string]string{"value": tc.value}, nil)
			if resp.StatusCode != http.StatusCreated {
				t.Errorf("valid credential of %d bytes must fit the HTTP contract; status=%d", len(tc.value), resp.StatusCode)
			}
		})
	}
}

func TestReviewCredentialsRejectTrailingJSONBeforeWriting(t *testing.T) {
	s, _, _ := configStackWithCredentials(t)
	endpoint := s.platform.URL + "/v1/credentials/fixture"
	resp, _ := call(t, "PUT", endpoint, "alice-tok", `{"value":"first-fixture"} {"value":"second-fixture"}`, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("two JSON documents must be rejected, got %d", resp.StatusCode)
	}
	resp, _ = call(t, "GET", endpoint, "alice-tok", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Error("an invalid request must not write a credential")
	}
}

// Compare responses of the real handlers with the spec served to generated clients.
func TestReviewCredentialsOpenAPIResponseContract(t *testing.T) {
	s, _, _ := configStackWithCredentials(t)
	resp, raw := call(t, "GET", s.platform.URL+"/openapi.yaml", "", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatal("OpenAPI endpoint unavailable")
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Responses map[string]any `yaml:"responses"`
		} `yaml:"paths"`
	}
	// Path-level parameters have a different shape from operations.
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	paths := root["paths"].(map[string]any)
	for _, item := range paths {
		delete(item.(map[string]any), "parameters")
	}
	clean, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(clean, &spec); err != nil {
		t.Fatal(err)
	}
	const item = "/v1/credentials/{name}"
	cases := []struct {
		name, method, route, endpoint, token string
		body                                 any
		status                               int
		disabled                             bool
	}{
		{"create", "PUT", item, "/v1/credentials/fixture", "alice-tok", map[string]string{"value": "fixture-one"}, 201, false},
		{"replace", "PUT", item, "/v1/credentials/fixture", "alice-tok", map[string]string{"value": "fixture-two"}, 200, false},
		{"get", "GET", item, "/v1/credentials/fixture", "alice-tok", nil, 200, false},
		{"list", "GET", "/v1/credentials", "/v1/credentials", "alice-tok", nil, 200, false},
		{"missing", "GET", item, "/v1/credentials/absent", "alice-tok", nil, 404, false},
		{"invalid", "PUT", item, "/v1/credentials/fixture", "alice-tok", map[string]string{"value": ""}, 422, false},
		{"unauthenticated", "GET", "/v1/credentials", "/v1/credentials", "", nil, 401, false},
		{"foreign_scope", "GET", "/v1/credentials", "/v1/credentials?tenant=bob", "alice-tok", nil, 403, false},
		{"delete", "DELETE", item, "/v1/credentials/fixture", "alice-tok", nil, 204, false},
		{"disabled_list", "GET", "/v1/credentials", "/v1/credentials", "alice-tok", nil, 503, true},
		{"disabled_get", "GET", item, "/v1/credentials/fixture", "alice-tok", nil, 503, true},
		{"disabled_put", "PUT", item, "/v1/credentials/fixture", "alice-tok", map[string]string{"value": "fixture"}, 503, true},
		{"disabled_delete", "DELETE", item, "/v1/credentials/fixture", "alice-tok", nil, 503, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.disabled {
				s.p.Credentials = nil
			}
			resp, body := call(t, tc.method, s.platform.URL+tc.endpoint, tc.token, tc.body, nil)
			if resp.StatusCode != tc.status {
				t.Fatalf("handler status=%d, want %d", resp.StatusCode, tc.status)
			}
			if resp.StatusCode != 204 && !json.Valid(body) {
				t.Error("response must be JSON")
			}
			responses := spec.Paths[tc.route][strings.ToLower(tc.method)].Responses
			if _, ok := responses[fmt.Sprint(resp.StatusCode)]; !ok && responses["default"] == nil {
				t.Errorf("OpenAPI omits actual response %d for %s %s", resp.StatusCode, tc.method, tc.route)
			}
		})
	}
}
