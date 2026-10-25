package httpapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"agent-sandbox/api"
	"gopkg.in/yaml.v3"
)

// Check the advertised contract against real responses, including common errors.
func TestReviewGitRepositoryOpenAPIResponseContract(t *testing.T) {
	s, _, _ := gitStack(t)
	const item = "/v1/gitrepos/{name}"
	const endpoint = "/v1/gitrepos/config"
	doc := `{"spec":{"url":"https://git.example.com/alice/config.git","ref":"main","paths":["bundle.yaml"]}}`
	if code, _ := putDoc(t, s.platform.URL, "alice-tok", "gitrepos", "config", doc); code != 201 {
		t.Fatalf("register: %d", code)
	}
	var root map[string]any
	if err := yaml.Unmarshal(api.OpenAPI, &root); err != nil {
		t.Fatal(err)
	}
	paths := root["paths"].(map[string]any)
	cases := []struct {
		name, method, route, endpoint, token string
		body                                 any
		status                               int
	}{
		{"list_auth", "GET", "/v1/gitrepos", "/v1/gitrepos", "", nil, 401},
		{"get_auth", "GET", item, endpoint, "", nil, 401},
		{"put_auth", "PUT", item, endpoint, "", nil, 401},
		{"delete_auth", "DELETE", item, endpoint, "", nil, 401},
		{"history_auth", "GET", item + "/revisions", endpoint + "/revisions", "", nil, 401},
		{"check_auth", "POST", item + "/check", endpoint + "/check", "", nil, 401},
		{"sync_auth", "POST", item + "/sync", endpoint + "/sync", "", nil, 401},
		{"status_auth", "GET", item + "/status", endpoint + "/status", "", nil, 401},
		{"foreign_list", "GET", "/v1/gitrepos", "/v1/gitrepos?tenant=bob", "alice-tok", nil, 403},
		{"foreign_status", "GET", item + "/status", endpoint + "/status?tenant=bob", "alice-tok", nil, 403},
		{"malformed_sync", "POST", item + "/sync", endpoint + "/sync", "alice-tok", "{", 400},
		{"invalid_commit", "POST", item + "/sync", endpoint + "/sync", "alice-tok", map[string]string{"commit": "not-a-sha"}, 422},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := call(t, tc.method, s.platform.URL+tc.endpoint, tc.token, tc.body, nil)
			if resp.StatusCode != tc.status {
				t.Fatalf("handler: status=%d want=%d body=%s", resp.StatusCode, tc.status, body)
			}
			operation := paths[tc.route].(map[string]any)[strings.ToLower(tc.method)].(map[string]any)
			responses := operation["responses"].(map[string]any)
			response, ok := responses[fmt.Sprint(resp.StatusCode)]
			if !ok {
				response, ok = responses["default"]
			}
			if !ok {
				t.Fatalf("OpenAPI omits actual response %d for %s %s", resp.StatusCode, tc.method, tc.route)
			}
			if tc.name != "invalid_commit" {
				return
			}
			// Resolve local references and verify a declared error-code enum, if any.
			resolve := func(node any) map[string]any {
				v := node.(map[string]any)
				for {
					ref, ok := v["$ref"].(string)
					if !ok {
						return v
					}
					var target any = root
					for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
						target = target.(map[string]any)[part]
					}
					v = target.(map[string]any)
				}
			}
			schema := resolve(resolve(response)["content"].(map[string]any)["application/json"].(map[string]any)["schema"])
			props, ok := schema["properties"].(map[string]any)
			if !ok {
				return // Composed schemas are covered by full schema validators.
			}
			codeSchema, ok := props["code"].(map[string]any)
			if !ok {
				return
			}
			enum, ok := codeSchema["enum"].([]any)
			if !ok {
				return
			}
			var actual struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(body, &actual); err != nil {
				t.Fatal(err)
			}
			for _, allowed := range enum {
				if allowed == actual.Code {
					return
				}
			}
			t.Errorf("actual code %q is outside the documented 422 enum %v", actual.Code, enum)
		})
	}
}
