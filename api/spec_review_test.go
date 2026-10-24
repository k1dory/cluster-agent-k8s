package api

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The embedded specification is the same document served to Swagger and API clients.
// This checks YAML and local reference integrity, not full OpenAPI schema validation.
func TestReviewOpenAPILocalReferences(t *testing.T) {
	var root map[string]any
	if err := yaml.Unmarshal(OpenAPI, &root); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if ref, ok := v["$ref"].(string); ok && strings.HasPrefix(ref, "#/") {
				var target any = root
				for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
					part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
					object, ok := target.(map[string]any)
					if !ok {
						t.Errorf("unresolved OpenAPI reference: %s", ref)
						break
					}
					var found bool
					target, found = object[part]
					if !found {
						t.Errorf("unresolved OpenAPI reference: %s", ref)
						break
					}
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(root)
}
