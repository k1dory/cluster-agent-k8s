package httpapi

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"agent-sandbox/api"

	"gopkg.in/yaml.v3"
)

// routeNotInSpec are mux patterns openapi.yaml does not describe on purpose: the gateway's
// catch-all hands every other request to the MCP proxy.
var routeNotInSpec = []string{"/"}

// Every route the two muxes register is in openapi.yaml with its method, and every operation
// in openapi.yaml is a registered route: adding a route without describing it fails here.
func TestReviewEveryRouteIsInTheSpecAndBack(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.OpenAPI, &spec); err != nil {
		t.Fatal(err)
	}
	inSpec := map[string]bool{}
	for path, item := range spec.Paths {
		for method := range item {
			switch method {
			case "get", "put", "post", "patch", "delete", "head", "options":
				inSpec[strings.ToUpper(method)+" "+path] = true
			}
		}
	}
	var registered []string
	registered = append(registered, (&Platform{}).routes().patterns...)
	registered = append(registered, (&Gateway{MCP: http.NotFoundHandler()}).routes().patterns...)
	seen := map[string]bool{}
	for _, pattern := range registered {
		if slices.Contains(routeNotInSpec, pattern) {
			continue
		}
		// "{name...}" matches the rest of the path; OpenAPI writes the parameter as "{name}".
		op := strings.ReplaceAll(pattern, "...}", "}")
		if seen[op] {
			continue // the same pattern on both listeners (/healthz)
		}
		seen[op] = true
		if !inSpec[op] {
			t.Errorf("route %q is not in api/openapi.yaml", pattern)
		}
	}
	for op := range inSpec {
		if !seen[op] {
			t.Errorf("openapi.yaml describes %q, which no mux registers", op)
		}
	}
}
