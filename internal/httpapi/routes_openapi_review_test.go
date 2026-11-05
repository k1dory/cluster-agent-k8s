package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"agent-sandbox/api"
	"agent-sandbox/internal/model"

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

// specSchema is the part of a component schema these checks read.
type specSchema struct {
	Required   []string `yaml:"required"`
	Properties map[string]struct {
		Enum []string `yaml:"enum"`
	} `yaml:"properties"`
}

func specSchemas(t *testing.T) map[string]specSchema {
	t.Helper()
	var spec struct {
		Components struct {
			Schemas map[string]specSchema `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(api.OpenAPI, &spec); err != nil {
		t.Fatal(err)
	}
	return spec.Components.Schemas
}

// conforms checks a JSON object against a schema: no field the schema does not name, the
// required ones present, enum values in the enum.
func conforms(t *testing.T, what string, raw []byte, sc specSchema) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("%s: %v %s", what, err, raw)
	}
	for k, v := range obj {
		p, ok := sc.Properties[k]
		if !ok {
			t.Errorf("%s: field %q is not in the schema", what, k)
			continue
		}
		if s, isStr := v.(string); isStr && len(p.Enum) > 0 && !slices.Contains(p.Enum, s) {
			t.Errorf("%s: %s %q is not in the enum %v", what, k, s, p.Enum)
		}
	}
	for _, k := range sc.Required {
		if _, ok := obj[k]; !ok {
			t.Errorf("%s: required field %q missing", what, k)
		}
	}
	return obj
}

// Every event type the server writes is in Event.type's enum, and a real response of
// GET /agent/fs/requests conforms to Event, its data to FSRequest.
func TestReviewEventTypesAndFSRequestsMatchTheSpec(t *testing.T) {
	schemas := specSchemas(t)
	enum := schemas["Event"].Properties["type"].Enum
	for _, typ := range []string{model.EventStatus, model.EventRunQueued, model.EventRunStart, model.EventRunOutput, model.EventRunDone,
		model.EventRunCancel, model.EventRunClose, model.EventInput, model.EventReply, model.EventFSRequest, model.EventFSResult,
		model.EventEgressOK, model.EventEgressDen, model.EventRollout} {
		if !slices.Contains(enum, typ) {
			t.Errorf("event type %q is not in Event.type's enum", typ)
		}
	}

	s := newStack(t)
	api, gw := s.platform.URL, s.gateway.URL
	sb, hdr := agentOf(t, s, "fsreq")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { // asks the pod for a listing and waits for an answer that never comes
		req, _ := http.NewRequestWithContext(ctx, "GET", api+"/v1/sandboxes/"+sb.ID+"/files?path=repo&depth=2", nil)
		req.Header.Set("Authorization", "Bearer t0k")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	resp, body := call(t, "GET", gw+"/agent/fs/requests?wait=5s", "", nil, hdr)
	var evs []json.RawMessage
	if err := json.Unmarshal(body, &evs); resp.StatusCode != 200 || err != nil || len(evs) == 0 {
		t.Fatalf("fs requests: %d %s", resp.StatusCode, body)
	}
	for _, raw := range evs {
		ev := conforms(t, "fs.request event", raw, schemas["Event"])
		data, _ := ev["data"].(string)
		req := conforms(t, "FSRequest", []byte(data), schemas["FSRequest"])
		if ev["type"] != model.EventFSRequest || req["op"] != model.FSList {
			t.Fatalf("event %s", raw)
		}
	}
}
