package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"agent-sandbox/internal/plan"
)

func TestPlanEndpoint(t *testing.T) {
	s, _ := configStack(t)
	api := s.platform.URL
	yaml := "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"
	resp, body := call(t, "POST", api+"/v1/plan", "alice-tok", yaml, map[string]string{"Content-Type": "application/yaml"})
	var p plan.Plan
	_ = json.Unmarshal(body, &p)
	if resp.StatusCode != 200 || !p.Valid || p.Summary.Create != 2 || p.Changes[1].Name != "backend" || p.Changes[1].Tenant != "alice" {
		t.Fatalf("yaml plan: %d %s", resp.StatusCode, body)
	}
	// Nothing was written.
	if resp, _ := call(t, "GET", api+"/v1/environments/py", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("plan wrote: %d", resp.StatusCode)
	}
	// JSON forms: a wrapper or an array; strict per document; bad input is 400.
	resp, body = call(t, "POST", api+"/v1/plan", "alice-tok", map[string]any{"documents": []map[string]any{{"kind": "EnvironmentProfile", "name": "py", "spec": map[string]any{"image": "stable"}}}}, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"action":"create"`) {
		t.Fatalf("json plan: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "POST", api+"/v1/plan", "alice-tok", `[{"kind":"EnvironmentProfile","name":"py","spec":{"image":"stable"},"extra":1}]`, nil)
	if resp.StatusCode != 400 {
		t.Fatalf("strict documents: %d %s", resp.StatusCode, body)
	}
	// A tenant cannot plan into another scope; the admin plans any and sees the problems.
	resp, body = call(t, "POST", api+"/v1/plan", "bob-tok", yaml, map[string]string{"Content-Type": "application/yaml"})
	_ = json.Unmarshal(body, &p)
	if resp.StatusCode != 200 || p.Valid || !strings.Contains(string(body), "may not use policy") {
		t.Fatalf("bob planning on alice's policy: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "POST", api+"/v1/plan?tenant=alice", "bob-tok", yaml, map[string]string{"Content-Type": "application/yaml"}); resp.StatusCode != 403 {
		t.Fatalf("bob planning in alice's scope: %d", resp.StatusCode)
	}
	resp, body = call(t, "POST", api+"/v1/plan?tenant=alice", "t0k", yaml+"---\nkind: PolicyBinding\nname: backend-dev\nspec: {max_awake: 1}\n", map[string]string{"Content-Type": "application/yaml"})
	_ = json.Unmarshal(body, &p)
	if resp.StatusCode != 200 || !p.Valid || p.Summary.Create != 3 {
		t.Fatalf("admin plan: %d %s", resp.StatusCode, body)
	}
}
