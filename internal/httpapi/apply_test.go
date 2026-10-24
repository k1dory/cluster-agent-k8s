package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/resource"
)

func TestApplyEndpoint(t *testing.T) {
	s, _ := configStack(t)
	api := s.platform.URL
	yaml := "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"
	// Plan, then apply with the fingerprint; a wrong fingerprint is 409 and writes nothing.
	resp, body := call(t, "POST", api+"/v1/plan", "alice-tok", yaml, map[string]string{"Content-Type": "application/yaml"})
	var p plan.Plan
	_ = json.Unmarshal(body, &p)
	if resp.StatusCode != 200 || !p.Valid || p.Fingerprint == "" {
		t.Fatalf("plan: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "POST", api+"/v1/apply?plan=stale", "alice-tok", yaml, map[string]string{"Content-Type": "application/yaml"}); resp.StatusCode != 409 || !strings.Contains(string(body), "plan again") {
		t.Fatalf("stale plan: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/environments/py", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatal("a refused apply wrote")
	}
	resp, body = call(t, "POST", api+"/v1/apply?plan="+p.Fingerprint, "alice-tok", yaml, map[string]string{"Content-Type": "application/yaml", "Idempotency-Key": "deploy-1"})
	var a model.Apply
	_ = json.Unmarshal(body, &a)
	if resp.StatusCode != 200 || a.Status != model.ApplyDone || a.Key != "deploy-1" || len(a.Steps) != 2 || a.Steps[1].Revision != 1 {
		t.Fatalf("apply: %d %s", resp.StatusCode, body)
	}
	// The same key and bundle return the same apply (JSON form, this time) and write nothing.
	docs, err := resource.ParseYAMLAll([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	resp, body = call(t, "POST", api+"/v1/apply", "alice-tok", map[string]any{"documents": docs, "plan": p.Fingerprint, "key": "deploy-1"}, nil)
	var again model.Apply
	_ = json.Unmarshal(body, &again)
	if resp.StatusCode != 200 || again.ID != a.ID {
		t.Fatalf("resubmit: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/environments/py/revisions", "alice-tok", nil, nil)
	var revs []model.CatalogItem
	_ = json.Unmarshal(body, &revs)
	if len(revs) != 1 {
		t.Fatalf("resubmit wrote: %d revisions", len(revs))
	}
	// Another bundle under the same key is a conflict carrying the existing apply.
	resp, body = call(t, "POST", api+"/v1/apply?plan=whatever&key=deploy-1", "alice-tok", strings.Replace(yaml, "stable", "stable, runtime_class: gvisor", 1), map[string]string{"Content-Type": "application/yaml"})
	if resp.StatusCode != 409 || !strings.Contains(string(body), "different bundle") || !strings.Contains(string(body), a.ID) {
		t.Fatalf("key reuse: %d %s", resp.StatusCode, body)
	}
	// Reads and isolation.
	if resp, _ := call(t, "GET", api+"/v1/applies/"+a.ID, "alice-tok", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("get: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "GET", api+"/v1/applies/"+a.ID, "bob-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("bob reading alice's apply: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/applies/"+a.ID+"/resume", "bob-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("bob resuming alice's apply: %d", resp.StatusCode)
	}
	resp, body = call(t, "GET", api+"/v1/applies", "alice-tok", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), a.ID) {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "GET", api+"/v1/applies?tenant=alice", "t0k", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), a.ID) {
		t.Fatalf("admin list: %d %s", resp.StatusCode, body)
	}
	// An invalid bundle answers 422 with the plan.
	if resp, body := call(t, "POST", api+"/v1/apply?plan=x", "alice-tok", "kind: EnvironmentProfile\nname: bad\nspec: {image: nope}\n", map[string]string{"Content-Type": "application/yaml"}); resp.StatusCode != 422 || !strings.Contains(string(body), `"invalid"`) {
		t.Fatalf("invalid: %d %s", resp.StatusCode, body)
	}
	// Resume of a finished apply is a no-op that returns it.
	resp, body = call(t, "POST", api+"/v1/applies/"+a.ID+"/resume", "alice-tok", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"status":"done"`) {
		t.Fatalf("resume done: %d %s", resp.StatusCode, body)
	}
}
