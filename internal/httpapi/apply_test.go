package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"agent-sandbox/internal/apply"
	"agent-sandbox/internal/drift"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/policy"
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

func TestDriftAndRollbackEndpoints(t *testing.T) {
	s, _ := configStack(t)
	api := s.platform.URL
	docs, err := resource.ParseYAMLAll([]byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"))
	if err != nil {
		t.Fatal(err)
	}
	resp, body := call(t, "POST", api+"/v1/plan", "alice-tok", map[string]any{"documents": docs}, nil)
	var p plan.Plan
	_ = json.Unmarshal(body, &p)
	if resp.StatusCode != 200 || !p.Valid {
		t.Fatalf("plan: %d %s", resp.StatusCode, body)
	}
	// Apply with a Git source: every written revision names the apply and the commit.
	sha := strings.Repeat("ab", 20)
	source := map[string]string{"repo": "git@example.com:acme/platform.git", "ref": "main", "commit": sha, "path": "bundles/alice.yaml"}
	resp, body = call(t, "POST", api+"/v1/apply", "alice-tok", map[string]any{"documents": docs, "plan": p.Fingerprint, "source": source}, nil)
	var a model.Apply
	_ = json.Unmarshal(body, &a)
	if resp.StatusCode != 200 || a.Status != model.ApplyDone || a.Source == nil || a.Source.Commit != sha || a.Source.Apply != a.ID {
		t.Fatalf("apply: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/environments/py", "alice-tok", nil, nil)
	var py model.CatalogItem
	_ = json.Unmarshal(body, &py)
	if resp.StatusCode != 200 || py.Source == nil || py.Source.Apply != a.ID || py.Source.Commit != sha || py.Source.Path != "bundles/alice.yaml" {
		t.Fatalf("revision source: %d %s", resp.StatusCode, body)
	}
	// The server boundary: a credential in the repository URL never reaches the record, and a
	// commit that is not an object name is refused before anything is written.
	leakyDocs, _ := resource.ParseYAMLAll([]byte("kind: EnvironmentProfile\nname: leaky\nspec: {image: stable}\n"))
	resp, body = call(t, "POST", api+"/v1/plan", "alice-tok", map[string]any{"documents": leakyDocs}, nil)
	_ = json.Unmarshal(body, &p)
	if resp, body := call(t, "POST", api+"/v1/apply", "alice-tok", map[string]any{"documents": leakyDocs, "plan": p.Fingerprint, "source": map[string]string{"commit": "ghp_notasha"}}, nil); resp.StatusCode != 400 {
		t.Fatalf("bad commit: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/environments/leaky", "alice-tok", nil, nil); resp.StatusCode != 404 {
		t.Fatal("a refused source wrote")
	}
	resp, body = call(t, "POST", api+"/v1/apply", "alice-tok", map[string]any{"documents": leakyDocs, "plan": p.Fingerprint, "source": map[string]string{"repo": "https://x-access-token:ghp_secret777@github.com/acme/platform.git", "commit": sha}}, nil)
	if resp.StatusCode != 200 || strings.Contains(string(body), "ghp_secret777") {
		t.Fatalf("credential in the apply record: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/environments/leaky/revisions", "alice-tok", nil, nil)
	if resp.StatusCode != 200 || strings.Contains(string(body), "ghp_secret777") || !strings.Contains(string(body), `"repo":"https://github.com/acme/platform.git"`) {
		t.Fatalf("credential in the revision history: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "GET", api+"/v1/applies", "alice-tok", nil, nil); strings.Contains(string(body), "ghp_secret777") {
		t.Fatalf("credential in the applies list: %d %s", resp.StatusCode, body)
	}
	// Nothing drifts yet.
	resp, body = call(t, "GET", api+"/v1/drift", "alice-tok", nil, nil)
	var rep drift.Report
	_ = json.Unmarshal(body, &rep)
	if resp.StatusCode != 200 || rep.Checked != 3 || len(rep.Drifted) != 0 {
		t.Fatalf("drift: %d %s", resp.StatusCode, body)
	}
	// A hand edit through the resource API is drift; another tenant does not see it.
	if code, _ := putDoc(t, api, "alice-tok", "environments", "py", `{"spec":{"image":"stable","runtime_class":"gvisor"}}`); code != 200 {
		t.Fatalf("manual edit: %d", code)
	}
	resp, body = call(t, "GET", api+"/v1/drift", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &rep)
	if resp.StatusCode != 200 || len(rep.Drifted) != 1 || rep.Drifted[0].State != drift.Changed || rep.Drifted[0].Name != "py" || rep.Drifted[0].Applied.Revision != 1 || rep.Drifted[0].Current.Revision != 2 || len(rep.Drifted[0].Diff) != 1 {
		t.Fatalf("drift after edit: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "GET", api+"/v1/drift", "bob-tok", nil, nil); resp.StatusCode != 200 || strings.Contains(string(body), `"py"`) {
		t.Fatalf("bob sees alice's drift: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, "GET", api+"/v1/drift?tenant=alice", "bob-tok", nil, nil); resp.StatusCode != 403 {
		t.Fatalf("bob reading alice's scope: %d", resp.StatusCode)
	}
	if resp, body := call(t, "GET", api+"/v1/drift?tenant=alice", "t0k", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), `"changed"`) {
		t.Fatalf("admin drift: %d %s", resp.StatusCode, body)
	}
	// Rollback of the item: dry run first, then for real. The restored revision is a new one.
	resp, body = call(t, "POST", api+"/v1/rollback", "alice-tok", map[string]any{"kind": model.KindEnvironment, "name": "py", "dry_run": true}, nil)
	var rb apply.Rollback
	_ = json.Unmarshal(body, &rb)
	if resp.StatusCode != 200 || rb.Apply != nil || rb.Plan == nil || !rb.Plan.Valid || rb.Plan.Changes[0].NextRevision != 3 {
		t.Fatalf("dry run: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "POST", api+"/v1/rollback", "alice-tok", map[string]any{"kind": model.KindEnvironment, "name": "py"}, nil)
	_ = json.Unmarshal(body, &rb)
	if resp.StatusCode != 200 || rb.Apply == nil || rb.Apply.Status != model.ApplyDone || rb.Target != "EnvironmentProfile alice/py@1" {
		t.Fatalf("rollback: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/environments/py", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &py)
	if py.Revision != 3 || strings.Contains(string(py.Spec), "gvisor") || py.Source == nil || py.Source.Rollback != rb.Target {
		t.Fatalf("restored: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, "GET", api+"/v1/drift", "alice-tok", nil, nil); resp.StatusCode != 200 || !strings.Contains(string(body), `"drifted":[]`) {
		t.Fatalf("drift after rollback: %d %s", resp.StatusCode, body)
	}
	// Rollback of an apply that only created things: 422 naming what it would not restore.
	if resp, body := call(t, "POST", api+"/v1/rollback", "alice-tok", map[string]any{"apply": a.ID}, nil); resp.StatusCode != 422 || !strings.Contains(string(body), "nothing_to_roll_back") || !strings.Contains(string(body), "created by "+a.ID) {
		t.Fatalf("creation rollback: %d %s", resp.StatusCode, body)
	}
	// Bad requests and isolation.
	if resp, _ := call(t, "POST", api+"/v1/rollback", "alice-tok", map[string]any{"apply": a.ID, "name": "py"}, nil); resp.StatusCode != 400 {
		t.Fatalf("ambiguous target: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/rollback", "alice-tok", `{"what": 1}`, nil); resp.StatusCode != 400 {
		t.Fatalf("unknown field: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/rollback", "bob-tok", map[string]any{"apply": a.ID}, nil); resp.StatusCode != 404 {
		t.Fatalf("bob rolling back alice's apply: %d", resp.StatusCode)
	}
	if resp, _ := call(t, "POST", api+"/v1/rollback", "bob-tok", map[string]any{"kind": model.KindEnvironment, "tenant": "alice", "name": "py"}, nil); resp.StatusCode != 403 {
		t.Fatalf("bob rolling back alice's item: %d", resp.StatusCode)
	}
	// A revoked right is never restored: a second bundle changes the environment and the
	// agent; after alice loses the policy, the agent revision its rollback would restore does
	// not validate, so the rollback plan is invalid and nothing is written.
	docs2, _ := resource.ParseYAMLAll([]byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable, runtime_class: gvisor}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py, repo: https://example.com/r.git}\n"))
	resp, body = call(t, "POST", api+"/v1/plan", "alice-tok", map[string]any{"documents": docs2}, nil)
	_ = json.Unmarshal(body, &p)
	resp, body = call(t, "POST", api+"/v1/apply", "alice-tok", map[string]any{"documents": docs2, "plan": p.Fingerprint}, nil)
	var v3 model.Apply
	_ = json.Unmarshal(body, &v3)
	if resp.StatusCode != 200 || v3.Status != model.ApplyDone || v3.Steps[0].Revision != 4 || v3.Steps[1].Revision != 2 {
		t.Fatalf("v3: %d %s", resp.StatusCode, body)
	}
	revoked := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}})
	revoked.Strict = true
	s.p.Applier.Planner.Policies = revoked
	resp, body = call(t, "POST", api+"/v1/rollback", "alice-tok", map[string]any{"apply": v3.ID}, nil)
	if resp.StatusCode != 422 || !strings.Contains(string(body), "invalid_plan") || !strings.Contains(string(body), "may not use policy") {
		t.Fatalf("rollback under revoked rights: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/environments/py", "alice-tok", nil, nil)
	_ = json.Unmarshal(body, &py)
	if py.Revision != 4 {
		t.Fatalf("a refused rollback wrote: %+v", py)
	}
	// With the right back, the same rollback restores both as new revisions.
	s.p.Applier.Planner.Policies = s.p.Policies
	resp, body = call(t, "POST", api+"/v1/rollback", "alice-tok", map[string]any{"apply": v3.ID}, nil)
	_ = json.Unmarshal(body, &rb)
	if resp.StatusCode != 200 || rb.Apply == nil || rb.Apply.Status != model.ApplyDone || len(rb.Apply.Steps) != 2 || rb.Apply.Steps[0].Revision != 5 || rb.Apply.Steps[1].Revision != 3 {
		t.Fatalf("rollback after restoring rights: %d %s", resp.StatusCode, body)
	}
}
