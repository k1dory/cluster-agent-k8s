package plan

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/services"
	"agent-sandbox/internal/store"
)

type images struct{}

func (images) ResolveVersion(v string, admin bool) (string, error) {
	if v == "stable" || admin {
		return "registry/agent:1.0", nil
	}
	return "", errors.New("unknown version " + v)
}

func deps(st store.Catalog) Deps {
	pols := policy.FromPolicies(
		&policy.Policy{Slug: "backend-dev", Tenants: []string{"acme"}, Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}},
		&policy.Policy{Slug: "locked", Allow: []policy.Rule{{Host: "api.github.com", Paths: []string{"/**"}}}},
	)
	pols.Strict = true
	return Deps{Store: st, Policies: pols, Images: images{}, Secrets: secrets.Static{"acme/github": "x"}, Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
}

func catalogOver(st store.Catalog, d Deps) *catalog.Service {
	return &catalog.Service{Store: st, Images: d.Images, Policies: d.Policies}
}

func docs(t *testing.T, yaml string) []*res.Document {
	t.Helper()
	ds, err := res.ParseYAMLAll([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

const bundle = `
kind: AgentDefinition
name: backend
spec: {policy: backend-dev, environment: py, connections: [github]}
---
kind: Connection
name: github
spec: {type: http, host: api.github.com, headers: {Authorization: "Bearer secret:github"}}
---
kind: EnvironmentProfile
name: py
description: Python
spec: {image: stable, resources: {cpu_limit: "2"}}
`

func TestPlanValidatesTheBundleWithoutWriting(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := deps(st)
	scope := Scope{Tenant: "acme", Subject: "alice"}
	p, err := d.Plan(ctx, docs(t, bundle), scope)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Valid || p.Summary.Create != 3 || len(p.Changes) != 3 {
		t.Fatalf("fresh bundle: %+v", p)
	}
	// Apply order: environment, connection, agent; the agent validated against the bundle.
	if p.Changes[0].Kind != model.KindEnvironment || p.Changes[1].Kind != model.KindConnection || p.Changes[2].Kind != model.KindAgent {
		t.Fatalf("order: %+v", p.Changes)
	}
	if p.Changes[2].ExpectedRevision != 0 || len(p.Changes[2].Diff) == 0 {
		t.Fatalf("agent change: %+v", p.Changes[2])
	}
	for _, kind := range []string{model.KindEnvironment, model.KindConnection, model.KindAgent} {
		if list, _ := st.ListItems(ctx, kind, "acme"); len(list) != 0 {
			t.Fatalf("planning wrote %s items", kind)
		}
	}
	// Deterministic: the same bundle gives the same plan and fingerprint.
	again, _ := d.Plan(ctx, docs(t, bundle), scope)
	if !reflect.DeepEqual(p, again) {
		t.Fatalf("plan is not stable:\n%+v\n%+v", p, again)
	}
	// Apply the environment for real; the plan now updates it, and notices no-ops.
	env := docs(t, "kind: EnvironmentProfile\nname: py\ndescription: Python\nspec: {image: stable, resources: {cpu_limit: \"2\"}}\n")[0]
	cat := catalogOver(st, d)
	if _, err := cat.Put(ctx, model.KindEnvironment, "acme", env, false, "alice"); err != nil {
		t.Fatal(err)
	}
	p2, _ := d.Plan(ctx, docs(t, bundle), scope)
	if p2.Bundle != p.Bundle {
		t.Fatal("the fingerprint is the bundle's, not the state's")
	}
	if p2.Changes[0].Action != ActionNoop || p2.Changes[0].CurrentRevision != 1 || p2.Changes[0].ExpectedRevision != 1 || p2.Summary.Noop != 1 {
		t.Fatalf("existing environment: %+v", p2.Changes[0])
	}
	changed := strings.Replace(bundle, `cpu_limit: "2"`, `cpu_limit: "3", memory_limit: 4Gi`, 1)
	p3, _ := d.Plan(ctx, docs(t, changed), scope)
	c := p3.Changes[0]
	if c.Action != ActionUpdate || len(c.Diff) != 2 || c.Diff[0].Path != "spec.resources.cpu_limit" || c.Diff[0].From != "2" || c.Diff[0].To != "3" ||
		c.Diff[1].Path != "spec.resources.memory_limit" || c.Diff[1].From != nil || c.Diff[1].To != "4Gi" {
		t.Fatalf("diff: %+v", c)
	}
	// A stale expected_revision is a conflict; a matching one passes.
	stale := strings.Replace(changed, "description: Python\n", "description: Python\nexpected_revision: 3\n", 1)
	p4, _ := d.Plan(ctx, docs(t, stale), scope)
	if p4.Valid || p4.Changes[0].Action != ActionInvalid || !strings.Contains(p4.Changes[0].Errors[0], "expected_revision 3") {
		t.Fatalf("stale expectation: %+v", p4.Changes[0])
	}
	fresh := strings.Replace(changed, "description: Python\n", "description: Python\nexpected_revision: 1\n", 1)
	if p5, _ := d.Plan(ctx, docs(t, fresh), scope); !p5.Valid {
		t.Fatalf("matching expectation: %+v", p5)
	}
}

func TestPlanReportsEveryProblem(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := deps(st)
	bad := `
kind: AgentDefinition
name: a
spec: {policy: backend-dev, environment: missing}
---
kind: EnvironmentProfile
name: broken
spec: {image: stable, resources: {cpu_limit: "-1"}}
---
kind: EnvironmentProfile
name: broken
spec: {image: stable}
---
kind: PolicyBinding
name: backend-dev
spec: {}
---
kind: TenantSettings
spec: {quota: {max_sandboxes: 1}}
---
kind: Widget
name: w
spec: {}
---
name: nokind
spec: {}
---
kind: EnvironmentProfile
tenant: other
name: foreign
spec: {image: stable}
`
	p, err := d.Plan(ctx, docs(t, bad), Scope{Tenant: "acme", Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Valid || p.Summary.Invalid != 7 || p.Summary.Create != 1 || len(p.Errors) != 1 || !strings.Contains(p.Errors[0], "both describe") {
		t.Fatalf("problems: %+v", p)
	}
	want := map[string]string{
		"AgentDefinition|acme|a":           "missing",
		"EnvironmentProfile|acme|broken":   "must be positive",
		"PolicyBinding|acme|backend-dev":   "admin only",
		"TenantSettings|acme|settings":     "admin only",
		"Widget|acme|w":                    "unknown kind",
		"|acme|nokind":                     "kind is required",
		"EnvironmentProfile|other|foreign": "scoped to tenant",
	}
	got := map[string]string{}
	for _, c := range p.Changes {
		if len(c.Errors) > 0 {
			got[c.Kind+"|"+c.Tenant+"|"+c.Name] = strings.Join(c.Errors, "; ")
		}
	}
	for k, substr := range want {
		if !strings.Contains(got[k], substr) {
			t.Errorf("%s: want %q in %q", k, substr, got[k])
		}
	}
	// The admin plans the admin-only kinds, and settings in the same bundle confine the agent.
	adminBundle := `
kind: TenantSettings
tenant: acme
spec: {environments: ["shared/base"]}
---
kind: EnvironmentProfile
name: base
spec: {image: stable}
---
kind: EnvironmentProfile
tenant: acme
name: own
spec: {image: stable}
---
kind: AgentDefinition
tenant: acme
name: confined
spec: {policy: backend-dev, environment: own}
---
kind: AgentDefinition
tenant: acme
name: ok
spec: {policy: backend-dev, environment: base}
---
kind: PolicyBinding
tenant: bob
name: locked
spec: {max_sandboxes: 1}
---
kind: AgentDefinition
tenant: bob
name: bound
spec: {policy: locked, environment: shared/base}
`
	p, err = d.Plan(ctx, docs(t, adminBundle), Scope{Admin: true, Subject: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Change{}
	for _, c := range p.Changes {
		byName[c.Tenant+"/"+c.Name] = c
	}
	if byName["acme/confined"].Action != ActionInvalid || !strings.Contains(strings.Join(byName["acme/confined"].Errors, " "), "not allowed") {
		t.Fatalf("settings in the bundle must confine the agent: %+v", byName["acme/confined"])
	}
	if byName["acme/ok"].Action != ActionCreate || byName["bob/bound"].Action != ActionCreate || byName["/base"].Action != ActionCreate {
		t.Fatalf("admin bundle: %+v", p)
	}
	if byName["bob/bound"].Action != ActionCreate {
		t.Fatal("a binding in the bundle grants the slug to the agent in the same bundle")
	}
	// An invalid document is not a dependency others may rely on.
	chain := `
kind: EnvironmentProfile
name: bad
spec: {image: nope}
---
kind: AgentDefinition
name: dep
spec: {policy: backend-dev, environment: bad}
`
	p, _ = d.Plan(ctx, docs(t, chain), Scope{Tenant: "acme"})
	if p.Summary.Invalid != 2 {
		t.Fatalf("dependency on an invalid document: %+v", p)
	}
}

func TestOverlayNumbersPendingRevisions(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	it := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Spec: json.RawMessage(`{"image":"stable"}`)}
	_ = st.PutItem(ctx, it, -1)
	ov := &overlay{base: st, pending: map[string]*model.CatalogItem{
		"EnvironmentProfile|acme|py":  {Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Spec: json.RawMessage(`{"image":"canary"}`)},
		"EnvironmentProfile|acme|new": {Kind: model.KindEnvironment, Tenant: "acme", Name: "new", Spec: json.RawMessage(`{"image":"stable"}`)},
	}}
	if got, _ := ov.GetItem(ctx, model.KindEnvironment, "acme", "py", 0); got.Revision != 2 || !strings.Contains(string(got.Spec), "canary") {
		t.Fatalf("latest is the pending one: %+v", got)
	}
	if got, _ := ov.GetItem(ctx, model.KindEnvironment, "acme", "py", 1); got.Revision != 1 || strings.Contains(string(got.Spec), "canary") {
		t.Fatalf("pinned revision stays the stored one: %+v", got)
	}
	if got, _ := ov.GetItem(ctx, model.KindEnvironment, "acme", "py", 2); got == nil || got.Revision != 2 {
		t.Fatalf("the next revision is the pending one: %+v", got)
	}
	if list, _ := ov.ListItems(ctx, model.KindEnvironment, "acme"); len(list) != 2 || list[0].Name != "new" || list[0].Revision != 1 || list[1].Revision != 2 {
		t.Fatalf("list: %+v", list)
	}
	if err := ov.PutItem(ctx, it, -1); err == nil {
		t.Fatal("overlay must be read-only")
	}
}

// A bundle is checked by the same validators a PUT runs: a self-service MCP connection with
// upstream, paths and mcp is valid when the tenant's settings allow the host (even when the
// settings arrive in the same bundle), and a plain connection for a host nobody delegated is
// refused, exactly as the API refuses it.
func TestPlanValidatesConnectionsLikeThePUT(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := deps(st)
	mcp := "kind: Connection\nname: tools\nspec: {type: mcp, host: mcp.tools.example.com, upstream: \"https://10.0.0.5:8443\", paths: [\"/mcp\"], mcp: {read_only: true, tools: [\"get_*\"]}}\n"
	// Not delegated: both the self-service connection and a plain one for that host are invalid.
	p, err := d.Plan(ctx, docs(t, mcp), Scope{Tenant: "acme"})
	if err != nil || p.Valid || !strings.Contains(strings.Join(p.Changes[0].Errors, ";"), "neither served by the policy repository nor listed") {
		t.Fatalf("undelegated self-service host: %v %+v", err, p.Changes)
	}
	plain := "kind: Connection\nname: tools\nspec: {type: mcp, host: mcp.tools.example.com}\n"
	if p, _ := d.Plan(ctx, docs(t, plain), Scope{Tenant: "acme"}); p.Valid {
		t.Fatalf("a plain connection for an undelegated host passed the plan: %+v", p.Changes)
	}
	// A repository host takes headers only, in a bundle as in a PUT.
	if p, _ := d.Plan(ctx, docs(t, "kind: Connection\nname: gh\nspec: {type: http, host: api.github.com, upstream: \"https://evil\"}\n"), Scope{Tenant: "acme"}); p.Valid {
		t.Fatalf("upstream on a repository host passed the plan: %+v", p.Changes)
	}
	// Delegated in the same bundle (admin scope): the connection is valid.
	both := "kind: TenantSettings\ntenant: acme\nspec: {hosts: [mcp.tools.example.com]}\n---\nkind: Connection\ntenant: acme\nname: tools\nspec: {type: mcp, host: mcp.tools.example.com, upstream: \"https://10.0.0.5:8443\", paths: [\"/mcp\"], mcp: {read_only: true}}\n"
	p, err = d.Plan(ctx, docs(t, both), Scope{Admin: true})
	if err != nil || !p.Valid {
		t.Fatalf("settings and connection in one bundle: %v %+v", err, p.Changes)
	}
	// Delegated already in the store: the tenant's own bundle is valid.
	tset := services.Assemble(st, services.Options{Policies: d.Policies}).Tenants
	if _, err := tset.Put(ctx, "acme", &res.Document{Spec: json.RawMessage(`{"hosts":["mcp.tools.example.com"]}`)}, "admin"); err != nil {
		t.Fatal(err)
	}
	if p, err := d.Plan(ctx, docs(t, mcp), Scope{Tenant: "acme"}); err != nil || !p.Valid {
		t.Fatalf("delegated self-service host: %v %+v", err, p.Changes)
	}
}
