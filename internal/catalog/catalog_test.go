package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

type images struct{}

func (images) ResolveVersion(v string, admin bool) (string, error) {
	switch v {
	case "", "stable":
		return "registry/agent:1.0", nil
	case "canary":
		return "registry/agent:1.1", nil
	}
	if admin {
		return v, nil
	}
	return "", errors.New("unknown version " + v)
}

func newService() *Service {
	pols := policy.FromPolicies(
		&policy.Policy{Slug: "backend-dev", Tenants: []string{"acme"}, Allow: []policy.Rule{{Host: "h.example.com", Paths: []string{"/"}}}},
		&policy.Policy{Slug: "shared-agent", Tenants: []string{"*"}, Allow: []policy.Rule{{Host: "h.example.com", Paths: []string{"/"}}}},
	)
	return &Service{Store: store.NewMemory(), Images: images{}, Policies: pols}
}

func doc(t *testing.T, name, spec string, expected *int) *Document {
	t.Helper()
	return &Document{Name: name, Spec: json.RawMessage(spec), ExpectedRevision: expected}
}

func TestEnvironmentValidationAndRevisions(t *testing.T) {
	s := newService()
	ctx := context.Background()
	for _, bad := range []string{
		`{}`,
		`{"image":"stable","resources":{"cpu_limit":"two"}}`,
		`{"image":"stable","lifecycle":{"idle_timeout":-1}}`,
		`{"image":"stable","imag":"typo"}`,
		`{"image":"registry/evil:1"}`,
		`{"image":"stable","env":{"BAD KEY":"x"}}`,
		// Platform names are the platform's: not through env, not through model.env.
		`{"image":"stable","env":{"GATEWAY_IP":"192.0.2.1"}}`,
		`{"image":"stable","env":{"SANDBOX_TASK":"x"}}`,
		`{"image":"stable","model":{"env":{"API_URL":"https://evil"}}}`,
		// Resources: positive quantities, request within limit.
		`{"image":"stable","resources":{"cpu_limit":"-1"}}`,
		`{"image":"stable","resources":{"memory_request":"0"}}`,
		`{"image":"stable","resources":{"volume_size":"0Gi"}}`,
		`{"image":"stable","resources":{"cpu_request":"4","cpu_limit":"1"}}`,
		`{"image":"stable","resources":{"memory_request":"8Gi","memory_limit":"4Gi"}}`,
	} {
		if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "py", bad, nil), false, "alice"); err == nil || !errors.Is(err, ErrInvalid) {
			t.Errorf("must be invalid: %s → %v", bad, err)
		}
	}
	if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "Bad Name", `{"image":"stable"}`, nil), false, "alice"); err == nil {
		t.Fatal("name must be a label")
	}
	// The admin may name an image reference directly; a tenant may not.
	if _, err := s.Put(ctx, model.KindEnvironment, "", doc(t, "base", `{"image":"registry/custom:7"}`, nil), true, "admin"); err != nil {
		t.Fatal(err)
	}
	one := 1
	zero := 0
	it, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "py", `{"image":"stable","harness":{"command":"codex exec \"$SANDBOX_TASK\""},"resources":{"cpu_limit":"2","memory_limit":"4Gi"}}`, &zero), false, "alice")
	if err != nil || it.Revision != 1 || it.CreatedBy != "alice" {
		t.Fatalf("create: %v %+v", err, it)
	}
	if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "py", `{"image":"stable"}`, &zero), false, "alice"); !errors.Is(err, ErrConflict) {
		t.Fatalf("create-only on an existing item must conflict: %v", err)
	}
	// Two writers from the same base revision: one wins, the other must re-read.
	if it2, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "py", `{"image":"canary"}`, &one), false, "alice"); err != nil || it2.Revision != 2 {
		t.Fatalf("first writer: %v %+v", err, it2)
	}
	if _, err := s.Put(ctx, model.KindEnvironment, "acme", doc(t, "py", `{"image":"stable"}`, &one), false, "bob"); !errors.Is(err, ErrConflict) {
		t.Fatalf("second writer must conflict: %v", err)
	}
	latest, _ := s.Get(ctx, model.KindEnvironment, "acme", "py", 0)
	first, _ := s.Get(ctx, model.KindEnvironment, "acme", "py", 1)
	if latest.Revision != 2 || !strings.Contains(string(latest.Spec), "canary") || !strings.Contains(string(first.Spec), "codex") {
		t.Fatalf("revisions: %+v / %+v", latest, first)
	}
	revs, _ := s.Revisions(ctx, model.KindEnvironment, "acme", "py")
	if len(revs) != 2 {
		t.Fatalf("history: %d", len(revs))
	}
	// Listing from a tenant shows its own items plus the shared ones it does not shadow.
	items, _ := s.List(ctx, model.KindEnvironment, "acme")
	if len(items) != 2 {
		t.Fatalf("list: %+v", items)
	}
	items, _ = s.List(ctx, model.KindEnvironment, "other")
	if len(items) != 1 || items[0].Name != "base" {
		t.Fatalf("other tenant must see only shared: %+v", items)
	}
}

func TestAgentValidationIsolationAndResolve(t *testing.T) {
	s := newService()
	ctx := context.Background()
	mustPut := func(kind, tenant, name, spec string, admin bool) *model.CatalogItem {
		t.Helper()
		it, err := s.Put(ctx, kind, tenant, doc(t, name, spec, nil), admin, "t")
		if err != nil {
			t.Fatalf("put %s/%s/%s: %v", kind, tenant, name, err)
		}
		return it
	}
	mustPut(model.KindEnvironment, "acme", "py", `{"image":"stable","model":{"name":"claude-opus-5-5","env":{"ANTHROPIC_BASE_URL":"https://api.anthropic.com"}},"env":{"PIP_INDEX_URL":"https://pypi.example.com"},"lifecycle":{"idle_timeout":600,"ttl":3600},"resources":{"cpu_limit":"3"}}`, false)
	mustPut(model.KindEnvironment, "other", "secret-env", `{"image":"stable"}`, false)
	mustPut(model.KindEnvironment, "", "base", `{"image":"registry/custom:7","harness":{"command":"claude -p \"$SANDBOX_TASK\""}}`, true)

	for _, bad := range []struct {
		spec string
		want error
	}{
		{`{"policy":"backend-dev"}`, ErrInvalid},                            // no environment
		{`{"policy":"backend-dev","environment":"missing"}`, ErrInvalid},    // unknown environment
		{`{"policy":"backend-dev","environment":"secret-env"}`, ErrInvalid}, // another tenant's: invisible
		{`{"policy":"nope","environment":"py"}`, ErrInvalid},                // unknown policy
		{`{"policy":"backend-dev","environment":"py","connections":["Bad!"]}`, ErrInvalid},
		{`{"policy":"backend-dev","environment":"py","extra":1}`, ErrInvalid},
	} {
		if _, err := s.Put(ctx, model.KindAgent, "acme", doc(t, "a", bad.spec, nil), false, "t"); !errors.Is(err, bad.want) {
			t.Errorf("%s: got %v, want %v", bad.spec, err, bad.want)
		}
	}
	// A tenant cannot define an agent on a policy it does not own; the admin can.
	if _, err := s.Put(ctx, model.KindAgent, "other", doc(t, "a", `{"policy":"backend-dev","environment":"base"}`, nil), false, "t"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign policy: %v", err)
	}
	mustPut(model.KindAgent, "other", "granted", `{"policy":"backend-dev","environment":"base"}`, true)
	agent := mustPut(model.KindAgent, "acme", "backend", `{"policy":"backend-dev","environment":"py","repo":"https://git.example.com/org/shop.git","instructions":"Be brief."}`, false)
	pinned := mustPut(model.KindAgent, "acme", "pinned", `{"policy":"backend-dev","environment":"py@1"}`, false)
	shared := mustPut(model.KindAgent, "", "generic", `{"policy":"shared-agent","environment":"base"}`, true)

	// Resolve renders the launch from the environment at this moment.
	res, err := s.Resolve(ctx, "acme", "backend", false)
	if err != nil {
		t.Fatal(err)
	}
	l := res.Launch
	if res.Agent.Revision != agent.Revision || res.Environment.Revision != 1 || l.Image != "registry/agent:1.0" || l.Model != "claude-opus-5-5" ||
		l.Env["PIP_INDEX_URL"] != "https://pypi.example.com" || l.Env["ANTHROPIC_BASE_URL"] == "" || len(l.Env) != 2 ||
		l.Instructions != "Be brief." || l.CPULimit != "3" || *res.EnvSpec.Lifecycle.IdleTimeout != 600 || res.AgentSpec.Repo == "" {
		t.Fatalf("resolved launch: %+v env=%+v", l, res.EnvSpec)
	}
	// A new environment revision is picked up by an unpinned agent, not by a pinned one.
	mustPut(model.KindEnvironment, "acme", "py", `{"image":"canary"}`, false)
	if res, _ = s.Resolve(ctx, "acme", "backend", false); res.Environment.Revision != 2 || res.Launch.Image != "registry/agent:1.1" {
		t.Fatalf("unpinned agent must follow the latest environment: %+v", res.Launch)
	}
	if res, _ = s.Resolve(ctx, "acme", "pinned", false); res.Environment.Revision != 1 || res.Launch.Image != "registry/agent:1.0" {
		t.Fatalf("pinned agent must keep its environment revision: %+v", res.Launch)
	}
	if res, _ = s.Resolve(ctx, "acme", "backend@1", false); res.Agent.Revision != 1 {
		t.Fatal("agent@N pins the agent revision")
	}
	// Shared agent over a shared, admin-written environment keeps the admin's image choice.
	if res, err = s.Resolve(ctx, "acme", "generic", false); err != nil || res.Agent.Revision != shared.Revision || res.Launch.Image != "registry/custom:7" || res.Launch.HarnessCommand == "" {
		t.Fatalf("shared agent: %v %+v", err, res)
	}
	// Isolation: another tenant's agent is not found, by any name form.
	if _, err := s.Resolve(ctx, "acme", "granted", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign agent must be invisible: %v", err)
	}
	if _, err := s.Resolve(ctx, "acme", "pinned@9", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing revision: %v", err)
	}
	if _, err := s.Resolve(ctx, "acme", "Bad Ref", false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad ref: %v", err)
	}
	_ = pinned
	// Delete hides the item and keeps its history; shared items are not deletable from a tenant.
	if err := s.Delete(ctx, model.KindAgent, "acme", "generic"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant deleting a shared item: %v", err)
	}
	if err := s.Delete(ctx, model.KindAgent, "acme", "pinned"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, model.KindAgent, "acme", "pinned", 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted item must be gone")
	}
	if _, err := s.Get(ctx, model.KindAgent, "acme", "pinned", 1); !errors.Is(err, ErrNotFound) {
		t.Fatal("a deleted revision is not resolvable")
	}
	if err := s.Delete(ctx, model.KindAgent, "acme", "pinned"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if revs, err := s.Revisions(ctx, model.KindAgent, "acme", "pinned"); err != nil || len(revs) != 1 || revs[0].DeletedAt == nil {
		t.Fatalf("history survives deletion, marked: %v %+v", err, revs)
	}
	if list, _ := s.List(ctx, model.KindAgent, "acme"); len(list) != 2 { // backend + shared generic
		t.Fatalf("deleted items are not listed: %+v", list)
	}
	// Recreating the name is a create (expected 0 passes) and continues the numbering: "pinned@1"
	// never names the new content.
	zero := 0
	again, err := s.Put(ctx, model.KindAgent, "acme", doc(t, "pinned", `{"policy":"backend-dev","environment":"py"}`, &zero), false, "alice")
	if err != nil || again.Revision != 2 {
		t.Fatalf("recreate: %v %+v", err, again)
	}
	if _, err := s.Resolve(ctx, "acme", "pinned@1", false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the deleted revision stays unavailable: %v", err)
	}
	if res, err := s.Resolve(ctx, "acme", "pinned", false); err != nil || res.Agent.Revision != 2 || res.Environment.Revision != 2 {
		t.Fatalf("recreated agent: %v %+v", err, res)
	}
}

func TestReferencesFixTheirScope(t *testing.T) {
	s := newService()
	ctx := context.Background()
	mustPut := func(kind, tenant, name, spec string, admin bool) *model.CatalogItem {
		t.Helper()
		it, err := s.Put(ctx, kind, tenant, doc(t, name, spec, nil), admin, "x")
		if err != nil {
			t.Fatalf("%s %s/%s: %v", kind, tenant, name, err)
		}
		return it
	}
	mustPut(model.KindEnvironment, "", "base", `{"image":"stable"}`, true)
	// A bare name that resolves to the shared item is stored as shared/name.
	a := mustPut(model.KindAgent, "acme", "worker", `{"policy":"backend-dev","environment":"base@1"}`, false)
	var spec AgentSpec
	_ = json.Unmarshal(a.Spec, &spec)
	if spec.Environment != "shared/base@1" {
		t.Fatalf("stored reference must carry the scope: %q", spec.Environment)
	}
	// The explicit form is accepted as written; a tenant's own item stays bare.
	mustPut(model.KindAgent, "acme", "explicit", `{"policy":"backend-dev","environment":"shared/base"}`, false)
	mustPut(model.KindEnvironment, "acme", "own", `{"image":"canary"}`, false)
	o := mustPut(model.KindAgent, "acme", "local", `{"policy":"backend-dev","environment":"own"}`, false)
	_ = json.Unmarshal(o.Spec, &spec)
	if spec.Environment != "own" {
		t.Fatalf("own reference: %q", spec.Environment)
	}
	// shared/ never finds a tenant item, even one of that name.
	if _, err := s.Put(ctx, model.KindAgent, "acme", doc(t, "bad", `{"policy":"backend-dev","environment":"shared/own"}`, nil), false, "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("shared/own: %v", err)
	}
	// The tenant creating its own "base" afterwards does not capture the agents.
	mustPut(model.KindEnvironment, "acme", "base", `{"image":"canary"}`, false)
	for _, ref := range []string{"worker", "worker@1", "explicit"} {
		res, err := s.Resolve(ctx, "acme", ref, false)
		if err != nil || res.Environment.Tenant != "" || res.Launch.Image != "registry/agent:1.0" || res.EnvironmentRef != "shared/base" || res.AgentRef != ref[:len(res.Agent.Name)] {
			t.Fatalf("%s must keep the shared environment: %v %+v", ref, err, res)
		}
	}
	// A new agent written now resolves the bare name to the tenant's own item.
	n := mustPut(model.KindAgent, "acme", "fresh", `{"policy":"backend-dev","environment":"base"}`, false)
	_ = json.Unmarshal(n.Spec, &spec)
	if res, err := s.Resolve(ctx, "acme", "fresh", false); spec.Environment != "base" || err != nil || res.Environment.Tenant != "acme" || res.EnvironmentRef != "base" {
		t.Fatalf("fresh: %q %v %+v", spec.Environment, err, res)
	}
	// Shared agents are named shared/... from a tenant, and their sandboxes record that.
	mustPut(model.KindAgent, "", "generic", `{"policy":"shared-agent","environment":"base"}`, true)
	if res, err := s.Resolve(ctx, "acme", "shared/generic", false); err != nil || res.AgentRef != "shared/generic" || res.EnvironmentRef != "base" || res.Environment.Tenant != "" {
		t.Fatalf("shared agent: %v %+v", err, res)
	}
	if res, err := s.Resolve(ctx, "acme", "generic", false); err != nil || res.AgentRef != "shared/generic" {
		t.Fatalf("bare shared agent: %v %+v", err, res)
	}
}

func TestYAMLStream(t *testing.T) {
	docs, err := ParseYAMLAll([]byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n---\n---\nkind: AgentDefinition\nname: a\nspec: {policy: p, environment: py}\n"))
	if err != nil || len(docs) != 2 || docs[0].Name != "py" || docs[1].Kind != model.KindAgent {
		t.Fatalf("stream: %v %+v", err, docs)
	}
	if _, err := ParseYAMLAll([]byte("kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: a\nspec: {policy: p, environment: py}\nextra: 1\n")); err == nil || !strings.Contains(err.Error(), "document 2") {
		t.Fatalf("second document must be strict too: %v", err)
	}
	if _, err := ParseYAML([]byte("---\n")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty: %v", err)
	}
}

func TestYAMLDocument(t *testing.T) {
	d, err := ParseYAML([]byte("kind: EnvironmentProfile\nname: py\ndescription: Python\nspec:\n  image: stable\n  resources: { cpu_limit: \"2\" }\n"))
	if err != nil || d.Kind != model.KindEnvironment || d.Name != "py" || !strings.Contains(string(d.Spec), `"cpu_limit":"2"`) {
		t.Fatalf("yaml: %v %+v", err, d)
	}
	if _, err := ParseYAML([]byte("kind: EnvironmentProfile\nname: py\nspce: {}\n")); err == nil {
		t.Fatal("unknown top-level field must be refused")
	}
	s := newService()
	if _, err := s.Put(context.Background(), model.KindAgent, "acme", d, false, "t"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("kind mismatch must be refused: %v", err)
	}
}

// fakeConnections stands for the connections service: a fixed set of names per scope.
type fakeConnections map[string]bool // "tenant|name"

func (f fakeConnections) Canonical(_ context.Context, tenant, ref string) (string, error) {
	r, err := res.ParseRef(ref)
	if err != nil {
		return "", err
	}
	if !r.Shared && f[tenant+"|"+r.Name] {
		return r.Name, nil
	}
	if f["|"+r.Name] {
		return "shared/" + r.Name, nil
	}
	return "", store.ErrNotFound
}

type allowEnvs map[string][]string

func (a allowEnvs) EnvironmentAllowed(tenant, ref string) bool {
	list, ok := a[tenant]
	if !ok {
		return true
	}
	for _, e := range list {
		if e == ref {
			return true
		}
	}
	return false
}

func TestAgentConnectionsAndAllowedEnvironments(t *testing.T) {
	s := newService()
	ctx := context.Background()
	mustPut := func(kind, tenant, name, spec string, admin bool) *model.CatalogItem {
		t.Helper()
		it, err := s.Put(ctx, kind, tenant, doc(t, name, spec, nil), admin, "x")
		if err != nil {
			t.Fatalf("%s %s/%s: %v", kind, tenant, name, err)
		}
		return it
	}
	mustPut(model.KindEnvironment, "acme", "py", `{"image":"stable"}`, false)
	mustPut(model.KindEnvironment, "", "base", `{"image":"stable"}`, true)
	// Without a connections service, agents may not name connections at all.
	if _, err := s.Put(ctx, model.KindAgent, "acme", doc(t, "a", `{"policy":"backend-dev","environment":"py","connections":["github"]}`, nil), false, "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("connections disabled: %v", err)
	}
	s.Connections = fakeConnections{"acme|github": true, "|registry": true, "other|private": true}
	for _, bad := range []string{`["private"]`, `["missing"]`, `["github","github"]`, `["registry","shared/registry"]`, `["Bad Name"]`} {
		if _, err := s.Put(ctx, model.KindAgent, "acme", doc(t, "a", `{"policy":"backend-dev","environment":"py","connections":`+bad+`}`, nil), false, "x"); !errors.Is(err, ErrInvalid) {
			t.Errorf("connections %s must be invalid: %v", bad, err)
		}
	}
	a := mustPut(model.KindAgent, "acme", "a", `{"policy":"backend-dev","environment":"py","connections":["github","registry"]}`, false)
	var spec AgentSpec
	_ = json.Unmarshal(a.Spec, &spec)
	if len(spec.Connections) != 2 || spec.Connections[0] != "github" || spec.Connections[1] != "shared/registry" {
		t.Fatalf("stored connections must be canonical: %v", spec.Connections)
	}
	// Tenant settings confine the environments: at write time and again at resolve time.
	s.Tenants = allowEnvs{"acme": {"shared/base"}}
	if _, err := s.Put(ctx, model.KindAgent, "acme", doc(t, "b", `{"policy":"backend-dev","environment":"py"}`, nil), false, "x"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("disallowed environment at write: %v", err)
	}
	mustPut(model.KindAgent, "acme", "c", `{"policy":"backend-dev","environment":"base"}`, false)
	if _, err := s.Resolve(ctx, "acme", "a", false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an agent written before the restriction loses the environment: %v", err)
	}
	if r, err := s.Resolve(ctx, "acme", "c", false); err != nil || r.EnvironmentRef != "shared/base" {
		t.Fatalf("allowed: %v %+v", err, r)
	}
	// The admin's shared agents and the admin's own writes are not confined.
	mustPut(model.KindAgent, "", "generic", `{"policy":"shared-agent","environment":"base"}`, true)
}

// TestShippedExamples: the declarative example files apply as they are.
func TestShippedExamples(t *testing.T) {
	s := newService()
	s.Connections = fakeConnections{"acme|github": true}
	ctx := context.Background()
	for _, f := range []string{"../../examples/catalog/environment-python.yaml", "../../examples/catalog/agent-backend.yaml"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		d, err := ParseYAML(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if _, err := s.Put(ctx, d.Kind, "acme", d, false, "ci"); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	r, err := s.Resolve(ctx, "acme", "backend", false)
	if err != nil || r.Launch.Model != "claude-opus-5-5" || r.Launch.VolumeSize != "20Gi" || *r.EnvSpec.Lifecycle.IdleTimeout != 1800 || r.AgentSpec.Repo == "" || len(r.AgentSpec.Connections) != 1 {
		t.Fatalf("example resolve: %v %+v", err, r)
	}
}
