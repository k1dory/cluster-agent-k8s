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
		l.Env["ANTHROPIC_MODEL"] != "claude-opus-5-5" || l.Env["PIP_INDEX_URL"] != "https://pypi.example.com" || l.Env["ANTHROPIC_BASE_URL"] == "" ||
		l.Env["SANDBOX_INSTRUCTIONS"] != "Be brief." || l.CPULimit != "3" || *res.EnvSpec.Lifecycle.IdleTimeout != 600 || res.AgentSpec.Repo == "" {
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
	// Delete removes the whole history; shared items are not deletable from a tenant.
	if err := s.Delete(ctx, model.KindAgent, "acme", "generic"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant deleting a shared item: %v", err)
	}
	if err := s.Delete(ctx, model.KindAgent, "acme", "pinned"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, model.KindAgent, "acme", "pinned", 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("deleted item must be gone")
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

// TestShippedExamples: the declarative example files apply as they are.
func TestShippedExamples(t *testing.T) {
	s := newService()
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
	res, err := s.Resolve(ctx, "acme", "backend", false)
	if err != nil || res.Launch.Model != "claude-opus-5-5" || res.Launch.VolumeSize != "20Gi" || *res.EnvSpec.Lifecycle.IdleTimeout != 1800 || res.AgentSpec.Repo == "" {
		t.Fatalf("example resolve: %v %+v", err, res)
	}
}
