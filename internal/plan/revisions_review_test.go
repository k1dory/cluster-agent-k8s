package plan

import (
	"context"
	"strings"
	"testing"

	"agent-sandbox/internal/model"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// The plan predicts the revisions apply will produce: numbering continues past deleted
// revisions, and an unchanged document keeps its current revision, so pinned references in
// the same bundle are checked against what will really exist.
func TestPlanPredictsRealRevisions(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := deps(st)
	cat := catalogOver(st, d)
	env := docs(t, "kind: EnvironmentProfile\nname: base\nspec: {image: stable}\n")[0]
	if _, err := cat.Put(ctx, model.KindEnvironment, "acme", env, false, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, "kind: EnvironmentProfile\nname: base\nspec: {image: stable, runtime_class: gvisor}\n")[0], false, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := cat.Delete(ctx, model.KindEnvironment, "acme", "base"); err != nil {
		t.Fatal(err)
	}
	// Recreating base after deletion gives revision 3, not 1: an agent pinned to base@3 is
	// fine, one pinned to base@1 (deleted) is not.
	bundle := `
kind: EnvironmentProfile
name: base
spec: {image: stable}
---
kind: AgentDefinition
name: pinned-next
spec: {policy: backend-dev, environment: base@3}
---
kind: AgentDefinition
name: pinned-deleted
spec: {policy: backend-dev, environment: base@1}
`
	p, err := d.Plan(ctx, docs(t, bundle), Scope{Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]Change{}
	for _, c := range p.Changes {
		by[c.Name] = c
	}
	if by["base"].Action != ActionCreate || by["base"].CurrentRevision != 0 || by["base"].NextRevision != 3 {
		t.Fatalf("recreated item: %+v", by["base"])
	}
	if by["pinned-next"].Action != ActionCreate || by["pinned-deleted"].Action != ActionInvalid {
		t.Fatalf("pins after deletion: next=%+v deleted=%+v", by["pinned-next"], by["pinned-deleted"])
	}
	// Apply it for real: the revisions match the plan.
	it, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, "kind: EnvironmentProfile\nname: base\nspec: {image: stable}\n")[0], false, "alice")
	if err != nil || it.Revision != 3 {
		t.Fatalf("apply: %v %+v", err, it)
	}
	// Now base is unchanged by the bundle (noop): a pin to base@4 does not exist after apply;
	// base@3 does.
	bundle2 := `
kind: EnvironmentProfile
name: base
spec: {image: stable}
---
kind: AgentDefinition
name: pinned-noop
spec: {policy: backend-dev, environment: base@4}
---
kind: AgentDefinition
name: pinned-current
spec: {policy: backend-dev, environment: base@3}
`
	p, err = d.Plan(ctx, docs(t, bundle2), Scope{Tenant: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	by = map[string]Change{}
	for _, c := range p.Changes {
		by[c.Name] = c
	}
	if by["base"].Action != ActionNoop || by["base"].NextRevision != 3 {
		t.Fatalf("noop keeps its revision: %+v", by["base"])
	}
	if by["pinned-noop"].Action != ActionInvalid || !strings.Contains(strings.Join(by["pinned-noop"].Errors, " "), "base@4") {
		t.Fatalf("a pin to a revision apply will not produce must be refused: %+v", by["pinned-noop"])
	}
	if by["pinned-current"].Action != ActionCreate {
		t.Fatalf("pin to the current revision: %+v", by["pinned-current"])
	}
	// An update predicts the next number and a pin to it is accepted.
	bundle3 := strings.Replace(bundle2, "spec: {image: stable}\n---", "spec: {image: stable, runtime_class: gvisor}\n---", 1)
	p, _ = d.Plan(ctx, docs(t, bundle3), Scope{Tenant: "acme"})
	by = map[string]Change{}
	for _, c := range p.Changes {
		by[c.Name] = c
	}
	if by["base"].Action != ActionUpdate || by["base"].NextRevision != 4 || by["pinned-noop"].Action != ActionCreate {
		t.Fatalf("update predicts the next number: base=%+v pin=%+v", by["base"], by["pinned-noop"])
	}
	_ = res.ErrInvalid
}
