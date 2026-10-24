package plan

import (
	"fmt"
	"testing"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

func TestReviewPlanUsesHistoricalRevisionAfterRecreate(t *testing.T) {
	for _, revision := range []int{1, 2} {
		t.Run(fmt.Sprintf("pinned_%d", revision), func(t *testing.T) {
			st := store.NewMemory()
			d := deps(st)
			cat := catalogOver(st, d)
			env := "kind: EnvironmentProfile\nname: base\nspec: {image: stable}\n"
			if _, err := cat.Put(t.Context(), model.KindEnvironment, "acme", docs(t, env)[0], false, "alice"); err != nil {
				t.Fatal(err)
			}
			if err := cat.Delete(t.Context(), model.KindEnvironment, "acme", "base"); err != nil {
				t.Fatal(err)
			}
			bundle := env + fmt.Sprintf("---\nkind: AgentDefinition\nname: worker\nspec: {policy: backend-dev, environment: base@%d}\n", revision)
			p, err := d.Plan(t.Context(), docs(t, bundle), Scope{Tenant: "acme", Subject: "alice"})
			if err != nil {
				t.Fatal(err)
			}
			if want := revision == 2; p.Valid != want {
				t.Fatalf("recreated base will be revision 2; plan for base@%d valid=%v, want %v", revision, p.Valid, want)
			}
		})
	}
}

func TestReviewPlanNoopDoesNotCreateRevision(t *testing.T) {
	st := store.NewMemory()
	d := deps(st)
	cat := catalogOver(st, d)
	env := "kind: EnvironmentProfile\nname: base\nspec: {image: stable}\n"
	if _, err := cat.Put(t.Context(), model.KindEnvironment, "acme", docs(t, env)[0], false, "alice"); err != nil {
		t.Fatal(err)
	}
	bundle := env + "---\nkind: AgentDefinition\nname: worker\nspec: {policy: backend-dev, environment: base@2}\n"
	p, err := d.Plan(t.Context(), docs(t, bundle), Scope{Tenant: "acme", Subject: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Changes[0].Action != ActionNoop {
		t.Fatal("fixture: environment is unchanged")
	}
	if p.Valid {
		t.Fatal("plan accepted a reference to a revision that its noop action will not create")
	}
}
