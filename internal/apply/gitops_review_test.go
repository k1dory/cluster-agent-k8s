package apply

import (
	"errors"
	"net/url"
	"testing"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

const gitopsReviewEnvironment = "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"

func TestReviewResumeRecognizesItsOwnCompletedCAS(t *testing.T) {
	ctx := t.Context()
	st := &faulty{Store: store.NewMemory(), failBefore: map[int]error{1: errors.New("temporary storage failure")}}
	c := controller(st, "review", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	input := "kind: EnvironmentProfile\nname: py\nexpected_revision: 0\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nexpected_revision: 0\nspec: {policy: backend-dev, environment: py}\n"
	a, err := c.Submit(ctx, planned(t, c, input, scope))
	if err != nil || a == nil || a.Status != model.ApplyFailed || a.Steps[0].Status != model.StepDone {
		t.Fatalf("setup partial apply: %v", err)
	}
	a, err = c.Resume(ctx, a.ID, scope)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != model.ApplyDone {
		t.Errorf("resume must accept the revision written by its own completed CAS: status=%s reason=%s", a.Status, a.Error)
	}
	for _, item := range [][2]string{{model.KindEnvironment, "py"}, {model.KindAgent, "backend"}} {
		if got := revisions(t, st, item[0], scope.Tenant, item[1]); got != 1 {
			t.Errorf("%s must have exactly one revision after resume: got %d", item[1], got)
		}
	}
}

func TestReviewPlanFingerprintBindsResolvedEnvironment(t *testing.T) {
	ctx := t.Context()
	st := store.NewMemory()
	c := controller(st, "review", pols("acme"))
	cat := &catalog.Service{Store: st, Images: images{}}
	if _, err := cat.Put(ctx, model.KindEnvironment, "", docs(t, gitopsReviewEnvironment)[0], true, "operator"); err != nil {
		t.Fatal(err)
	}
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	input := "kind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"
	req := planned(t, c, input, scope)
	// The reviewed plan selects shared/py. Before submission a local py appears;
	// the new plan would write a different canonical reference into the agent.
	if _, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, "kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n")[0], false, "alice"); err != nil {
		t.Fatal(err)
	}
	now, err := c.Planner.Plan(ctx, docs(t, input), scope)
	if err != nil {
		t.Fatal(err)
	}
	if now.Fingerprint == req.Plan {
		t.Error("plans writing shared/py and local py must have different state fingerprints")
	}
	if _, err := c.Submit(ctx, req); !errors.Is(err, ErrPlanMismatch) {
		t.Errorf("changed resolution must refuse the previously approved plan: got %v", err)
	}
	if got := revisions(t, st, model.KindAgent, "acme", "backend"); got != 0 {
		t.Errorf("a plan mismatch must not create the agent: got %d revisions", got)
	}
}

func TestReviewSourceStoresOnlyCredentialFreeRepositoryURL(t *testing.T) {
	ctx := t.Context()
	st := store.NewMemory()
	c := controller(st, "review", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	req := planned(t, c, gitopsReviewEnvironment, scope)
	remote := &url.URL{Scheme: "https", Host: "git.example.test", Path: "/team/config.git", User: url.UserPassword("fixture-user", "fixture-password")}
	req.Source = &model.Source{Repo: remote.String(), Path: "bundle.yaml"}
	a, err := c.Submit(ctx, req)
	if err != nil {
		if !errors.Is(err, res.ErrInvalid) {
			t.Fatal("credential-bearing provenance must be explicitly rejected or sanitized")
		}
		if n := revisions(t, st, model.KindEnvironment, "acme", "py"); n != 0 {
			t.Error("invalid provenance must be rejected before resource writes")
		}
		if records, readErr := st.ListApplies(ctx, scope.Tenant, 10); readErr != nil || len(records) != 0 {
			t.Error("invalid provenance must be rejected before persisting the apply record")
		}
		return
	}
	stored, err := st.GetApply(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	it := latest(t, st, model.KindEnvironment, "acme", "py")
	for name, source := range map[string]*model.Source{"apply record": stored.Source, "resource revision": it.Source} {
		if source == nil {
			continue
		}
		parsed, err := url.Parse(source.Repo)
		if err != nil || parsed.User != nil {
			t.Errorf("%s must not persist repository URL credentials", name)
		}
	}
}
