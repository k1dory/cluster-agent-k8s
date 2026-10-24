package apply

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/policy"
	"agent-sandbox/internal/store"
)

const reviewEnvironment = "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n"

func TestReviewResumeChecksDeletedHistory(t *testing.T) {
	ctx := t.Context()
	st := &faulty{Store: store.NewMemory(), failBefore: map[int]error{0: errors.New("temporary storage failure")}}
	c := controller(st, "review", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	a, err := c.Submit(ctx, planned(t, c, reviewEnvironment, scope))
	if err != nil || a.Status != model.ApplyFailed {
		t.Fatalf("setup failed apply: %v %+v", err, a)
	}
	cat := &catalog.Service{Store: st, Images: images{}}
	if _, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, reviewEnvironment)[0], false, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteItem(ctx, model.KindEnvironment, "acme", "py"); err != nil {
		t.Fatal(err)
	}
	a, err = c.Resume(ctx, a.ID, scope)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != model.ApplyConflict {
		t.Errorf("changed history must require a new plan: status=%s promised_revision=%d written_revision=%d", a.Status, a.Steps[0].NextRevision, a.Steps[0].Revision)
	}
	if n := revisions(t, st, model.KindEnvironment, "acme", "py"); n != 1 {
		t.Errorf("resume must not recreate the resource after its planned revision changed: %d revisions", n)
	}
}

func TestReviewSameKeySameDocumentsSurviveNewLocalDependency(t *testing.T) {
	ctx := t.Context()
	st := store.NewMemory()
	c := controller(st, "review", pols("acme"))
	cat := &catalog.Service{Store: st, Images: images{}}
	if _, err := cat.Put(ctx, model.KindEnvironment, "", docs(t, reviewEnvironment)[0], true, "operator"); err != nil {
		t.Fatal(err)
	}
	input := "kind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"
	req := planned(t, c, input, plan.Scope{Tenant: "acme", Subject: "alice"})
	req.Key = "review-same-documents"
	a, err := c.Submit(ctx, req)
	if err != nil || a.Status != model.ApplyDone {
		t.Fatalf("initial apply: %v %+v", err, a)
	}
	if _, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, "kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n")[0], false, "alice"); err != nil {
		t.Fatal(err)
	}
	// Each HTTP retry parses the same original body anew. A new local environment changes
	// resolution of the bare name, but it does not change the submitted documents or key.
	req.Docs = docs(t, input)
	again, err := c.Submit(ctx, req)
	if err != nil || again == nil || again.ID != a.ID || again.Status != model.ApplyDone {
		t.Fatalf("retry of identical documents and key must return apply %s: %v", a.ID, err)
	}
}

func TestReviewResumeRevalidatesCompletedDocuments(t *testing.T) {
	ctx := t.Context()
	st := &faulty{Store: store.NewMemory(), failBefore: map[int]error{2: errors.New("temporary storage failure")}}
	policies := func(allowBackend bool) *policy.Set {
		var tenants []string
		if allowBackend {
			tenants = []string{"acme"}
		}
		p := policy.FromPolicies(
			&policy.Policy{Slug: "backend-dev", Tenants: tenants},
			&policy.Policy{Slug: "worker-dev", Tenants: []string{"acme"}},
		)
		p.Strict = true
		return p
	}
	c := controller(st, "review", policies(true))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	input := reviewEnvironment + "---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n---\nkind: AgentDefinition\nname: worker\nspec: {policy: worker-dev, environment: py}\n"
	a, err := c.Submit(ctx, planned(t, c, input, scope))
	if err != nil || a.Status != model.ApplyFailed || a.Steps[1].Status != model.StepDone {
		t.Fatalf("setup partial apply: %v %+v", err, a)
	}
	c.Planner.Policies = policies(false)
	a, err = c.Resume(ctx, a.ID, scope)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != model.ApplyConflict {
		t.Errorf("a completed document no longer validates; resume must conflict: status=%s", a.Status)
	}
	if n := revisions(t, st, model.KindAgent, "acme", "worker"); n != 0 {
		t.Errorf("invalid stored bundle must stop before adding pending revisions: %d", n)
	}
}

// Pause each worker immediately before its transaction. Only the second worker's clock
// advances, modelling the first worker returning after its lease has expired.
type reviewPausedApplyStore struct {
	store.Store
	oneEntered, twoEntered   chan struct{}
	oneContinue, twoContinue chan struct{}
	oneOnce, twoOnce         sync.Once
}

func (s *reviewPausedApplyStore) ApplyStep(ctx context.Context, a *model.Apply, step int, it *model.CatalogItem, expected int) error {
	var wait <-chan struct{}
	switch a.LeaseOwner {
	case "one":
		s.oneOnce.Do(func() { close(s.oneEntered) })
		wait = s.oneContinue
	case "two":
		s.twoOnce.Do(func() { close(s.twoEntered) })
		wait = s.twoContinue
	}
	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Store.ApplyStep(ctx, a, step, it, expected)
}

func TestReviewExpiredWorkerCannotReleaseSuccessorsLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	st := &reviewPausedApplyStore{Store: store.NewMemory(), oneEntered: make(chan struct{}), twoEntered: make(chan struct{}), oneContinue: make(chan struct{}), twoContinue: make(chan struct{})}
	one, two := controller(st, "one", pols("acme")), controller(st, "two", pols("acme"))
	now := time.Now()
	one.Now = func() time.Time { return now }
	two.Now = func() time.Time { return now.Add(3 * time.Minute) }
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	req := planned(t, one, reviewEnvironment, scope)
	req.Key = "review-lease-transfer"
	type outcome struct {
		a   *model.Apply
		err error
	}
	first, second := make(chan outcome, 1), make(chan outcome, 1)
	go func() { a, err := one.Submit(ctx, req); first <- outcome{a, err} }()
	select {
	case <-st.oneEntered:
	case <-ctx.Done():
		t.Fatal("first worker did not reach its step")
	}
	a, err := st.GetApplyByKey(ctx, scope.Tenant, req.Key)
	if err != nil {
		t.Fatal(err)
	}
	go func() { a, err := two.Resume(ctx, a.ID, scope); second <- outcome{a, err} }()
	select {
	case <-st.twoEntered:
	case <-ctx.Done():
		t.Fatal("second worker did not acquire the expired lease")
	}
	held, err := st.GetApply(ctx, a.ID)
	if err != nil || held.LeaseOwner != "two" {
		t.Fatalf("second worker must hold the lease: %v %+v", err, held)
	}
	close(st.oneContinue)
	select {
	case <-first:
	case <-ctx.Done():
		t.Fatal("expired worker did not return")
	}
	current, err := st.GetApply(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.LeaseOwner != "two" || current.Status != model.ApplyRunning || current.Version != held.Version {
		t.Errorf("expired worker changed its successor's record: owner=%q status=%s version=%d (was %d)", current.LeaseOwner, current.Status, current.Version, held.Version)
	}
	close(st.twoContinue)
	select {
	case result := <-second:
		if result.err != nil || result.a == nil || result.a.Status != model.ApplyDone {
			t.Errorf("successor must finish after the old worker returns: %v %+v", result.err, result.a)
		}
	case <-ctx.Done():
		t.Fatal("second worker did not finish")
	}
}
