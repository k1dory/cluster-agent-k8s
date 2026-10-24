package apply

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// hooked lets a test run code right before a replica's ApplyStep of a given step.
type hooked struct {
	store.Store
	mu     sync.Mutex
	before map[int]func()
}

func (h *hooked) ApplyStep(ctx context.Context, a *model.Apply, step int, it *model.CatalogItem, expected int) error {
	h.mu.Lock()
	f := h.before[step]
	delete(h.before, step)
	h.mu.Unlock()
	if f != nil {
		f()
	}
	return h.Store.ApplyStep(ctx, a, step, it, expected)
}

// A worker whose lease lapsed and was taken over by another replica must not touch the record
// again: neither mark it conflict nor release the successor's lease.
func TestLostLeaseWorkerLeavesTheSuccessorAlone(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	two := controller(mem, "two", pols("acme"))
	st := &hooked{Store: mem, before: map[int]func(){}}
	one := controller(st, "one", pols("acme"))
	one.Lease = time.Millisecond
	req := planned(t, one, bundle, scope)
	var takenOver *model.Apply
	st.before[1] = func() {
		// Replica one stalls; its lease lapses and replica two finishes the apply.
		time.Sleep(5 * time.Millisecond)
		a, err := two.Submit(ctx, req)
		if err != nil || a.Status != model.ApplyDone {
			t.Errorf("successor: %v %+v", err, a)
		}
		takenOver = a
	}
	got, err := one.Submit(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	final, _ := mem.GetApply(ctx, got.ID)
	if final.Status != model.ApplyDone || final.Attempt != takenOver.Attempt || final.LeaseOwner != "" {
		t.Fatalf("the lost worker changed the successor's record: %+v", final)
	}
	if got.Status != model.ApplyDone {
		t.Fatalf("the lost worker must report what the record says: %+v", got)
	}
	for _, item := range []string{"backend", "worker"} {
		if revisions(t, mem, model.KindAgent, "acme", item) != 1 {
			t.Fatalf("%s written twice", item)
		}
	}
}

// An applied document that no longer validates stops the apply even when the pending steps
// would still be fine.
func TestAppliedStepsAreRevalidatedOnResume(t *testing.T) {
	ctx := context.Background()
	st := &faulty{Store: store.NewMemory(), failBefore: map[int]error{2: errors.New("boom")}, failAfter: map[int]error{}}
	p := pols("acme")
	c := controller(st, "r1", p)
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	three := bundle + "---\nkind: EnvironmentProfile\nname: extra\nspec: {image: stable}\n"
	// Order: environments (extra, py) then agents (backend, worker): step index 2 is backend.
	a, err := c.Submit(ctx, planned(t, c, three, scope))
	if err != nil || a.Status != model.ApplyFailed || a.Steps[2].Name != "backend" {
		t.Fatalf("setup: %v %+v", err, a)
	}
	// backend is now applied by a retry, worker remains pending... first finish backend only.
	st.failBefore[3] = errors.New("boom again")
	if a, err = c.Resume(ctx, a.ID, scope); err != nil || a.Status != model.ApplyFailed || a.Steps[2].Status != model.StepDone || a.Steps[3].Status != model.StepFailed {
		t.Fatalf("second attempt: %v %+v", err, a)
	}
	// acme loses the policy: the applied backend no longer validates, and so must the resume
	// report, not finish on the remaining environment-only work.
	c.Planner.Policies = pols()
	// Make the pending agent moot by giving it something that validates regardless: not
	// possible for an agent, so check that the error names the applied one first.
	a, err = c.Resume(ctx, a.ID, scope)
	if err != nil || a.Status != model.ApplyConflict || !strings.Contains(a.Error, "backend") || !strings.Contains(a.Error, "no longer validates") {
		t.Fatalf("applied document must be re-validated: %v %+v", err, a)
	}
}

// Resume refuses a step whose promised revision moved because the item's history changed
// (created and deleted since the plan), and the store refuses the write at the last moment too.
func TestResumeChecksPromisedRevisions(t *testing.T) {
	ctx := context.Background()
	st := &faulty{Store: store.NewMemory(), failBefore: map[int]error{1: errors.New("boom")}, failAfter: map[int]error{}}
	c := controller(st, "r1", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	a, _ := c.Submit(ctx, planned(t, c, bundle, scope))
	cat := &catalog.Service{Store: st, Images: images{}, Policies: pols("acme")}
	if _, err := cat.Put(ctx, model.KindAgent, "acme", docs(t, "kind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n")[0], false, "mallory"); err != nil {
		t.Fatal(err)
	}
	if err := cat.Delete(ctx, model.KindAgent, "acme", "backend"); err != nil {
		t.Fatal(err)
	}
	// Live state looks as planned (absent), but the next revision is 2, not the promised 1.
	a, err := c.Resume(ctx, a.ID, scope)
	if err != nil || a.Status != model.ApplyConflict || !strings.Contains(a.Error, "history changed") {
		t.Fatalf("history conflict expected: %v %+v", err, a)
	}
	if revisions(t, st, model.KindAgent, "acme", "backend") != 1 {
		t.Fatal("the conflict must not write")
	}
	// Store level: a step whose promised revision cannot be honoured is refused, nothing written.
	mem := store.NewMemory()
	rec := &model.Apply{ID: "apply_h", Key: "k", Tenant: "acme", Status: model.ApplyRunning, Documents: json.RawMessage(`[]`),
		Steps: []model.ApplyStep{{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Action: plan.ActionCreate, ExpectedRevision: 0, NextRevision: 1, Status: model.StepDone}}}
	if err := mem.CreateApply(ctx, rec); err != nil {
		t.Fatal(err)
	}
	_ = mem.PutItem(ctx, &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Spec: json.RawMessage(`{}`)}, -1)
	_ = mem.DeleteItem(ctx, model.KindEnvironment, "acme", "py")
	it := &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Spec: json.RawMessage(`{"image":"stable"}`)}
	if err := mem.ApplyStep(ctx, rec, 0, it, 0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("promised revision 1, would write 2: %v", err)
	}
	if revs, _ := mem.ListRevisions(ctx, model.KindEnvironment, "acme", "py"); len(revs) != 1 {
		t.Fatalf("refused step wrote: %d revisions", len(revs))
	}
	// A noop step confirms the revision atomically: a stale expectation is refused.
	rec2 := &model.Apply{ID: "apply_n", Key: "k2", Tenant: "acme", Status: model.ApplyRunning, Documents: json.RawMessage(`[]`),
		Steps: []model.ApplyStep{{Kind: model.KindEnvironment, Tenant: "acme", Name: "live", Action: plan.ActionNoop, ExpectedRevision: 1, NextRevision: 1, Status: model.StepSkipped}}}
	_ = mem.CreateApply(ctx, rec2)
	_ = mem.PutItem(ctx, &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "live", Spec: json.RawMessage(`{}`)}, -1)
	_ = mem.PutItem(ctx, &model.CatalogItem{Kind: model.KindEnvironment, Tenant: "acme", Name: "live", Spec: json.RawMessage(`{"a":1}`)}, -1)
	if err := mem.ApplyStep(ctx, rec2, 0, nil, 1); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("noop with a stale revision: %v", err)
	}
	if got, _ := mem.GetApply(ctx, rec2.ID); got.Steps[0].Status != model.StepSkipped || got.Version != 1 {
		t.Fatalf("refused noop recorded progress: %+v", got)
	}
	if err := mem.ApplyStep(ctx, rec2, 0, nil, 2); err != nil || rec2.Steps[0].Revision != 2 {
		t.Fatalf("noop at the right revision: %v %+v", err, rec2.Steps[0])
	}
}

// The idempotency key keeps matching the same request even when a reference now resolves to
// another item (a local environment shadowing the shared one the first apply used).
func TestKeyMatchesTheRequestNotItsResolution(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	p := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Tenants: []string{"acme"}, Allow: []policy.Rule{{Host: "h.example.com", Paths: []string{"/"}}}})
	p.Strict = true
	c := controller(st, "r1", p)
	cat := &catalog.Service{Store: st, Images: images{}, Policies: p}
	if _, err := cat.Put(ctx, model.KindEnvironment, "", docs(t, "kind: EnvironmentProfile\nname: base\nspec: {image: stable}\n")[0], true, "admin"); err != nil {
		t.Fatal(err)
	}
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	agent := "kind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: base}\n"
	req := planned(t, c, agent, scope)
	req.Key = "deploy-7"
	a, err := c.Submit(ctx, req)
	if err != nil || a.Status != model.ApplyDone {
		t.Fatalf("first: %v %+v", err, a)
	}
	// The tenant now has its own base: the same documents resolve differently.
	if _, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, "kind: EnvironmentProfile\nname: base\nspec: {image: canary}\n")[0], false, "alice"); err != nil {
		t.Fatal(err)
	}
	again, err := c.Submit(ctx, Request{Docs: docs(t, agent), Plan: req.Plan, Key: "deploy-7", Scope: scope})
	if err != nil || again.ID != a.ID || again.Status != model.ApplyDone {
		t.Fatalf("same request and key must return the same apply: %v %+v", err, again)
	}
	if revisions(t, st, model.KindAgent, "acme", "backend") != 1 {
		t.Fatal("nothing written on the repeat")
	}
	_ = res.ErrInvalid
}
