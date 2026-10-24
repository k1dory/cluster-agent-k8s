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

type images struct{}

func (images) ResolveVersion(v string, admin bool) (string, error) {
	if v == "stable" || v == "canary" || admin {
		return "registry/agent:" + v, nil
	}
	return "", errors.New("unknown version " + v)
}

// faulty injects failures into ApplyStep: before the write (nothing happens) or after it
// (the write commits, the acknowledgement is lost).
type faulty struct {
	store.Store
	mu          sync.Mutex
	failBefore  map[int]error // step → error returned instead of writing
	failAfter   map[int]error // step → error returned after writing
	applySteps  int
	putsWrapped int
}

func (f *faulty) ApplyStep(ctx context.Context, a *model.Apply, step int, it *model.CatalogItem, expected int) error {
	f.mu.Lock()
	before, after := f.failBefore[step], f.failAfter[step]
	delete(f.failBefore, step)
	delete(f.failAfter, step)
	f.applySteps++
	f.mu.Unlock()
	if before != nil {
		return before
	}
	err := f.Store.ApplyStep(ctx, a, step, it, expected)
	if err == nil && after != nil {
		return after
	}
	return err
}

func pols(allowed ...string) *policy.Set {
	p := policy.FromPolicies(&policy.Policy{Slug: "backend-dev", Tenants: allowed, Allow: []policy.Rule{{Host: "h.example.com", Paths: []string{"/"}}}})
	p.Strict = true
	return p
}

func controller(st store.Store, replica string, p *policy.Set) *Controller {
	return &Controller{Store: st, Planner: plan.Deps{Store: st, Policies: p, Images: images{}}, Replica: replica}
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
kind: EnvironmentProfile
name: py
spec: {image: stable}
---
kind: AgentDefinition
name: backend
spec: {policy: backend-dev, environment: py}
---
kind: AgentDefinition
name: worker
spec: {policy: backend-dev, environment: py@1}
`

func planned(t *testing.T, c *Controller, yaml string, scope plan.Scope) Request {
	t.Helper()
	ds := docs(t, yaml)
	p, err := c.Planner.Plan(context.Background(), ds, scope)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Docs: ds, Plan: p.Fingerprint, Scope: scope}
}

func revisions(t *testing.T, st store.Catalog, kind, tenant, name string) int {
	t.Helper()
	revs, err := st.ListRevisions(context.Background(), kind, tenant, name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	return len(revs)
}

func TestApplyIsIdempotentAndBoundToThePlan(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	c := controller(st, "r1", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	// Without a matching plan fingerprint nothing is applied.
	if _, err := c.Submit(ctx, Request{Docs: docs(t, bundle), Plan: "stale", Scope: scope}); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("stale plan: %v", err)
	}
	if revisions(t, st, model.KindEnvironment, "acme", "py") != 0 {
		t.Fatal("a mismatched plan must not write")
	}
	// An invalid bundle is refused with its plan.
	var invalid *InvalidPlan
	if _, err := c.Submit(ctx, Request{Docs: docs(t, "kind: EnvironmentProfile\nname: bad\nspec: {image: nope}\n"), Plan: "x", Scope: scope}); !errors.As(err, &invalid) || invalid.Plan.Summary.Invalid != 1 {
		t.Fatalf("invalid bundle: %v", err)
	}
	req := planned(t, c, bundle, scope)
	a, err := c.Submit(ctx, req)
	if err != nil || a.Status != model.ApplyDone || len(a.Steps) != 3 {
		t.Fatalf("apply: %v %+v", err, a)
	}
	for i, st := range a.Steps {
		if st.Status != model.StepDone || st.Revision != 1 {
			t.Fatalf("step %d: %+v", i, st)
		}
	}
	if a.Key != req.Plan || a.LeaseOwner != "" {
		t.Fatalf("key defaults to the plan fingerprint and the lease is released: %+v", a)
	}
	// The same submission again returns the same apply and writes nothing more.
	again, err := c.Submit(ctx, req)
	if err != nil || again.ID != a.ID || again.Status != model.ApplyDone {
		t.Fatalf("resubmit: %v %+v", err, again)
	}
	if revisions(t, st, model.KindEnvironment, "acme", "py") != 1 || revisions(t, st, model.KindAgent, "acme", "backend") != 1 {
		t.Fatal("resubmitting must not write")
	}
	// The same bundle planned again is a noop plan with its own fingerprint: applying it skips
	// every step and confirms the revisions.
	req2 := planned(t, c, bundle, scope)
	if req2.Plan == req.Plan {
		t.Fatal("the fingerprint follows the state")
	}
	a2, err := c.Submit(ctx, req2)
	if err != nil || a2.ID == a.ID || a2.Status != model.ApplyDone || a2.Steps[0].Status != model.StepSkipped || a2.Steps[0].Revision != 1 {
		t.Fatalf("noop apply: %v %+v", err, a2)
	}
	// The key reused for another bundle is a conflict.
	other := planned(t, c, strings.Replace(bundle, "image: stable", "image: canary", 1), scope)
	other.Key = req.Plan
	if got, err := c.Submit(ctx, other); !errors.Is(err, ErrKeyReused) || got == nil || got.ID != a.ID {
		t.Fatalf("key reuse: %v %+v", err, got)
	}
	// A tenant cannot see or resume another tenant's apply; the admin can.
	if _, err := c.Get(ctx, a.ID, plan.Scope{Tenant: "bob"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("isolation: %v", err)
	}
	if got, err := c.Get(ctx, a.ID, plan.Scope{Admin: true}); err != nil || got.ID != a.ID {
		t.Fatalf("admin view: %v", err)
	}
}

func TestFailureBeforeAndAfterCommit(t *testing.T) {
	ctx := context.Background()
	for _, after := range []bool{false, true} {
		name := "before_commit"
		if after {
			name = "after_commit"
		}
		t.Run(name, func(t *testing.T) {
			st := &faulty{Store: store.NewMemory(), failBefore: map[int]error{}, failAfter: map[int]error{}}
			boom := errors.New("database went away")
			if after {
				st.failAfter[1] = boom
			} else {
				st.failBefore[1] = boom
			}
			c := controller(st, "r1", pols("acme"))
			scope := plan.Scope{Tenant: "acme", Subject: "alice"}
			req := planned(t, c, bundle, scope)
			a, err := c.Submit(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if after {
				// The write committed; the lost acknowledgement must not undo it or redo it.
				if a.Status != model.ApplyDone {
					t.Fatalf("after-commit failure: %+v", a)
				}
			} else {
				if a.Status != model.ApplyFailed || a.Steps[0].Status != model.StepDone || a.Steps[1].Status != model.StepFailed || a.Steps[2].Status != model.StepPending || !strings.Contains(a.Error, "step 2") {
					t.Fatalf("before-commit failure: %+v", a)
				}
				if revisions(t, st, model.KindAgent, "acme", "backend") != 0 {
					t.Fatal("a step that failed before its commit wrote nothing")
				}
				// Partial application is visible; resume finishes from the failed step.
				stored, _ := st.GetApply(ctx, a.ID)
				if stored.Status != model.ApplyFailed || stored.Steps[0].Revision != 1 {
					t.Fatalf("stored record: %+v", stored)
				}
				a, err = c.Resume(ctx, a.ID, scope)
				if err != nil || a.Status != model.ApplyDone {
					t.Fatalf("resume: %v %+v", err, a)
				}
			}
			for _, item := range []string{"backend", "worker"} {
				if revisions(t, st, model.KindAgent, "acme", item) != 1 {
					t.Fatalf("%s must have exactly one revision", item)
				}
			}
			if revisions(t, st, model.KindEnvironment, "acme", "py") != 1 {
				t.Fatal("py must have exactly one revision")
			}
		})
	}
}

func TestAnotherReplicaContinuesAndLeasesAreHonoured(t *testing.T) {
	ctx := context.Background()
	mem := store.NewMemory()
	st := &faulty{Store: mem, failBefore: map[int]error{1: errors.New("replica one died")}, failAfter: map[int]error{}}
	one := controller(st, "one", pols("acme"))
	two := controller(mem, "two", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	req := planned(t, one, bundle, scope)
	a, err := one.Submit(ctx, req)
	if err != nil || a.Status != model.ApplyFailed {
		t.Fatalf("first replica: %v %+v", err, a)
	}
	// Replica one is still holding the lease (it crashed before releasing it).
	until := time.Now().Add(time.Minute)
	a.LeaseOwner, a.LeaseUntil, a.Status = "one", &until, model.ApplyRunning
	if err := mem.UpdateApply(ctx, a); err != nil {
		t.Fatal(err)
	}
	held, err := two.Submit(ctx, req)
	if err != nil || held.Status != model.ApplyRunning || held.Steps[1].Status != model.StepFailed {
		t.Fatalf("a live lease elsewhere is respected: %v %+v", err, held)
	}
	// The lease lapses: the second replica continues from the record.
	past := time.Now().Add(-time.Second)
	held.LeaseUntil = &past
	if err := mem.UpdateApply(ctx, held); err != nil {
		t.Fatal(err)
	}
	done, err := two.Submit(ctx, req)
	if err != nil || done.Status != model.ApplyDone || done.ID != a.ID {
		t.Fatalf("second replica: %v %+v", err, done)
	}
	if revisions(t, mem, model.KindAgent, "acme", "backend") != 1 || revisions(t, mem, model.KindEnvironment, "acme", "py") != 1 {
		t.Fatal("nothing written twice")
	}
}

func TestParallelSubmissionsApplyOnce(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	c := controller(st, "r1", pols("acme"))
	req := planned(t, c, bundle, scope)
	const n = 8
	var wg sync.WaitGroup
	results := make(chan *model.Apply, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ci := controller(st, "replica-"+string(rune('a'+i)), pols("acme"))
			a, err := ci.Submit(ctx, req)
			if err != nil {
				t.Error(err)
				return
			}
			results <- a
		}(i)
	}
	wg.Wait()
	close(results)
	ids := map[string]bool{}
	for a := range results {
		ids[a.ID] = true
	}
	if len(ids) != 1 {
		t.Fatalf("one apply expected, got %d", len(ids))
	}
	for id := range ids {
		final, _ := st.GetApply(ctx, id)
		if final.Status != model.ApplyDone {
			t.Fatalf("final status: %+v", final)
		}
	}
	for _, item := range [][2]string{{model.KindEnvironment, "py"}, {model.KindAgent, "backend"}, {model.KindAgent, "worker"}} {
		if revisions(t, st, item[0], "acme", item[1]) != 1 {
			t.Fatalf("%s written more than once", item[1])
		}
	}
}

func TestResumeChecksStateAndRights(t *testing.T) {
	ctx := context.Background()
	t.Run("applied_item_changed_outside", func(t *testing.T) {
		st := &faulty{Store: store.NewMemory(), failBefore: map[int]error{1: errors.New("boom")}, failAfter: map[int]error{}}
		c := controller(st, "r1", pols("acme"))
		scope := plan.Scope{Tenant: "acme", Subject: "alice"}
		a, _ := c.Submit(ctx, planned(t, c, bundle, scope))
		cat := &catalog.Service{Store: st, Images: images{}}
		if _, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, "kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n")[0], false, "mallory"); err != nil {
			t.Fatal(err)
		}
		a, err := c.Resume(ctx, a.ID, scope)
		if err != nil || a.Status != model.ApplyConflict || !strings.Contains(a.Error, "changed outside this apply") || !strings.Contains(a.Error, "revision 2") {
			t.Fatalf("conflict expected: %v %+v", err, a)
		}
		if revisions(t, st, model.KindAgent, "acme", "backend") != 0 {
			t.Fatal("a conflict stops the apply before writing more")
		}
	})
	t.Run("pending_item_changed_outside", func(t *testing.T) {
		st := &faulty{Store: store.NewMemory(), failBefore: map[int]error{1: errors.New("boom")}, failAfter: map[int]error{}}
		c := controller(st, "r1", pols("acme"))
		scope := plan.Scope{Tenant: "acme", Subject: "alice"}
		a, _ := c.Submit(ctx, planned(t, c, bundle, scope))
		cat := &catalog.Service{Store: st, Images: images{}, Policies: pols("acme")}
		if _, err := cat.Put(ctx, model.KindAgent, "acme", docs(t, "kind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n")[0], false, "mallory"); err != nil {
			t.Fatal(err)
		}
		a, err := c.Resume(ctx, a.ID, scope)
		if err != nil || a.Status != model.ApplyConflict || !strings.Contains(a.Error, "the plan expected 0") {
			t.Fatalf("conflict expected: %v %+v", err, a)
		}
		if revisions(t, st, model.KindAgent, "acme", "backend") != 1 {
			t.Fatal("the outside write stands alone; the apply did not add a revision")
		}
	})
	t.Run("rights_revoked_between_attempts", func(t *testing.T) {
		st := &faulty{Store: store.NewMemory(), failBefore: map[int]error{1: errors.New("boom")}, failAfter: map[int]error{}}
		p := pols("acme")
		c := controller(st, "r1", p)
		scope := plan.Scope{Tenant: "acme", Subject: "alice"}
		a, _ := c.Submit(ctx, planned(t, c, bundle, scope))
		// acme loses backend-dev: the pending agents no longer validate.
		c.Planner.Policies = pols()
		a, err := c.Resume(ctx, a.ID, scope)
		if err != nil || a.Status != model.ApplyConflict || !strings.Contains(a.Error, "no longer validates") || !strings.Contains(a.Error, "may not use policy") {
			t.Fatalf("conflict expected: %v %+v", err, a)
		}
		if a.Steps[0].Status != model.StepDone || a.Steps[1].Status != model.StepPending {
			t.Fatalf("partial state visible: %+v", a.Steps)
		}
		// Rights restored: resume finishes.
		c.Planner.Policies = p
		if a, err = c.Resume(ctx, a.ID, scope); err != nil || a.Status != model.ApplyDone {
			t.Fatalf("after restoring rights: %v %+v", err, a)
		}
	})
	t.Run("noop_step_checks_its_revision", func(t *testing.T) {
		st := store.NewMemory()
		c := controller(st, "r1", pols("acme"))
		scope := plan.Scope{Tenant: "acme", Subject: "alice"}
		if _, err := c.Submit(ctx, planned(t, c, bundle, scope)); err != nil {
			t.Fatal(err)
		}
		// A plan where py is a noop; before applying, py moves on.
		req := planned(t, c, bundle, scope)
		cat := &catalog.Service{Store: st, Images: images{}}
		if _, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, "kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n")[0], false, "mallory"); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Submit(ctx, req); !errors.Is(err, ErrPlanMismatch) {
			t.Fatalf("a noop whose revision moved invalidates the plan: %v", err)
		}
	})
}

func TestApplyRecordRoundTrip(t *testing.T) {
	// The stored record is self-describing JSON (what the API returns and what resume reads).
	a := &model.Apply{ID: "apply_x", Key: "k", Tenant: "acme", Status: model.ApplyRunning, Documents: json.RawMessage(`[]`),
		Steps: []model.ApplyStep{{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Action: plan.ActionCreate, Status: model.StepPending}}}
	b, _ := json.Marshal(a)
	var back model.Apply
	if err := json.Unmarshal(b, &back); err != nil || back.Steps[0].Name != "py" || string(back.Documents) != "[]" {
		t.Fatalf("round trip: %v %+v", err, back)
	}
}
