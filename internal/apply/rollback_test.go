package apply

import (
	"context"
	"errors"
	"strings"
	"testing"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/drift"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

const bundleV2 = `
kind: EnvironmentProfile
name: py
spec: {image: canary}
---
kind: AgentDefinition
name: backend
spec: {policy: backend-dev, environment: py}
---
kind: AgentDefinition
name: worker
spec: {policy: backend-dev, environment: py@1}
`

func latest(t *testing.T, st store.Catalog, kind, tenant, name string) *model.CatalogItem {
	t.Helper()
	it, err := st.GetItem(context.Background(), kind, tenant, name, 0)
	if err != nil {
		t.Fatalf("%s %s/%s: %v", kind, tenant, name, err)
	}
	return it
}

func TestSourceIsRecordedOnWrittenRevisions(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	c := controller(st, "r1", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	req := planned(t, c, bundle, scope)
	req.Source = &model.Source{Repo: "git@example.com:acme/platform.git", Ref: "main", Commit: "0123456789abcdef0123456789abcdef01234567", Path: "bundles/acme.yaml"}
	a, err := c.Submit(ctx, req)
	if err != nil || a.Status != model.ApplyDone {
		t.Fatalf("apply: %v %+v", err, a)
	}
	if a.Source == nil || a.Source.Apply != a.ID || a.Source.Bundle != a.Bundle || a.Source.Commit != req.Source.Commit {
		t.Fatalf("apply source: %+v", a.Source)
	}
	py := latest(t, st, model.KindEnvironment, "acme", "py")
	if !py.Managed() || py.Source.Apply != a.ID || py.Source.Bundle != a.Bundle || py.Source.Commit != req.Source.Commit || py.Source.Path != "bundles/acme.yaml" {
		t.Fatalf("revision source: %+v", py.Source)
	}
	// The same bundle from a later commit changes nothing: no revision, the old provenance stays.
	again := planned(t, c, bundle, scope)
	again.Source = &model.Source{Commit: strings.Repeat("f", 40)}
	if b, err := c.Submit(ctx, again); err != nil || b.ID == a.ID || b.Status != model.ApplyDone || b.Steps[0].Status != model.StepSkipped {
		t.Fatalf("noop apply: %v %+v", err, b)
	}
	if py2 := latest(t, st, model.KindEnvironment, "acme", "py"); py2.Revision != 1 || py2.Source.Commit != req.Source.Commit {
		t.Fatalf("noop rewrote provenance: %+v", py2)
	}
	// A direct write through the resource API belongs to nobody.
	cat := &catalog.Service{Store: st, Images: images{}}
	if _, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, "kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n")[0], false, "mallory"); err != nil {
		t.Fatal(err)
	}
	if py3 := latest(t, st, model.KindEnvironment, "acme", "py"); py3.Revision != 2 || py3.Managed() {
		t.Fatalf("manual revision carries a source: %+v", py3)
	}
	if applied, _ := drift.LastApplied(ctx, st, model.KindEnvironment, "acme", "py"); applied == nil || applied.Revision != 1 {
		t.Fatalf("last applied: %+v", applied)
	}
}

func TestRollbackRestoresTheReplacedRevisions(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	c := controller(st, "r1", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	if _, err := c.Submit(ctx, planned(t, c, bundle, scope)); err != nil {
		t.Fatal(err)
	}
	v2, err := c.Submit(ctx, planned(t, c, bundleV2, scope))
	if err != nil || v2.Status != model.ApplyDone || v2.Steps[0].Revision != 2 {
		t.Fatalf("v2: %v %+v", err, v2)
	}
	// Dry run: the plan says what would be restored, nothing is written.
	rb, err := c.Rollback(ctx, RollbackRequest{Apply: v2.ID, DryRun: true, Scope: scope})
	if err != nil || rb.Plan == nil || !rb.Plan.Valid || len(rb.Documents) != 1 || rb.Plan.Changes[0].Action != plan.ActionUpdate || rb.Plan.Changes[0].NextRevision != 3 {
		t.Fatalf("dry run: %v %+v", err, rb)
	}
	if latest(t, st, model.KindEnvironment, "acme", "py").Revision != 2 {
		t.Fatal("dry run wrote")
	}
	// The rollback is a new apply: py goes back to the stable image as revision 3, and the
	// revision says what it restored. backend and worker were noops in v2: nothing to undo.
	rb, err = c.Rollback(ctx, RollbackRequest{Apply: v2.ID, Scope: scope})
	if err != nil || rb.Apply == nil || rb.Apply.Status != model.ApplyDone || rb.Target != v2.ID {
		t.Fatalf("rollback: %v %+v", err, rb)
	}
	py := latest(t, st, model.KindEnvironment, "acme", "py")
	if py.Revision != 3 || !strings.Contains(string(py.Spec), `"image":"stable"`) || py.Source == nil || py.Source.Apply != rb.Apply.ID || py.Source.Rollback != v2.ID {
		t.Fatalf("restored revision: %+v %s", py, py.Spec)
	}
	if revisions(t, st, model.KindAgent, "acme", "backend") != 1 {
		t.Fatal("rollback touched an item v2 left alone")
	}
	// Rolling back again finds the state already restored: a new apply whose only step is a
	// noop, nothing written (the plan is bound to the state, so it is not the same apply).
	if again, err := c.Rollback(ctx, RollbackRequest{Apply: v2.ID, Scope: scope}); err != nil || again.Apply.ID == rb.Apply.ID || again.Apply.Steps[0].Status != model.StepSkipped || latest(t, st, model.KindEnvironment, "acme", "py").Revision != 3 {
		t.Fatalf("second rollback: %v %+v", err, again)
	}
	// An apply that only created things has nothing rollback can restore: the creations are
	// named, nothing is written, the caller removes them explicitly.
	first, _ := c.Store.ListApplies(ctx, "acme", 10)
	var v1 *model.Apply
	for _, a := range first {
		if a.Steps[0].ExpectedRevision == 0 {
			v1 = a
		}
	}
	rb, err = c.Rollback(ctx, RollbackRequest{Apply: v1.ID, Scope: scope})
	if !errors.Is(err, ErrNothingToRollBack) || rb == nil || len(rb.Skipped) != 3 || !strings.Contains(rb.Skipped[0].Reason, "created by "+v1.ID) {
		t.Fatalf("creation rollback: %v %+v", err, rb)
	}
	if latest(t, st, model.KindEnvironment, "acme", "py").Revision != 3 {
		t.Fatal("a refused rollback wrote")
	}
	// Isolation: another tenant cannot see, let alone roll back, acme's apply.
	if _, err := c.Rollback(ctx, RollbackRequest{Apply: v2.ID, Scope: plan.Scope{Tenant: "other"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other tenant: %v", err)
	}
}

func TestRollbackOfOneItem(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	c := controller(st, "r1", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	a, _ := c.Submit(ctx, planned(t, c, bundle, scope))
	// Drift: py is changed by hand; rollback without a revision restores what the apply wrote.
	cat := &catalog.Service{Store: st, Images: images{}}
	if _, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, "kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n")[0], false, "mallory"); err != nil {
		t.Fatal(err)
	}
	rb, err := c.Rollback(ctx, RollbackRequest{Kind: model.KindEnvironment, Name: "py", Scope: scope})
	if err != nil || rb.Apply.Status != model.ApplyDone || rb.Target != "EnvironmentProfile acme/py@1" {
		t.Fatalf("rollback: %v %+v", err, rb)
	}
	py := latest(t, st, model.KindEnvironment, "acme", "py")
	if py.Revision != 3 || !strings.Contains(string(py.Spec), `"image":"stable"`) || py.Source.Rollback != "EnvironmentProfile acme/py@1" {
		t.Fatalf("restored: %+v %s", py, py.Spec)
	}
	rep, err := drift.Detect(ctx, st, "acme", c.now())
	if err != nil || len(rep.Drifted) != 0 {
		t.Fatalf("drift after rollback: %v %+v", err, rep)
	}
	// An explicit revision, even a deleted one, can be restored; a missing one is 404.
	if err := st.DeleteItem(ctx, model.KindEnvironment, "acme", "py"); err != nil {
		t.Fatal(err)
	}
	rb, err = c.Rollback(ctx, RollbackRequest{Kind: model.KindEnvironment, Name: "py", Revision: 2, Scope: scope})
	if err != nil || rb.Plan.Changes[0].Action != plan.ActionCreate || rb.Plan.Changes[0].NextRevision != 4 {
		t.Fatalf("restore a deleted item: %v %+v", err, rb)
	}
	if py := latest(t, st, model.KindEnvironment, "acme", "py"); py.Revision != 4 || !strings.Contains(string(py.Spec), "canary") {
		t.Fatalf("restored deleted: %+v", py)
	}
	if _, err := c.Rollback(ctx, RollbackRequest{Kind: model.KindEnvironment, Name: "py", Revision: 9, Scope: scope}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing revision: %v", err)
	}
	if _, err := c.Rollback(ctx, RollbackRequest{Kind: model.KindAgent, Name: "nobody", Scope: scope}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("never applied: %v", err)
	}
	// A tenant stays in its scope; the admin names one.
	if _, err := c.Rollback(ctx, RollbackRequest{Kind: model.KindEnvironment, Tenant: "other", Name: "py", Scope: scope}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("other scope: %v", err)
	}
	if rb, err := c.Rollback(ctx, RollbackRequest{Kind: model.KindEnvironment, Tenant: "acme", Name: "py", Revision: 1, DryRun: true, Scope: plan.Scope{Admin: true, Subject: "root"}}); err != nil || !rb.Plan.Valid || rb.Documents[0].Tenant == nil || *rb.Documents[0].Tenant != "acme" {
		t.Fatalf("admin: %v %+v", err, rb)
	}
	_ = a
}

func TestRollbackRunsUnderCurrentRights(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	p := pols("acme")
	c := controller(st, "r1", p)
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	if _, err := c.Submit(ctx, planned(t, c, bundle, scope)); err != nil {
		t.Fatal(err)
	}
	v2, err := c.Submit(ctx, planned(t, c, strings.Replace(bundleV2, "policy: backend-dev, environment: py}", "policy: backend-dev, environment: py, repo: https://example.com/r.git}", 1), scope))
	if err != nil || v2.Status != model.ApplyDone || v2.Steps[1].Revision != 2 {
		t.Fatalf("v2: %v %+v", err, v2)
	}
	// acme loses backend-dev: the agent revision rollback would restore does not validate any
	// more, the rollback is refused as a whole and nothing is written. The environment alone
	// would have been fine, but a rollback is one bundle, like the apply it undoes.
	c.Planner.Policies = pols()
	rb, err := c.Rollback(ctx, RollbackRequest{Apply: v2.ID, Scope: scope})
	var invalid *InvalidPlan
	if !errors.As(err, &invalid) || rb.Plan.Valid || !strings.Contains(strings.Join(rb.Plan.Changes[1].Errors, ";"), "may not use policy") {
		t.Fatalf("revoked rights: %v %+v", err, rb)
	}
	if latest(t, st, model.KindEnvironment, "acme", "py").Revision != 2 || latest(t, st, model.KindAgent, "acme", "backend").Revision != 2 {
		t.Fatal("a refused rollback wrote")
	}
	// Rights back: the same rollback goes through.
	c.Planner.Policies = p
	if rb, err = c.Rollback(ctx, RollbackRequest{Apply: v2.ID, Scope: scope}); err != nil || rb.Apply.Status != model.ApplyDone {
		t.Fatalf("after restoring rights: %v %+v", err, rb)
	}
}

func TestRollbackNeverRestoresGrants(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	c := controller(st, "r1", pols())
	admin := plan.Scope{Admin: true, Subject: "root"}
	grant := func(max int) string {
		return "kind: PolicyBinding\ntenant: acme\nname: backend-dev\nspec: {max_sandboxes: " + itoa(max) + "}\n---\nkind: TenantSettings\ntenant: acme\nspec: {quota: {max_sandboxes: " + itoa(max) + "}}\n---\nkind: EnvironmentProfile\ntenant: acme\nname: py\nspec: {image: stable}\n"
	}
	v1, err := c.Submit(ctx, planned(t, c, grant(5), admin))
	if err != nil || v1.Status != model.ApplyDone {
		t.Fatalf("v1: %v %+v", err, v1)
	}
	v2, err := c.Submit(ctx, planned(t, c, strings.Replace(grant(1), "image: stable", "image: canary", 1), admin))
	if err != nil || v2.Status != model.ApplyDone || len(v2.Steps) != 3 {
		t.Fatalf("v2: %v %+v", err, v2)
	}
	// The grant is then revoked by hand.
	if err := st.DeleteItem(ctx, model.KindBinding, "acme", "backend-dev"); err != nil {
		t.Fatal(err)
	}
	rb, err := c.Rollback(ctx, RollbackRequest{Apply: v2.ID, Scope: admin})
	if err != nil || rb.Apply.Status != model.ApplyDone || len(rb.Documents) != 1 || rb.Documents[0].Kind != model.KindEnvironment {
		t.Fatalf("rollback: %v %+v", err, rb)
	}
	kinds := map[string]string{}
	for _, sk := range rb.Skipped {
		kinds[sk.Kind] = sk.Reason
	}
	if !strings.Contains(kinds[model.KindBinding], "not restored") || !strings.Contains(kinds[model.KindTenantSettings], "not restored") {
		t.Fatalf("grants not reported as skipped: %+v", rb.Skipped)
	}
	if _, err := st.GetItem(ctx, model.KindBinding, "acme", "backend-dev", 0); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("rollback restored a revoked grant")
	}
	if settings := latest(t, st, model.KindTenantSettings, "acme", "settings"); settings.Revision != 2 {
		t.Fatalf("rollback touched the quotas: %+v", settings)
	}
	if py := latest(t, st, model.KindEnvironment, "acme", "py"); py.Revision != 3 || !strings.Contains(string(py.Spec), "stable") {
		t.Fatalf("configuration not restored: %+v", py)
	}
	// Nor can a grant be rolled back on its own.
	if _, err := c.Rollback(ctx, RollbackRequest{Kind: model.KindBinding, Tenant: "acme", Name: "backend-dev", Revision: 1, Scope: admin}); !errors.Is(err, res.ErrInvalid) {
		t.Fatalf("grant rollback: %v", err)
	}
}

func itoa(n int) string {
	return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+n)))
}

func TestResumeAfterOwnWriteWithExpectedRevisionZero(t *testing.T) {
	ctx := context.Background()
	st := &faulty{Store: store.NewMemory(), failBefore: map[int]error{1: errors.New("boom")}, failAfter: map[int]error{}}
	c := controller(st, "r1", pols("acme"))
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	pinned := strings.ReplaceAll(bundle, "spec:", "expected_revision: 0\nspec:")
	a, err := c.Submit(ctx, planned(t, c, pinned, scope))
	if err != nil || a.Status != model.ApplyFailed || a.Steps[0].Status != model.StepDone {
		t.Fatalf("first attempt: %v %+v", err, a)
	}
	// The environment this apply created is at revision 1; its document said "must not exist"
	// about the state before the apply, not about the apply's own work.
	a, err = c.Resume(ctx, a.ID, scope)
	if err != nil || a.Status != model.ApplyDone {
		t.Fatalf("resume: %v %+v", err, a)
	}
	// The same through Submit with the original key and bundle.
	st2 := &faulty{Store: store.NewMemory(), failBefore: map[int]error{1: errors.New("boom")}, failAfter: map[int]error{}}
	c2 := controller(st2, "r1", pols("acme"))
	req := planned(t, c2, pinned, scope)
	if a, _ := c2.Submit(ctx, req); a.Status != model.ApplyFailed {
		t.Fatalf("first attempt: %+v", a)
	}
	if a, err := c2.Submit(ctx, req); err != nil || a.Status != model.ApplyDone {
		t.Fatalf("resubmit: %v %+v", err, a)
	}
	// Rights are still checked on the way: the applied environment stays, the pending agents
	// are refused once the policy is gone.
	st3 := &faulty{Store: store.NewMemory(), failBefore: map[int]error{1: errors.New("boom")}, failAfter: map[int]error{}}
	c3 := controller(st3, "r1", pols("acme"))
	a3, _ := c3.Submit(ctx, planned(t, c3, pinned, scope))
	c3.Planner.Policies = pols()
	if a3, err := c3.Resume(ctx, a3.ID, scope); err != nil || a3.Status != model.ApplyConflict || !strings.Contains(a3.Error, "may not use policy") {
		t.Fatalf("rights still checked: %v %+v", err, a3)
	}
	// And a real outside change to the created item is still a conflict.
	cat := &catalog.Service{Store: st, Images: images{}}
	st4 := &faulty{Store: store.NewMemory(), failBefore: map[int]error{1: errors.New("boom")}, failAfter: map[int]error{}}
	c4 := controller(st4, "r1", pols("acme"))
	a4, _ := c4.Submit(ctx, planned(t, c4, pinned, scope))
	cat.Store = st4
	if _, err := cat.Put(ctx, model.KindEnvironment, "acme", docs(t, "kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n")[0], false, "mallory"); err != nil {
		t.Fatal(err)
	}
	if a4, err := c4.Resume(ctx, a4.ID, scope); err != nil || a4.Status != model.ApplyConflict || !strings.Contains(a4.Error, "changed outside this apply") {
		t.Fatalf("outside change: %v %+v", err, a4)
	}
}

func TestPlanFingerprintCoversWhatReferencesResolveTo(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	c := controller(st, "r1", pols("acme"))
	admin := plan.Scope{Admin: true, Subject: "root"}
	if _, err := c.Submit(ctx, planned(t, c, "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n", admin)); err != nil {
		t.Fatal(err)
	}
	// acme plans an agent on "py": today that is the shared environment.
	scope := plan.Scope{Tenant: "acme", Subject: "alice"}
	agent := "kind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"
	req := planned(t, c, agent, scope)
	p0, _ := c.Planner.Plan(ctx, req.Docs, scope)
	// Before apply, acme gets its own "py": the same document now names another item.
	if _, err := c.Submit(ctx, planned(t, c, "kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n", scope)); err != nil {
		t.Fatal(err)
	}
	p1, _ := c.Planner.Plan(ctx, req.Docs, scope)
	if p1.Bundle != p0.Bundle {
		t.Fatal("the request did not change: the bundle hash must not either")
	}
	if p1.Fingerprint == p0.Fingerprint || p1.Changes[0].Resolved == p0.Changes[0].Resolved {
		t.Fatalf("the plan resolved differently but kept its fingerprint: %+v %+v", p0.Changes[0], p1.Changes[0])
	}
	if _, err := c.Submit(ctx, req); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("apply of the stale plan: %v", err)
	}
	if revisions(t, st, model.KindAgent, "acme", "backend") != 0 {
		t.Fatal("a refused apply wrote")
	}
	// A continuation whose pending step would now resolve differently stops as a conflict.
	st2 := &faulty{Store: store.NewMemory(), failBefore: map[int]error{1: errors.New("boom")}, failAfter: map[int]error{}}
	c2 := controller(st2, "r1", pols("acme"))
	if _, err := c2.Submit(ctx, planned(t, c2, "kind: EnvironmentProfile\nname: py\nspec: {image: stable}\n", admin)); err != nil {
		t.Fatal(err)
	}
	two := "kind: EnvironmentProfile\nname: go\nspec: {image: stable}\n---\nkind: AgentDefinition\nname: backend\nspec: {policy: backend-dev, environment: py}\n"
	a, _ := c2.Submit(ctx, planned(t, c2, two, scope))
	if a.Status != model.ApplyFailed {
		t.Fatalf("first attempt: %+v", a)
	}
	if _, err := c2.Submit(ctx, planned(t, c2, "kind: EnvironmentProfile\nname: py\nspec: {image: canary}\n", scope)); err != nil {
		t.Fatal(err)
	}
	a, err := c2.Resume(ctx, a.ID, scope)
	if err != nil || a.Status != model.ApplyConflict || !strings.Contains(a.Error, "resolves differently") {
		t.Fatalf("resume: %v %+v", err, a)
	}
	if revisions(t, st2, model.KindAgent, "acme", "backend") != 0 {
		t.Fatal("the conflicting step was written")
	}
}
