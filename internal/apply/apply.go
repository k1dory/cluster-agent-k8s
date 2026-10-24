// Package apply is the second half of the apply controller: it applies a planned bundle so
// that nothing is done twice and nothing is left half-known.
//
//   - A plan binds documents to state: apply takes the plan's fingerprint and refuses a bundle
//     whose plan no longer matches what it finds.
//   - Each step writes its item revision and its own completion in one transaction (the
//     store's ApplyStep), guarded by the apply's version: a step is either applied and recorded
//     or neither, and two replicas cannot both commit it.
//   - An apply is created once per idempotency key and continued: the same key with the same
//     bundle returns the same apply (finishing it if needed), another bundle under the key is a
//     conflict. A replica continuing an unfinished apply takes a lease first.
//   - Continuation re-plans the stored documents under the stored scope with the caller's
//     current rights: every pending step must still find the revision it expected (a noop
//     too), every applied step must still be the latest revision, and every document must
//     still validate; otherwise the apply stops with status conflict and the reason.
package apply

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// Errors the API maps to status codes.
var (
	ErrPlanMismatch = errors.New("the plan does not match the current state: plan again") // 409
	ErrKeyReused    = errors.New("the key was used for a different bundle")               // 409
	ErrForbidden    = res.ErrForbidden
	ErrNotFound     = store.ErrNotFound
)

// InvalidPlan says the bundle did not plan cleanly; the plan carries the problems.
type InvalidPlan struct{ Plan *plan.Plan }

func (e *InvalidPlan) Error() string { return "the bundle is not valid: see the plan" }

// Request is one apply submission.
type Request struct {
	Docs  []*res.Document
	Plan  string // fingerprint of the plan the caller approved
	Key   string // idempotency key; "" = the plan fingerprint
	Scope plan.Scope
}

// Controller applies bundles.
type Controller struct {
	Store   store.Store
	Planner plan.Deps
	// Refresh reloads the snapshots the services decide from (bindings, settings,
	// connections) once an apply wrote something.
	Refresh []func(context.Context) error
	Replica string        // lease owner
	Lease   time.Duration // how long a replica holds an apply; 0 = 2 minutes
	Now     func() time.Time
	Log     *slog.Logger
}

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Controller) lease() time.Duration {
	if c.Lease > 0 {
		return c.Lease
	}
	return 2 * time.Minute
}

// Submit plans the bundle, checks the plan against the caller's fingerprint and applies it,
// or continues the apply already submitted under the same key.
func (c *Controller) Submit(ctx context.Context, req Request) (*model.Apply, error) {
	p, _, err := c.Planner.PlanItems(ctx, req.Docs, req.Scope)
	if err != nil {
		return nil, err
	}
	// The key defaults to the fingerprint the caller submitted (not the one computed now:
	// once the apply ran, the state has moved and so has the fingerprint; the key must still
	// find the same apply).
	key := req.Key
	if key == "" {
		key = req.Plan
	}
	if key == "" {
		key = p.Fingerprint
	}
	if existing, err := c.Store.GetApplyByKey(ctx, req.Scope.Tenant, key); err == nil {
		if existing.Bundle != p.Bundle {
			return existing, fmt.Errorf("%w: apply %s", ErrKeyReused, existing.ID)
		}
		if !req.Scope.Admin && existing.Admin {
			return nil, fmt.Errorf("%w: apply %s was submitted by the admin", ErrForbidden, existing.ID)
		}
		return c.run(ctx, existing)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if !p.Valid {
		return nil, &InvalidPlan{Plan: p}
	}
	if req.Plan == "" || req.Plan != p.Fingerprint {
		return nil, fmt.Errorf("%w (planned %q, now %q)", ErrPlanMismatch, req.Plan, p.Fingerprint)
	}
	docs, err := json.Marshal(req.Docs)
	if err != nil {
		return nil, err
	}
	a := &model.Apply{
		ID: newID(), Key: key, Tenant: req.Scope.Tenant, Admin: req.Scope.Admin, Subject: req.Scope.Subject,
		Bundle: p.Bundle, Plan: p.Fingerprint, Status: model.ApplyRunning, Documents: docs,
	}
	for _, ch := range p.Changes {
		a.Steps = append(a.Steps, model.ApplyStep{Kind: ch.Kind, Tenant: ch.Tenant, Name: ch.Name, Action: ch.Action,
			ExpectedRevision: ch.ExpectedRevision, NextRevision: ch.NextRevision, Status: model.StepPending})
	}
	if err := c.Store.CreateApply(ctx, a); err != nil {
		if !errors.Is(err, store.ErrConflict) {
			return nil, err
		}
		// Submitted twice at once: the other submission created it; continue that one.
		if a, err = c.Store.GetApplyByKey(ctx, req.Scope.Tenant, key); err != nil {
			return nil, err
		}
		if a.Bundle != p.Bundle {
			return a, fmt.Errorf("%w: apply %s", ErrKeyReused, a.ID)
		}
	}
	return c.run(ctx, a)
}

// Resume continues an apply that stopped (failed or conflict) or that another replica left
// unfinished. The stored scope is re-planned with its current rights.
func (c *Controller) Resume(ctx context.Context, id string, scope plan.Scope) (*model.Apply, error) {
	a, err := c.Get(ctx, id, scope)
	if err != nil {
		return nil, err
	}
	if !scope.Admin && a.Admin {
		return nil, fmt.Errorf("%w: apply %s was submitted by the admin", ErrForbidden, id)
	}
	return c.run(ctx, a)
}

// Get returns an apply the caller may see.
func (c *Controller) Get(ctx context.Context, id string, scope plan.Scope) (*model.Apply, error) {
	a, err := c.Store.GetApply(ctx, id)
	if err != nil {
		return nil, err
	}
	if !scope.Admin && a.Tenant != scope.Tenant {
		return nil, store.ErrNotFound
	}
	return a, nil
}

// List returns the applies of a scope, newest first.
func (c *Controller) List(ctx context.Context, tenant string, limit int) ([]*model.Apply, error) {
	return c.Store.ListApplies(ctx, tenant, limit)
}

// run takes the lease, re-verifies and applies the pending steps.
func (c *Controller) run(ctx context.Context, a *model.Apply) (*model.Apply, error) {
	if a.Status == model.ApplyDone {
		return a, nil
	}
	// Lease: one replica at a time; a caller finding a live lease elsewhere gets the apply as
	// it is (status running) rather than racing it.
	for {
		if a.LeaseOwner != "" && a.LeaseOwner != c.Replica && a.LeaseUntil != nil && a.LeaseUntil.After(c.now()) && a.Status == model.ApplyRunning {
			return a, nil
		}
		until := c.now().Add(c.lease())
		a.LeaseOwner, a.LeaseUntil, a.Status, a.Error = c.Replica, &until, model.ApplyRunning, ""
		err := c.Store.UpdateApply(ctx, a)
		if err == nil {
			break
		}
		if !errors.Is(err, store.ErrConflict) {
			return nil, err
		}
		if a, err = c.Store.GetApply(ctx, a.ID); err != nil {
			return nil, err
		}
		if a.Status == model.ApplyDone {
			return a, nil
		}
	}
	a, err := c.execute(ctx, a)
	// Release the lease whatever happened (best effort: the record may have moved).
	if a != nil {
		a.LeaseOwner, a.LeaseUntil = "", nil
		if uerr := c.Store.UpdateApply(ctx, a); uerr != nil && c.Log != nil {
			c.Log.Warn("apply: release lease", "id", a.ID, "err", uerr)
		}
	}
	return a, err
}

func (c *Controller) execute(ctx context.Context, a *model.Apply) (*model.Apply, error) {
	var docs []*res.Document
	if err := json.Unmarshal(a.Documents, &docs); err != nil {
		return c.stop(ctx, a, model.ApplyFailed, "stored documents are unreadable: "+err.Error())
	}
	scope := plan.Scope{Tenant: a.Tenant, Admin: a.Admin, Subject: a.Subject}
	p, items, err := c.Planner.PlanItems(ctx, docs, scope)
	if err != nil {
		return c.stop(ctx, a, model.ApplyFailed, "plan: "+err.Error())
	}
	index := map[string]int{}
	for i, ch := range p.Changes {
		index[ch.Kind+"|"+ch.Tenant+"|"+ch.Name] = i
	}
	wrote := false
	for i := range a.Steps {
		st := &a.Steps[i]
		ci, ok := index[st.Kind+"|"+st.Tenant+"|"+st.Name]
		if !ok {
			return c.stop(ctx, a, model.ApplyConflict, fmt.Sprintf("%s %s/%s is no longer part of the plan", st.Kind, st.Tenant, st.Name))
		}
		ch := p.Changes[ci]
		switch st.Status {
		case model.StepDone, model.StepSkipped:
			// Applied earlier: it must still be what was written.
			cur, err := c.Store.GetItem(ctx, st.Kind, st.Tenant, st.Name, 0)
			if err != nil || cur.Revision != st.Revision {
				got := "deleted"
				if cur != nil {
					got = fmt.Sprintf("revision %d", cur.Revision)
				}
				return c.stop(ctx, a, model.ApplyConflict, fmt.Sprintf("%s %s/%s was changed outside this apply after step %d wrote revision %d (now %s)", st.Kind, st.Tenant, st.Name, i+1, st.Revision, got))
			}
			continue
		}
		// Pending or failed: the document must still validate under the current rights and the
		// item must still be at the revision the plan expected (a noop checks it too). A failure
		// recorded by an earlier attempt belongs to that attempt.
		st.Status, st.Error = model.StepPending, ""
		if ch.Action == plan.ActionInvalid {
			return c.stop(ctx, a, model.ApplyConflict, fmt.Sprintf("%s %s/%s no longer validates: %s", st.Kind, st.Tenant, st.Name, strings.Join(ch.Errors, "; ")))
		}
		if ch.ExpectedRevision != st.ExpectedRevision {
			return c.stop(ctx, a, model.ApplyConflict, fmt.Sprintf("%s %s/%s is at revision %d, the plan expected %d", st.Kind, st.Tenant, st.Name, ch.ExpectedRevision, st.ExpectedRevision))
		}
		if ch.Action != st.Action {
			return c.stop(ctx, a, model.ApplyConflict, fmt.Sprintf("%s %s/%s would now be a %s, the plan said %s", st.Kind, st.Tenant, st.Name, ch.Action, st.Action))
		}
		until := c.now().Add(c.lease())
		a.LeaseUntil = &until
		var it *model.CatalogItem
		if ch.Action == plan.ActionNoop {
			st.Status, st.Revision, st.Error = model.StepSkipped, st.ExpectedRevision, ""
		} else {
			it = items[ci]
			it.CreatedBy = a.Subject
			st.Status, st.Error = model.StepDone, ""
		}
		err := c.Store.ApplyStep(ctx, a, i, it, st.ExpectedRevision)
		if err == nil {
			wrote = wrote || it != nil
			continue
		}
		// Whatever the error, the record decides: the transaction may have committed with its
		// acknowledgement lost, or another replica may have done the step. Only what is recorded
		// as pending is retried; nothing is ever written twice.
		if cur, gerr := c.Store.GetApply(ctx, a.ID); gerr == nil {
			if cur.Steps[i].Status == model.StepDone || cur.Steps[i].Status == model.StepSkipped {
				c.refresh(ctx)
				return c.run(ctx, cur)
			}
			a = cur
		}
		if errors.Is(err, store.ErrConflict) {
			// The item moved under us (its revision is not what the plan expected).
			a.Steps[i].Status, a.Steps[i].Error = model.StepPending, ""
			return c.stop(ctx, a, model.ApplyConflict, fmt.Sprintf("step %d (%s %s/%s): %v", i+1, st.Kind, st.Tenant, st.Name, err))
		}
		a.Steps[i].Status, a.Steps[i].Error = model.StepFailed, err.Error()
		return c.stop(ctx, a, model.ApplyFailed, fmt.Sprintf("step %d (%s %s/%s): %v", i+1, st.Kind, st.Tenant, st.Name, err))
	}
	a.Status, a.Error = model.ApplyDone, ""
	if wrote {
		c.refresh(ctx)
	}
	return a, nil
}

// stop records why the apply did not finish; the caller releases the lease.
func (c *Controller) stop(ctx context.Context, a *model.Apply, status, reason string) (*model.Apply, error) {
	a.Status, a.Error = status, reason
	c.refresh(ctx)
	return a, nil
}

func (c *Controller) refresh(ctx context.Context) {
	for _, f := range c.Refresh {
		if err := f(ctx); err != nil && c.Log != nil {
			c.Log.Warn("apply: refresh after write", "err", err)
		}
	}
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "apply_" + hex.EncodeToString(b)
}
