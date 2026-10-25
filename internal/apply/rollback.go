package apply

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"agent-sandbox/internal/drift"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/store"
)

// ErrNothingToRollBack says the target left nothing that rollback can restore.
var ErrNothingToRollBack = errors.New("nothing to roll back")

// RollbackRequest names what to restore: everything an apply wrote (to the revisions it
// replaced), or one item to a revision (0: the last revision an apply wrote). The restored
// documents are planned and applied like any bundle, under the caller's current rights: a
// policy, environment or connection the caller may no longer use fails the plan, and nothing is
// written. Grants (PolicyBinding, TenantSettings, CITrust) are never restored: a revoked right stays
// revoked whatever an earlier bundle said.
type RollbackRequest struct {
	Apply    string
	Kind     string
	Tenant   string // of the item; defaults to the scope's tenant
	Name     string
	Revision int
	Key      string // idempotency key of the apply; "" = its plan fingerprint
	DryRun   bool   // plan only, write nothing
	Scope    plan.Scope
}

// Skipped is a document of the target that rollback does not restore, and why.
type Skipped struct {
	Kind   string `json:"kind"`
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Rollback is the result: the documents that would be (or were) written, what was left alone,
// the plan, and the apply when one ran.
type Rollback struct {
	Target    string          `json:"target"`
	Documents []*res.Document `json:"documents"`
	Skipped   []Skipped       `json:"skipped,omitempty"`
	Plan      *plan.Plan      `json:"plan"`
	Apply     *model.Apply    `json:"apply,omitempty"`
}

// grants are the kinds rollback never writes.
var grants = map[string]string{
	model.KindBinding:        "a grant is not restored by rollback: issue it again deliberately",
	model.KindTenantSettings: "quotas and allowed environments are not restored by rollback: set them again deliberately",
	model.KindCITrust:        "a CI trust is a grant: a revoked or narrowed trust is not restored by rollback; register it again deliberately",
}

// Rollback builds the documents of the target, plans them and, unless DryRun, applies them.
// An invalid plan is returned as *InvalidPlan with the rollback attached to the error's Plan.
func (c *Controller) Rollback(ctx context.Context, req RollbackRequest) (*Rollback, error) {
	var (
		rb  *Rollback
		err error
	)
	switch {
	case req.Apply != "" && req.Kind == "" && req.Name == "":
		rb, err = c.rollbackApply(ctx, req)
	case req.Apply == "" && req.Kind != "" && req.Name != "":
		rb, err = c.rollbackItem(ctx, req)
	default:
		return nil, fmt.Errorf("%w: name an apply, or a kind and a name", res.ErrInvalid)
	}
	if err != nil {
		return nil, err
	}
	if len(rb.Documents) == 0 {
		return rb, fmt.Errorf("%w: %s", ErrNothingToRollBack, rb.Target)
	}
	p, err := c.Planner.Plan(ctx, rb.Documents, req.Scope)
	if err != nil {
		return nil, err
	}
	rb.Plan = p
	if req.DryRun {
		return rb, nil
	}
	if !p.Valid {
		return rb, &InvalidPlan{Plan: p}
	}
	a, err := c.Submit(ctx, Request{Docs: rb.Documents, Plan: p.Fingerprint, Key: req.Key, Scope: req.Scope, Source: &model.Source{Rollback: rb.Target}})
	rb.Apply = a
	return rb, err
}

// rollbackApply restores every item the apply wrote to the revision it replaced.
func (c *Controller) rollbackApply(ctx context.Context, req RollbackRequest) (*Rollback, error) {
	a, err := c.Get(ctx, req.Apply, req.Scope)
	if err != nil {
		return nil, err
	}
	if !req.Scope.Admin && a.Admin {
		return nil, fmt.Errorf("%w: apply %s was submitted by the admin", ErrForbidden, a.ID)
	}
	rb := &Rollback{Target: a.ID, Documents: []*res.Document{}}
	for _, st := range a.Steps {
		if st.Status != model.StepDone {
			continue // nothing written: noop, pending or failed
		}
		if reason, grant := grants[st.Kind]; grant {
			rb.Skipped = append(rb.Skipped, Skipped{Kind: st.Kind, Tenant: st.Tenant, Name: st.Name, Reason: reason})
			continue
		}
		if st.ExpectedRevision == 0 {
			rb.Skipped = append(rb.Skipped, Skipped{Kind: st.Kind, Tenant: st.Tenant, Name: st.Name,
				Reason: fmt.Sprintf("created by %s (no earlier revision): remove it explicitly if it should go", a.ID)})
			continue
		}
		prev, err := revisionOf(ctx, c.Store, st.Kind, st.Tenant, st.Name, st.ExpectedRevision)
		if err != nil {
			return nil, err
		}
		rb.Documents = append(rb.Documents, document(prev, req.Scope))
	}
	return rb, nil
}

// rollbackItem restores one item to a revision (0: the last revision an apply wrote).
func (c *Controller) rollbackItem(ctx context.Context, req RollbackRequest) (*Rollback, error) {
	tenant := req.Tenant
	if tenant == "" {
		tenant = req.Scope.Tenant
	}
	if !req.Scope.Admin && tenant != req.Scope.Tenant {
		return nil, fmt.Errorf("%w: token is scoped to tenant %q", ErrForbidden, req.Scope.Tenant)
	}
	if reason, grant := grants[req.Kind]; grant {
		return nil, fmt.Errorf("%w: %s", res.ErrInvalid, reason)
	}
	var (
		target *model.CatalogItem
		err    error
	)
	if req.Revision == 0 {
		if target, err = drift.LastApplied(ctx, c.Store, req.Kind, tenant, req.Name); err != nil {
			return nil, err
		}
		if target == nil {
			return nil, fmt.Errorf("%w: no apply ever wrote %s %s/%s; name a revision", ErrNotFound, req.Kind, tenant, req.Name)
		}
	} else if target, err = revisionOf(ctx, c.Store, req.Kind, tenant, req.Name, req.Revision); err != nil {
		return nil, err
	}
	return &Rollback{Target: fmt.Sprintf("%s %s/%s@%d", req.Kind, tenant, req.Name, target.Revision),
		Documents: []*res.Document{document(target, req.Scope)}}, nil
}

// revisionOf reads revision n of an item, deleted or superseded ones included.
func revisionOf(ctx context.Context, st store.Catalog, kind, tenant, name string, n int) (*model.CatalogItem, error) {
	revs, err := st.ListRevisions(ctx, kind, tenant, name)
	if err != nil {
		return nil, fmt.Errorf("%s %s/%s: %w", kind, tenant, name, err)
	}
	for _, r := range revs {
		if r.Revision == n {
			return r, nil
		}
	}
	return nil, fmt.Errorf("%w: %s %s/%s has no revision %d", ErrNotFound, kind, tenant, name, n)
}

// document is the revision as a document to apply again: the same spec and description,
// nothing of its provenance (the new revision gets its own).
func document(it *model.CatalogItem, scope plan.Scope) *res.Document {
	d := &res.Document{Kind: it.Kind, Name: it.Name, Description: it.Description, Spec: append([]byte(nil), it.Spec...)}
	if scope.Admin || it.Tenant != scope.Tenant {
		t := it.Tenant
		d.Tenant = &t
	}
	return d
}

// String renders the request's target for messages.
func (r RollbackRequest) String() string {
	if r.Apply != "" {
		return r.Apply
	}
	return strings.TrimSuffix(fmt.Sprintf("%s %s/%s@%d", r.Kind, r.Tenant, r.Name, r.Revision), "@0")
}
