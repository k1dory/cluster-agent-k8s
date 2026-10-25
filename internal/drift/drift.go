// Package drift finds catalogue items that moved away from what an apply last wrote.
//
// An item belongs to the apply that wrote its latest revision (the revision's Source names the
// apply, its bundle and, when the bundle came from Git, the commit). A revision written directly
// through the resource API carries no source: on an item nobody applied it is simply manual,
// on an item an apply wrote earlier it is drift. A managed item that was deleted is drift too.
// A later apply that writes the item is not drift: the desired state moved with it.
//
// The report is computed from the store alone, so it is the same on every replica and needs no
// access to Git. Drift against a bundle (what Git says now versus what the platform holds) is
// the plan of that bundle: every change that is not a noop.
package drift

import (
	"context"
	"errors"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
	"agent-sandbox/internal/store"
)

// States an entry can be in.
const (
	Changed = "changed" // the latest revision was written outside apply
	Deleted = "deleted" // the item an apply wrote is gone
)

// Kinds the report covers, in apply order.
var Kinds = []string{model.KindEnvironment, model.KindConnection, model.KindTenantSettings, model.KindBinding, model.KindAgent, model.KindGitRepository, model.KindCITrust}

// Revision is one revision as the report shows it.
type Revision struct {
	Revision  int           `json:"revision"`
	CreatedBy string        `json:"created_by,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
	Source    *model.Source `json:"source,omitempty"`
}

// Entry is one drifted item.
type Entry struct {
	Kind   string `json:"kind"`
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
	State  string `json:"state"` // changed | deleted
	// Applied is the last revision an apply wrote: what rollback restores by default.
	Applied Revision `json:"applied"`
	// Current is the live revision (absent when deleted).
	Current *Revision `json:"current,omitempty"`
	// Diff is applied → current (changed only).
	Diff []plan.FieldChange `json:"diff,omitempty"`
}

// Report is the drift of one scope.
type Report struct {
	Tenant  string    `json:"tenant"`
	Checked int       `json:"checked"` // managed items examined
	Drifted []Entry   `json:"drifted"`
	At      time.Time `json:"at"`
}

// Detect reports the drift of tenant's scope ("" = shared items).
func Detect(ctx context.Context, st store.Catalog, tenant string, now time.Time) (*Report, error) {
	rep := &Report{Tenant: tenant, Drifted: []Entry{}, At: now}
	for _, kind := range Kinds {
		live, err := st.ListItems(ctx, kind, tenant)
		if err != nil {
			return nil, err
		}
		for _, it := range live {
			if it.Managed() {
				rep.Checked++
				continue
			}
			applied, err := LastApplied(ctx, st, kind, tenant, it.Name)
			if err != nil {
				return nil, err
			}
			if applied == nil {
				continue // never applied: manual, not drift
			}
			rep.Checked++
			rep.Drifted = append(rep.Drifted, Entry{Kind: kind, Tenant: tenant, Name: it.Name, State: Changed,
				Applied: describe(applied), Current: ptr(describe(it)), Diff: plan.Diff(applied, it)})
		}
		gone, err := st.ListDeleted(ctx, kind, tenant)
		if err != nil {
			return nil, err
		}
		for _, it := range gone {
			applied, err := LastApplied(ctx, st, kind, tenant, it.Name)
			if err != nil {
				return nil, err
			}
			if applied == nil {
				continue
			}
			rep.Checked++
			rep.Drifted = append(rep.Drifted, Entry{Kind: kind, Tenant: tenant, Name: it.Name, State: Deleted, Applied: describe(applied)})
		}
	}
	return rep, nil
}

// LastApplied is the highest revision of an item that an apply wrote (nil when none).
func LastApplied(ctx context.Context, st store.Catalog, kind, tenant, name string) (*model.CatalogItem, error) {
	revs, err := st.ListRevisions(ctx, kind, tenant, name)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	for i := len(revs) - 1; i >= 0; i-- {
		if revs[i].Managed() {
			return revs[i], nil
		}
	}
	return nil, nil
}

func describe(it *model.CatalogItem) Revision {
	return Revision{Revision: it.Revision, CreatedBy: it.CreatedBy, CreatedAt: it.CreatedAt, Source: it.Source}
}

func ptr(r Revision) *Revision { return &r }
