// Package plan validates a bundle of configuration documents against the platform and reports
// what applying it would change, without changing anything. It is the first half of the apply
// controller: the whole bundle is checked at once (documents may depend on each other), the
// caller's authority over every document is verified, each document is compared with the
// current revision into a stable field diff, and the revision apply must find is recorded, so
// a later apply can refuse a bundle planned against a state that moved.
package plan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/policy"
	res "agent-sandbox/internal/resource"
	"agent-sandbox/internal/secrets"
	"agent-sandbox/internal/services"
	"agent-sandbox/internal/store"
	"agent-sandbox/internal/tenants"
)

// Actions a change can carry.
const (
	ActionCreate  = "create"
	ActionUpdate  = "update"
	ActionNoop    = "noop"
	ActionInvalid = "invalid"
)

// Deps is what the planner validates against: the live store (read only) and the same
// policy set, image catalogue, secrets and quota defaults the running services use.
type Deps struct {
	Store    store.Catalog
	Policies *policy.Set
	Images   catalog.Images
	Secrets  secrets.Provider
	Defaults func(tenant string) tenants.Quota
	Now      func() time.Time
}

// Scope is who plans: a tenant (confined to its own scope and the kinds it may write) or the
// admin, whose documents default to Tenant when they name none ("" = shared).
type Scope struct {
	Tenant  string
	Admin   bool
	Subject string
}

// FieldChange is one leaf of the canonical spec that differs ("description" for the item's
// description). From is absent for an added field, To for a removed one.
type FieldChange struct {
	Path string `json:"path"`
	From any    `json:"from,omitempty"`
	To   any    `json:"to,omitempty"`
}

// Change is the plan for one document.
type Change struct {
	Kind   string `json:"kind"`
	Tenant string `json:"tenant"`
	Name   string `json:"name"`
	Action string `json:"action"`
	// CurrentRevision is the live revision the document was compared with (0: none).
	// ExpectedRevision is what apply must find for this change to be the one planned here: the
	// current revision (apply refuses the change otherwise).
	CurrentRevision  int `json:"current_revision"`
	ExpectedRevision int `json:"expected_revision"`
	// NextRevision is the revision the item will have after apply: a new number for create and
	// update (numbering continues past deleted revisions), the current one for noop.
	NextRevision int `json:"next_revision"`
	// Resolved fingerprints the item as apply will write it: the canonical spec after every
	// reference was resolved (a bare environment name to the tenant's own item or the shared
	// one, a connection to its canonical form). The same document resolves differently once
	// the state changes, so the plan's fingerprint includes it and apply refuses to write
	// anything but what the plan showed.
	Resolved string        `json:"resolved,omitempty"`
	Diff     []FieldChange `json:"diff,omitempty"`
	Errors   []string      `json:"errors,omitempty"`
}

// Plan is the result for a bundle: deterministic for the same documents and the same state.
type Plan struct {
	// Bundle fingerprints the documents as submitted (not the state, not what their references
	// resolved to): the same request gives the same value. Fingerprint binds the plan to the state:
	// scope, every change's action, expected and next revision. Apply takes it and refuses a
	// bundle whose plan no longer matches what it finds.
	Bundle      string   `json:"bundle"`
	Fingerprint string   `json:"plan"`
	Valid       bool     `json:"valid"`
	Changes     []Change `json:"changes"`
	Errors      []string `json:"errors,omitempty"` // bundle-level: duplicates, unknown kinds
	Summary     Summary  `json:"summary"`
}

// Summary counts the actions.
type Summary struct {
	Create  int `json:"create"`
	Update  int `json:"update"`
	Noop    int `json:"noop"`
	Invalid int `json:"invalid"`
}

// kindRank is the apply order: what others depend on comes first.
var kindRank = map[string]int{
	model.KindEnvironment:    0,
	model.KindConnection:     1,
	model.KindTenantSettings: 2,
	model.KindBinding:        3,
	model.KindAgent:          4,
}

type entry struct {
	doc    *res.Document
	tenant string
	key    string
	change *Change
	item   *model.CatalogItem // candidate after validation
}

// Plan validates docs as one bundle under scope and reports the changes. Nothing is written.
func (d Deps) Plan(ctx context.Context, docs []*res.Document, scope Scope) (*Plan, error) {
	p, _, err := d.PlanItems(ctx, docs, scope)
	return p, err
}

// PlanItems is Plan plus the validated items of the valid changes, in the plan's order (nil
// for an invalid change): what apply writes.
func (d Deps) PlanItems(ctx context.Context, docs []*res.Document, scope Scope) (*Plan, []*model.CatalogItem, error) {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	p := &Plan{}
	var entries []*entry
	seen := map[string]int{}
	for i, doc := range docs {
		c := &Change{Kind: doc.Kind, Name: doc.Name, Tenant: scope.Tenant}
		e := &entry{doc: doc, change: c, tenant: scope.Tenant}
		if doc.Tenant != nil {
			e.tenant, c.Tenant = *doc.Tenant, *doc.Tenant
		}
		entries = append(entries, e)
		if _, known := kindRank[doc.Kind]; !known {
			if doc.Kind == "" {
				c.Errors = append(c.Errors, "kind is required")
			} else {
				c.Errors = append(c.Errors, fmt.Sprintf("unknown kind %q", doc.Kind))
			}
			continue
		}
		if doc.Kind == model.KindTenantSettings && doc.Name == "" {
			doc.Name, c.Name = tenants.Name, tenants.Name
		}
		// Authority.
		if doc.Tenant != nil && !scope.Admin && *doc.Tenant != scope.Tenant {
			c.Errors = append(c.Errors, fmt.Sprintf("token is scoped to tenant %q, document names %q", scope.Tenant, *doc.Tenant))
		}
		if !scope.Admin && (doc.Kind == model.KindBinding || doc.Kind == model.KindTenantSettings) {
			c.Errors = append(c.Errors, doc.Kind+" is written by the admin only")
		}
		if !scope.Admin && e.tenant == "" {
			c.Errors = append(c.Errors, "shared items are written by the admin only")
		}
		e.key = doc.Kind + "|" + e.tenant + "|" + doc.Name
		if j, dup := seen[e.key]; dup {
			p.Errors = append(p.Errors, fmt.Sprintf("documents %d and %d both describe %s %s/%s", j+1, i+1, doc.Kind, e.tenant, doc.Name))
		}
		seen[e.key] = i
	}
	// The bundle as the services would see it after apply: every document is visible to the
	// others' validation, so an agent may name an environment or a connection the same bundle
	// introduces. Canonical specs replace the raw ones as validation proceeds in apply order.
	ov := &overlay{base: d.Store, pending: map[string]*model.CatalogItem{}, fixed: map[string]int{}}
	for _, e := range entries {
		if len(e.change.Errors) == 0 {
			ov.pending[e.key] = &model.CatalogItem{Kind: e.doc.Kind, Tenant: e.tenant, Name: e.doc.Name, Description: e.doc.Description, Spec: e.doc.Spec}
		}
	}
	// The same validators the API runs on a PUT, over the overlay instead of the live store.
	svc := services.Assemble(ov, services.Options{Policies: d.Policies, Images: d.Images, Secrets: d.Secrets, Defaults: d.Defaults, Now: now})
	tset, bind, conns, cat := svc.Tenants, svc.Bindings, svc.Connections, svc.Catalog

	order := append([]*entry(nil), entries...)
	sort.SliceStable(order, func(i, j int) bool { return kindRank[order[i].doc.Kind] < kindRank[order[j].doc.Kind] })
	validate := func() error {
		for name, r := range map[string]interface{ Refresh(context.Context) error }{"tenant settings": tset, "bindings": bind} {
			if err := r.Refresh(ctx); err != nil {
				return fmt.Errorf("plan: load %s: %w", name, err)
			}
		}
		for _, e := range order {
			if len(e.change.Errors) > 0 {
				continue
			}
			var err error
			switch e.doc.Kind {
			case model.KindEnvironment, model.KindAgent:
				e.item, err = cat.Validate(ctx, e.doc.Kind, e.tenant, e.doc, scope.Admin, scope.Subject)
			case model.KindConnection:
				e.item, err = conns.Validate(ctx, e.tenant, e.doc, scope.Admin, scope.Subject)
			case model.KindBinding:
				e.item, err = bind.Validate(ctx, e.tenant, e.doc, scope.Admin, scope.Subject)
			case model.KindTenantSettings:
				e.item, err = tset.Validate(ctx, e.tenant, e.doc, scope.Subject)
			}
			if err != nil {
				e.change.Errors = append(e.change.Errors, err.Error())
				delete(ov.pending, e.key) // an invalid document is not something others may depend on
				continue
			}
			ov.pending[e.key] = e.item
		}
		return nil
	}
	if err := validate(); err != nil {
		return nil, nil, err
	}
	// Compare each candidate with the live state and decide the action; the overlay then
	// presents the revision apply will really produce (a noop keeps the current one, the rest
	// get the next number of the history, deleted revisions included).
	decide := func() error {
		for _, e := range entries {
			c := e.change
			if _, known := kindRank[e.doc.Kind]; !known {
				c.Action = ActionInvalid
				continue
			}
			cur, err := d.Store.GetItem(ctx, e.doc.Kind, e.tenant, e.doc.Name, 0)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			c.CurrentRevision = 0
			if cur != nil {
				c.CurrentRevision = cur.Revision
			}
			c.ExpectedRevision = c.CurrentRevision
			if e.doc.ExpectedRevision != nil && *e.doc.ExpectedRevision != c.CurrentRevision {
				c.Errors = appendOnce(c.Errors, fmt.Sprintf("%s: expected_revision %d, but the current revision is %d", res.ErrConflict, *e.doc.ExpectedRevision, c.CurrentRevision))
			}
			if len(c.Errors) > 0 {
				c.Action, c.NextRevision = ActionInvalid, c.CurrentRevision
				delete(ov.pending, e.key)
				continue
			}
			var from, to map[string]any
			if cur != nil {
				from = flatten(cur.Spec, cur.Description)
			}
			to = flatten(e.item.Spec, e.item.Description)
			c.Diff = diff(from, to)
			switch {
			case cur == nil:
				c.Action = ActionCreate
			case len(c.Diff) == 0:
				c.Action = ActionNoop
			default:
				c.Action = ActionUpdate
			}
			if c.Action == ActionNoop {
				c.NextRevision = c.CurrentRevision
			} else if c.NextRevision, err = ov.nextRevision(ctx, e.doc.Kind, e.tenant, e.doc.Name); err != nil {
				return err
			}
			ov.fixed[e.key] = c.NextRevision
		}
		return nil
	}
	if err := decide(); err != nil {
		return nil, nil, err
	}
	// Second pass: references pinned to a revision the first pass promised but apply will not
	// produce (an item that turns out unchanged) are refused now, not at apply time.
	if err := validate(); err != nil {
		return nil, nil, err
	}
	if err := decide(); err != nil {
		return nil, nil, err
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if kindRank[a.doc.Kind] != kindRank[b.doc.Kind] {
			return kindRank[a.doc.Kind] < kindRank[b.doc.Kind]
		}
		if a.tenant != b.tenant {
			return a.tenant < b.tenant
		}
		return a.doc.Name < b.doc.Name
	})
	h := sha256.New()
	fp := sha256.New()
	fmt.Fprintf(fp, "scope %s admin=%v\n", scope.Tenant, scope.Admin)
	var items []*model.CatalogItem
	for _, e := range entries {
		if e.change.Action == ActionInvalid {
			items = append(items, nil)
		} else {
			items = append(items, e.item)
			e.change.Resolved = ResolvedOf(e.item)
		}
		p.Changes = append(p.Changes, *e.change)
		// The state the plan saw (action, revisions) and what it resolved to: a bundle whose
		// references would now resolve to other items is another plan, whatever its documents.
		fmt.Fprintf(fp, "%s|%s|%s %s %d %d %s\n", e.doc.Kind, e.tenant, e.doc.Name, e.change.Action, e.change.ExpectedRevision, e.change.NextRevision, e.change.Resolved)
		switch e.change.Action {
		case ActionCreate:
			p.Summary.Create++
		case ActionUpdate:
			p.Summary.Update++
		case ActionNoop:
			p.Summary.Noop++
		default:
			p.Summary.Invalid++
		}
		// The documents as submitted (not as resolved): the same request stays the same bundle
		// whatever its references resolve to later, so an idempotency key keeps matching.
		fmt.Fprintf(h, "%s|%s|%s\n%s\n%s\n", e.doc.Kind, e.tenant, e.doc.Name, e.doc.Description, canonical(e.doc.Spec))
	}
	p.Bundle = hex.EncodeToString(h.Sum(nil))[:16]
	fmt.Fprintf(fp, "bundle %s\n", p.Bundle)
	p.Fingerprint = hex.EncodeToString(fp.Sum(nil))[:16]
	p.Valid = len(p.Errors) == 0 && p.Summary.Invalid == 0
	return p, items, nil
}

// ResolvedOf is the fingerprint of an item as it would be written: description and canonical
// spec, references resolved.
func ResolvedOf(it *model.CatalogItem) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s", it.Description, canonical(it.Spec))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func appendOnce(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}

// canonical renders JSON with sorted keys and no insignificant whitespace.
func canonical(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return strings.TrimSpace(string(raw))
	}
	b, _ := json.Marshal(v) // encoding/json sorts map keys
	return string(b)
}

// flatten turns a spec (and the description) into path → leaf value.
func flatten(spec json.RawMessage, description string) map[string]any {
	out := map[string]any{}
	if description != "" {
		out["description"] = description
	}
	var v any
	if err := json.Unmarshal(spec, &v); err != nil {
		out["spec"] = strings.TrimSpace(string(spec))
		return out
	}
	walk("spec", v, out)
	return out
}

func walk(path string, v any, out map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		// An empty object says nothing (a struct field rendered as {}): no leaf.
		for k, sub := range x {
			walk(path+"."+k, sub, out)
		}
	case []any:
		if len(x) == 0 {
			out[path] = []any{}
			return
		}
		for i, sub := range x {
			walk(path+"["+strconv.Itoa(i)+"]", sub, out)
		}
	default:
		out[path] = v
	}
}

// Diff is the stable field diff between two revisions of an item (nil from: a creation), the
// same one a plan reports for a change.
func Diff(from, to *model.CatalogItem) []FieldChange {
	var f, t map[string]any
	if from != nil {
		f = flatten(from.Spec, from.Description)
	}
	if to != nil {
		t = flatten(to.Spec, to.Description)
	}
	return diff(f, t)
}

// diff lists the leaves that differ between from and to, in path order.
func diff(from, to map[string]any) []FieldChange {
	paths := map[string]bool{}
	for k := range from {
		paths[k] = true
	}
	for k := range to {
		paths[k] = true
	}
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []FieldChange
	for _, k := range keys {
		f, inFrom := from[k]
		t, inTo := to[k]
		if inFrom && inTo && reflect.DeepEqual(f, t) {
			continue
		}
		out = append(out, FieldChange{Path: k, From: f, To: t})
	}
	return out
}

// overlay is the store as it would be after the bundle applied: the bundle's documents are
// the latest revisions of their items; everything else is read from the base. Writes are
// refused: planning changes nothing.
type overlay struct {
	base    store.Catalog
	pending map[string]*model.CatalogItem // kind|tenant|name → candidate
	// fixed names the revision a pending item will really have (set once its action is
	// known: a noop keeps the current revision); absent: the next number in the history.
	fixed map[string]int
}

// nextRevision is the number the next write of an item gets: one past the highest ever
// used, deleted revisions included (the store never reuses numbers).
func (o *overlay) nextRevision(ctx context.Context, kind, tenant, name string) (int, error) {
	revs, err := o.base.ListRevisions(ctx, kind, tenant, name)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	max := 0
	for _, r := range revs {
		if r.Revision > max {
			max = r.Revision
		}
	}
	return max + 1, nil
}

// pendingRevision is the revision a pending item presents.
func (o *overlay) pendingRevision(ctx context.Context, key string, p *model.CatalogItem) (int, error) {
	if n, ok := o.fixed[key]; ok {
		return n, nil
	}
	return o.nextRevision(ctx, p.Kind, p.Tenant, p.Name)
}

var errReadOnly = errors.New("plan: the store is read-only while planning")

func (o *overlay) PutItem(context.Context, *model.CatalogItem, int) error   { return errReadOnly }
func (o *overlay) DeleteItem(context.Context, string, string, string) error { return errReadOnly }

func (o *overlay) GetItem(ctx context.Context, kind, tenant, name string, revision int) (*model.CatalogItem, error) {
	key := kind + "|" + tenant + "|" + name
	if p, ok := o.pending[key]; ok {
		next, err := o.pendingRevision(ctx, key, p)
		if err != nil {
			return nil, err
		}
		if revision == 0 || revision == next {
			c := *p
			c.Revision = next
			return &c, nil
		}
	}
	return o.base.GetItem(ctx, kind, tenant, name, revision)
}

func (o *overlay) ListItems(ctx context.Context, kind, tenant string) ([]*model.CatalogItem, error) {
	list, err := o.base.ListItems(ctx, kind, tenant)
	if err != nil {
		return nil, err
	}
	return o.merge(ctx, list, func(it *model.CatalogItem) bool { return it.Kind == kind && it.Tenant == tenant })
}

func (o *overlay) ListKind(ctx context.Context, kind string) ([]*model.CatalogItem, error) {
	list, err := o.base.ListKind(ctx, kind)
	if err != nil {
		return nil, err
	}
	return o.merge(ctx, list, func(it *model.CatalogItem) bool { return it.Kind == kind })
}

func (o *overlay) ListRevisions(ctx context.Context, kind, tenant, name string) ([]*model.CatalogItem, error) {
	return o.base.ListRevisions(ctx, kind, tenant, name)
}

func (o *overlay) ListDeleted(ctx context.Context, kind, tenant string) ([]*model.CatalogItem, error) {
	return o.base.ListDeleted(ctx, kind, tenant)
}

func (o *overlay) merge(ctx context.Context, list []*model.CatalogItem, match func(*model.CatalogItem) bool) ([]*model.CatalogItem, error) {
	byKey := map[string]*model.CatalogItem{}
	for _, it := range list {
		byKey[it.Kind+"|"+it.Tenant+"|"+it.Name] = it
	}
	for k, p := range o.pending {
		if match(p) {
			c := *p
			n, err := o.pendingRevision(ctx, k, p)
			if err != nil {
				return nil, err
			}
			c.Revision = n
			byKey[k] = &c
		}
	}
	out := make([]*model.CatalogItem, 0, len(byKey))
	for _, it := range byKey {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Tenant < out[j].Tenant || out[i].Tenant == out[j].Tenant && out[i].Name < out[j].Name
	})
	return out, nil
}
