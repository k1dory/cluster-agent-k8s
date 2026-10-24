// Package resource holds what every versioned configuration resource shares: the document
// shape the API and declarative files use, strict parsing, reference syntax and a snapshot
// cache over the store. The catalogue (AgentDefinition, EnvironmentProfile), Connections,
// PolicyBindings and TenantSettings are built on it, each in its own package.
package resource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Errors the API maps to status codes.
var (
	ErrInvalid   = errors.New("invalid")   // 400 / 422
	ErrForbidden = errors.New("forbidden") // 403: a reference or scope the caller may not use
	ErrConflict  = store.ErrConflict       // 409
	ErrNotFound  = store.ErrNotFound       // 404
)

// NameRe is the shape of every resource name (a DNS label).
var NameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// SharedPrefix marks a reference to a shared item: "shared/name".
const SharedPrefix = "shared/"

// Document is the wire and file form of an item of any kind.
type Document struct {
	Kind             string          `yaml:"kind,omitempty" json:"kind,omitempty"`
	Tenant           *string         `yaml:"tenant,omitempty" json:"tenant,omitempty"` // admin only; "" = shared
	Name             string          `yaml:"name" json:"name"`
	Description      string          `yaml:"description,omitempty" json:"description,omitempty"`
	Spec             json.RawMessage `yaml:"spec" json:"spec"`
	ExpectedRevision *int            `yaml:"expected_revision,omitempty" json:"expected_revision,omitempty"`
}

// Expected is the store's expected-revision argument for this document (-1: any).
func (d *Document) Expected() int {
	if d.ExpectedRevision == nil {
		return -1
	}
	return *d.ExpectedRevision
}

// ParseYAML reads one declarative document (strict: unknown fields are errors). A file with
// several documents is refused: nothing is applied silently; use ParseYAMLAll for a batch.
func ParseYAML(raw []byte) (*Document, error) {
	docs, err := ParseYAMLAll(raw)
	if err != nil {
		return nil, err
	}
	switch len(docs) {
	case 0:
		return nil, fmt.Errorf("%w: no document", ErrInvalid)
	case 1:
		return docs[0], nil
	}
	return nil, fmt.Errorf("%w: %d documents in one input; apply them as a batch", ErrInvalid, len(docs))
}

// ParseYAMLAll reads every document of a YAML stream (--- separated), in order, each strict.
// Empty documents are skipped.
func ParseYAMLAll(raw []byte) ([]*Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var docs []*Document
	for n := 1; ; n++ {
		var generic map[string]any
		err := dec.Decode(&generic)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: document %d: %v", ErrInvalid, n, err)
		}
		if len(generic) == 0 {
			continue
		}
		// Round-trip through JSON so the spec is validated by the same strict decoder as the API.
		b, err := json.Marshal(generic)
		if err != nil {
			return nil, err
		}
		d, err := ParseJSON(b)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", n, err)
		}
		docs = append(docs, d)
	}
}

// ParseJSON reads one API body (strict): unknown fields and anything after the object are errors.
func ParseJSON(raw []byte) (*Document, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var d Document
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: unexpected data after the document", ErrInvalid)
	}
	return &d, nil
}

// DecodeStrict decodes a spec, refusing unknown fields.
func DecodeStrict(raw json.RawMessage, into any) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("%w: spec is required", ErrInvalid)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%w: spec: %v", ErrInvalid, err)
	}
	return nil
}

// CheckDocument validates what every kind shares: the kind matches, the name is a label.
func CheckDocument(d *Document, kind string) error {
	if d.Kind != "" && d.Kind != kind {
		return fmt.Errorf("%w: kind %q does not match %s", ErrInvalid, d.Kind, kind)
	}
	if !NameRe.MatchString(d.Name) {
		return fmt.Errorf("%w: name must match %s", ErrInvalid, NameRe)
	}
	return nil
}

// Ref is a parsed reference: name, optional pinned revision, optional explicit shared scope.
type Ref struct {
	Name   string
	Rev    int  // 0 = latest
	Shared bool // "shared/name": only the shared scope is searched
}

// ParseRef splits "name", "name@N" or "shared/name[@N]".
func ParseRef(raw string) (Ref, error) {
	var r Ref
	rest := raw
	if strings.HasPrefix(rest, SharedPrefix) {
		r.Shared = true
		rest = strings.TrimPrefix(rest, SharedPrefix)
	}
	name, revStr, pinned := strings.Cut(rest, "@")
	if !NameRe.MatchString(name) {
		return r, fmt.Errorf("%q is not a name, name@revision or shared/name", raw)
	}
	r.Name = name
	if !pinned {
		return r, nil
	}
	n, err := strconv.Atoi(revStr)
	if err != nil || n <= 0 {
		return r, fmt.Errorf("%q: revision must be a positive integer", raw)
	}
	r.Rev = n
	return r, nil
}

// InScope renders the reference in the form that names it unambiguously from tenant: the
// shared prefix when it resolved to a shared item seen from a tenant, the pinned revision kept.
func (r Ref) InScope(it *model.CatalogItem, tenant string) string {
	out := r.Name
	if it.Tenant == "" && tenant != "" {
		out = SharedPrefix + out
	}
	if r.Rev > 0 {
		out += "@" + strconv.Itoa(r.Rev)
	}
	return out
}

// Scope is the tenant the reference lives in when read from tenant's scope.
func (r Ref) Scope(tenant string) string {
	if r.Shared {
		return ""
	}
	return tenant
}

// RefOf is the reference string that names an item from tenant's point of view: "name" for
// the tenant's own items, "shared/name" for shared ones (revision not included).
func RefOf(it *model.CatalogItem, tenant string) string {
	return Ref{Name: it.Name}.InScope(it, tenant)
}

// Lookup finds a reference from tenant: an explicitly shared one only among the shared items;
// a bare one in the tenant's scope, then among the shared ones. Another tenant's items are
// invisible: they are simply not found.
func Lookup(ctx context.Context, s store.Catalog, kind, tenant string, r Ref) (*model.CatalogItem, error) {
	if r.Shared || tenant == "" {
		return s.GetItem(ctx, kind, "", r.Name, r.Rev)
	}
	it, err := s.GetItem(ctx, kind, tenant, r.Name, r.Rev)
	if errors.Is(err, store.ErrNotFound) {
		it, err = s.GetItem(ctx, kind, "", r.Name, r.Rev)
	}
	return it, err
}

// ListVisible returns the latest revisions visible from tenant: its own items and the shared
// ones it does not shadow.
func ListVisible(ctx context.Context, s store.Catalog, kind, tenant string) ([]*model.CatalogItem, error) {
	own, err := s.ListItems(ctx, kind, tenant)
	if err != nil {
		return nil, err
	}
	if tenant == "" {
		return own, nil
	}
	shared, err := s.ListItems(ctx, kind, "")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, it := range own {
		seen[it.Name] = true
	}
	for _, it := range shared {
		if !seen[it.Name] {
			own = append(own, it)
		}
	}
	return own, nil
}

// Revisions lists an item's whole history (own scope, else shared), deleted revisions included.
func Revisions(ctx context.Context, s store.Catalog, kind, tenant, name string) ([]*model.CatalogItem, error) {
	revs, err := s.ListRevisions(ctx, kind, tenant, name)
	if errors.Is(err, store.ErrNotFound) && tenant != "" {
		revs, err = s.ListRevisions(ctx, kind, "", name)
	}
	return revs, err
}

// Snapshot is the latest live revision of every item of one kind across tenants, kept in
// memory for decisions made on every request (ownership, quotas). It is refreshed on a
// timer, and at once by the replica that writes; other replicas see a change within Every.
type Snapshot struct {
	Store store.Catalog
	Kind  string
	Every time.Duration // refresh period; 0 = 5s
	// refresh serialises reloads: a reload that started before a write cannot install its
	// (older) reading after the write's own reload, so a revocation is never undone in memory.
	refresh sync.Mutex
	mu      sync.RWMutex
	items   map[string]*model.CatalogItem // tenant|name → latest
	at      time.Time
}

// Refresh reloads the snapshot from the store. Reloads run one at a time, in the order they
// were asked for: the one a write triggers always lands after any reload already in flight.
func (s *Snapshot) Refresh(ctx context.Context) error {
	s.refresh.Lock()
	defer s.refresh.Unlock()
	list, err := s.Store.ListKind(ctx, s.Kind)
	if err != nil {
		return err
	}
	items := make(map[string]*model.CatalogItem, len(list))
	for _, it := range list {
		items[it.Tenant+"|"+it.Name] = it
	}
	s.mu.Lock()
	s.items, s.at = items, time.Now()
	s.mu.Unlock()
	return nil
}

// Watch refreshes periodically until ctx ends; onErr receives failures (the previous snapshot
// stays in use).
func (s *Snapshot) Watch(ctx context.Context, onErr func(error)) {
	every := s.Every
	if every == 0 {
		every = 5 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Refresh(ctx); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

// Get returns the latest live revision of tenant's item, or nil.
func (s *Snapshot) Get(tenant, name string) *model.CatalogItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.items[tenant+"|"+name]
}

// All returns every item of the snapshot.
func (s *Snapshot) All() []*model.CatalogItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.CatalogItem, 0, len(s.items))
	for _, it := range s.items {
		out = append(out, it)
	}
	return out
}

// Loaded reports whether Refresh ever succeeded.
func (s *Snapshot) Loaded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.items != nil
}

// Marshal encodes a validated spec in canonical form.
func Marshal(spec any) (json.RawMessage, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return nil, err
	}
	return b, nil
}
