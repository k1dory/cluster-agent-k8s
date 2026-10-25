package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"agent-sandbox/internal/model"
)

// Memory is an in-memory Store for tests and `runtime: fake` development.
type Memory struct {
	mu        sync.Mutex
	sandboxes map[string]*model.Sandbox
	runs      map[string]*model.Run
	events    []*model.Event
	instances map[int]*model.Instance
	idem      map[string]*Idempotent
	blobs     map[string][]byte
	blobAt    map[string]time.Time
	tenants   map[string]*sync.Mutex
	catalog   map[string][]*model.CatalogItem // kind|tenant|name → revisions
	applies   map[string]*model.Apply
	apiKeys   map[string]*model.APIKey
	gitSyncs  map[string]*model.GitSync
	creds     map[string]*memCredential // tenant|name
	nextInst  int
	nextEvent int64
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		sandboxes: map[string]*model.Sandbox{},
		runs:      map[string]*model.Run{},
		instances: map[int]*model.Instance{},
		idem:      map[string]*Idempotent{},
		blobs:     map[string][]byte{},
		blobAt:    map[string]time.Time{},
		tenants:   map[string]*sync.Mutex{},
		catalog:   map[string][]*model.CatalogItem{},
		applies:   map[string]*model.Apply{},
		apiKeys:   map[string]*model.APIKey{},
		gitSyncs:  map[string]*model.GitSync{},
		creds:     map[string]*memCredential{},
	}
}

func catalogKey(kind, tenant, name string) string { return kind + "|" + tenant + "|" + name }

func cloneItem(it *model.CatalogItem) *model.CatalogItem {
	c := *it
	c.Spec = append([]byte(nil), it.Spec...)
	if it.DeletedAt != nil {
		d := *it.DeletedAt
		c.DeletedAt = &d
	}
	if it.Source != nil {
		src := *it.Source
		c.Source = &src
	}
	return &c
}

func (m *Memory) PutItem(_ context.Context, it *model.CatalogItem, expected int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.putItem(it, expected)
}

// putItem is PutItem under the lock already held.
func (m *Memory) putItem(it *model.CatalogItem, expected int) error {
	k := catalogKey(it.Kind, it.Tenant, it.Name)
	revs := m.catalog[k]
	latest, current := 0, 0 // highest number ever used; latest live revision (0 when deleted)
	if len(revs) > 0 {
		last := revs[len(revs)-1]
		latest = last.Revision
		if last.DeletedAt == nil {
			current = last.Revision
		}
	}
	if expected >= 0 && expected != current {
		return fmt.Errorf("%w: latest revision is %d, expected %d", ErrConflict, current, expected)
	}
	it.Revision = latest + 1
	it.CreatedAt = time.Now()
	it.DeletedAt = nil
	m.catalog[k] = append(revs, cloneItem(it))
	return nil
}

func (m *Memory) GetItem(_ context.Context, kind, tenant, name string, revision int) (*model.CatalogItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	revs := m.catalog[catalogKey(kind, tenant, name)]
	if len(revs) == 0 {
		return nil, ErrNotFound
	}
	if revision == 0 {
		if last := revs[len(revs)-1]; last.DeletedAt == nil {
			return cloneItem(last), nil
		}
		return nil, ErrNotFound
	}
	for _, r := range revs {
		if r.Revision == revision && r.DeletedAt == nil {
			return cloneItem(r), nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) ListItems(_ context.Context, kind, tenant string) ([]*model.CatalogItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.CatalogItem
	for _, revs := range m.catalog {
		if len(revs) == 0 || revs[0].Kind != kind || revs[0].Tenant != tenant || revs[len(revs)-1].DeletedAt != nil {
			continue
		}
		out = append(out, cloneItem(revs[len(revs)-1]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) ListKind(_ context.Context, kind string) ([]*model.CatalogItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.CatalogItem
	for _, revs := range m.catalog {
		if len(revs) == 0 || revs[0].Kind != kind || revs[len(revs)-1].DeletedAt != nil {
			continue
		}
		out = append(out, cloneItem(revs[len(revs)-1]))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Tenant < out[j].Tenant || out[i].Tenant == out[j].Tenant && out[i].Name < out[j].Name
	})
	return out, nil
}

func (m *Memory) ListDeleted(_ context.Context, kind, tenant string) ([]*model.CatalogItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.CatalogItem
	for _, revs := range m.catalog {
		if len(revs) == 0 || revs[0].Kind != kind || revs[0].Tenant != tenant || revs[len(revs)-1].DeletedAt == nil {
			continue
		}
		out = append(out, cloneItem(revs[len(revs)-1]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) ListRevisions(_ context.Context, kind, tenant, name string) ([]*model.CatalogItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	revs := m.catalog[catalogKey(kind, tenant, name)]
	if len(revs) == 0 {
		return nil, ErrNotFound
	}
	out := make([]*model.CatalogItem, 0, len(revs))
	for _, r := range revs {
		out = append(out, cloneItem(r))
	}
	return out, nil
}

func (m *Memory) DeleteItem(_ context.Context, kind, tenant, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	deleted := 0
	for _, r := range m.catalog[catalogKey(kind, tenant, name)] {
		if r.DeletedAt == nil {
			r.DeletedAt = &now
			deleted++
		}
	}
	if deleted == 0 {
		return ErrNotFound
	}
	return nil
}

// WithTenantLock serialises per tenant within this process (one process is all a memory store has).
func (m *Memory) WithTenantLock(ctx context.Context, tenant string, fn func(ctx context.Context) error) error {
	m.mu.Lock()
	l, ok := m.tenants[tenant]
	if !ok {
		l = &sync.Mutex{}
		m.tenants[tenant] = l
	}
	m.mu.Unlock()
	l.Lock()
	defer l.Unlock()
	return fn(ctx)
}

type memLease struct{}

func (memLease) Ping(context.Context) error { return nil }
func (memLease) Release()                   {}

// TryLead always succeeds: a memory store never has a second replica.
func (m *Memory) TryLead(context.Context, string) (Lease, bool, error) { return memLease{}, true, nil }

func (m *Memory) GetOrCreateBlob(_ context.Context, name string, create func() ([]byte, error)) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.blobs[name]; ok {
		return append([]byte(nil), b...), nil
	}
	b, err := create()
	if err != nil {
		return nil, err
	}
	m.blobs[name] = append([]byte(nil), b...)
	m.blobAt[name] = time.Now()
	return b, nil
}

func (m *Memory) PutBlob(_ context.Context, name string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.blobs[name] = append([]byte(nil), data...)
	m.blobAt[name] = time.Now()
	return nil
}

func (m *Memory) GetBlob(_ context.Context, name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.blobs[name]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), b...), nil
}

func (m *Memory) DeleteBlob(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blobs, name)
	delete(m.blobAt, name)
	return nil
}

func (m *Memory) DeleteBlobsBefore(_ context.Context, prefix string, t time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for name, at := range m.blobAt {
		if strings.HasPrefix(name, prefix) && at.Before(t) {
			delete(m.blobs, name)
			delete(m.blobAt, name)
			n++
		}
	}
	return n, nil
}

func cloneSandbox(s *model.Sandbox) *model.Sandbox {
	c := *s
	if s.Preview != nil {
		p := *s.Preview
		c.Preview = &p
	}
	if s.Launch != nil {
		l := *s.Launch
		if s.Launch.Env != nil {
			l.Env = map[string]string{}
			for k, v := range s.Launch.Env {
				l.Env[k] = v
			}
		}
		c.Launch = &l
	}
	c.Connections = append([]string(nil), s.Connections...)
	return &c
}

func (m *Memory) CreateSandbox(_ context.Context, s *model.Sandbox) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.Revision = 1
	m.sandboxes[s.ID] = cloneSandbox(s)
	return nil
}

func (m *Memory) GetSandbox(_ context.Context, id string) (*model.Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sandboxes[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneSandbox(s), nil
}

func (m *Memory) ListSandboxes(_ context.Context) ([]*model.Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*model.Sandbox, 0, len(m.sandboxes))
	for _, s := range m.sandboxes {
		out = append(out, cloneSandbox(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) UpdateSandbox(_ context.Context, s *model.Sandbox) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.sandboxes[s.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Revision != s.Revision {
		return ErrConflict
	}
	s.Revision++
	c := cloneSandbox(s)
	// Like Postgres (GREATEST): a Touch that landed after the caller's read is not rolled back.
	if cur.LastActivity.After(c.LastActivity) {
		c.LastActivity = cur.LastActivity
	}
	m.sandboxes[s.ID] = c
	return nil
}

func (m *Memory) TouchSandbox(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.sandboxes[id]
	if !ok {
		return ErrNotFound
	}
	if at.After(cur.LastActivity) {
		cur.LastActivity = at
	}
	return nil
}

func (m *Memory) DeleteSandbox(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sandboxes[id]; !ok {
		return ErrNotFound
	}
	delete(m.sandboxes, id)
	return nil
}

func (m *Memory) SandboxByPreviewHost(_ context.Context, host string) (*model.Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sandboxes {
		if s.Preview != nil && s.Preview.Host == host {
			return cloneSandbox(s), nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) CreateRun(_ context.Context, r *model.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *r
	m.runs[r.ID] = &c
	return nil
}

func (m *Memory) GetRun(_ context.Context, id string) (*model.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *r
	return &c, nil
}

func (m *Memory) UpdateRun(_ context.Context, r *model.Run) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.runs[r.ID]; !ok {
		return ErrNotFound
	}
	c := *r
	m.runs[r.ID] = &c
	return nil
}

func (m *Memory) runsOf(sandboxID string) []*model.Run {
	var out []*model.Run
	for _, r := range m.runs {
		if r.SandboxID == sandboxID {
			c := *r
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (m *Memory) ListRuns(_ context.Context, sandboxID string) ([]*model.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.runsOf(sandboxID), nil
}

func (m *Memory) ClaimQueuedRun(_ context.Context, sandboxID string, startedAt time.Time) (*model.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.runsOf(sandboxID) {
		if c.Status == model.RunQueued {
			r := m.runs[c.ID]
			r.Status, r.StartedAt = model.RunRunning, &startedAt
			out := *r
			return &out, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) RunningRun(_ context.Context, sandboxID string) (*model.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.runsOf(sandboxID) {
		if r.Status == model.RunRunning {
			return r, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) AppendEvent(_ context.Context, e *model.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextEvent++
	e.ID = m.nextEvent
	if e.At.IsZero() {
		e.At = time.Now()
	}
	c := *e
	m.events = append(m.events, &c)
	return nil
}

func (m *Memory) ListEvents(_ context.Context, sandboxID string, afterID int64, limit int) ([]*model.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.Event
	for _, e := range m.events {
		if e.SandboxID == sandboxID && e.ID > afterID {
			c := *e
			out = append(out, &c)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (m *Memory) NextInstance(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextInst++
	return m.nextInst, nil
}

func (m *Memory) CreateInstance(_ context.Context, in *model.Instance) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *in
	m.instances[in.N] = &c
	return nil
}

func (m *Memory) InstanceBySerial(_ context.Context, serial string) (*model.Instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, in := range m.instances {
		if in.Serial == serial {
			c := *in
			return &c, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Memory) RetireInstance(_ context.Context, n int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.instances[n]
	if !ok {
		return ErrNotFound
	}
	if in.RetiredAt == nil {
		t := time.Now()
		in.RetiredAt = &t
	}
	return nil
}

func (m *Memory) ListInstances(_ context.Context, sandboxID string) ([]*model.Instance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.Instance
	for _, in := range m.instances {
		if in.SandboxID == sandboxID {
			c := *in
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N < out[j].N })
	return out, nil
}

func (m *Memory) ReserveIdempotent(_ context.Context, key, bodyHash string) (*Idempotent, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, v := range m.idem {
		if v.CreatedAt.Before(now.Add(-IdempotencyTTL)) || v.InProgress() && v.CreatedAt.Before(now.Add(-IdempotencyStale)) {
			delete(m.idem, k)
		}
	}
	if v, ok := m.idem[key]; ok {
		c := *v
		return &c, false, nil
	}
	m.idem[key] = &Idempotent{Key: key, BodyHash: bodyHash, CreatedAt: now}
	return nil, true, nil
}

func (m *Memory) PutIdempotent(_ context.Context, rec *Idempotent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *rec
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	m.idem[rec.Key] = &c
	return nil
}

func (m *Memory) ReleaseIdempotent(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.idem, key)
	return nil
}

func (m *Memory) GetIdempotent(_ context.Context, key string) (*Idempotent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.idem[key]
	if !ok || v.CreatedAt.Before(time.Now().Add(-IdempotencyTTL)) {
		return nil, ErrNotFound
	}
	c := *v
	return &c, nil
}

func (m *Memory) Close() error { return nil }

func (m *Memory) QuerySandboxes(_ context.Context, f SandboxFilter) ([]*model.Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []*model.Sandbox
	for _, s := range m.sandboxes {
		if f.Tenant != "" && s.Tenant != f.Tenant || f.Owner != "" && s.Owner != f.Owner ||
			f.Slug != "" && s.Slug != f.Slug || f.Status != "" && string(s.Status) != f.Status ||
			f.Instance != 0 && s.Instance != f.Instance {
			continue
		}
		all = append(all, s)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].ID < all[j].ID
		}
		return all[i].CreatedAt.Before(all[j].CreatedAt)
	})
	var out []*model.Sandbox
	for _, s := range all {
		if !f.Cursor.after(s.CreatedAt, s.ID) {
			continue
		}
		out = append(out, cloneSandbox(s))
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}

func (m *Memory) CountSandboxes(_ context.Context, tenant, slug string) (SandboxCounts, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var c SandboxCounts
	for _, s := range m.sandboxes {
		if s.Tenant != tenant || slug != "" && s.Slug != slug {
			continue
		}
		c.Total++
		switch s.Status {
		case model.StatusCreating, model.StatusWaking, model.StatusRunning:
			c.Awake++
		}
	}
	return c, nil
}

func (f Filter) matchRun(r *model.Run) bool {
	if f.Tenant != "" && r.Tenant != f.Tenant {
		return false
	}
	if f.Status != "" && string(r.Status) != f.Status {
		return false
	}
	if f.Slug != "" && r.Slug != f.Slug {
		return false
	}
	if f.SandboxID != "" && r.SandboxID != f.SandboxID {
		return false
	}
	if f.RunID != "" && r.ID != f.RunID {
		return false
	}
	if !f.From.IsZero() && r.CreatedAt.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && !r.CreatedAt.Before(f.To) {
		return false
	}
	return true
}

func (f Filter) matchEvent(e *model.Event) bool {
	if f.Tenant != "" && e.Tenant != f.Tenant {
		return false
	}
	if f.Slug != "" && e.Slug != f.Slug {
		return false
	}
	if f.SandboxID != "" && e.SandboxID != f.SandboxID {
		return false
	}
	if f.RunID != "" && e.RunID != f.RunID {
		return false
	}
	if f.RunScope != "" && e.RunID != "" && e.RunID != f.RunScope {
		return false
	}
	if e.ID <= f.AfterID {
		return false
	}
	if !f.From.IsZero() && e.At.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && !e.At.Before(f.To) {
		return false
	}
	if len(f.Types) > 0 {
		ok := false
		for _, t := range f.Types {
			if t == e.Type {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func (m *Memory) QueryRuns(_ context.Context, f Filter) ([]*model.Run, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []*model.Run
	for _, r := range m.runs {
		if f.matchRun(r) {
			all = append(all, r)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].ID < all[j].ID
		}
		return all[i].CreatedAt.Before(all[j].CreatedAt)
	})
	var out []*model.Run
	for _, r := range all {
		if !f.Cursor.after(r.CreatedAt, r.ID) {
			continue
		}
		c := *r
		out = append(out, &c)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}

func (m *Memory) QueryEvents(_ context.Context, f Filter) ([]*model.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.Event
	for _, e := range m.events {
		if f.matchEvent(e) {
			c := *e
			out = append(out, &c)
			if f.Limit > 0 && len(out) >= f.Limit {
				break
			}
		}
	}
	return out, nil
}

func (m *Memory) CountEvents(_ context.Context, f Filter) ([]EventCount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	type key struct {
		tenant, slug, sb, run, typ string
		day                        time.Time
	}
	counts := map[key]int64{}
	var order []key
	for _, e := range m.events {
		if !f.matchEvent(e) {
			continue
		}
		k := key{e.Tenant, e.Slug, e.SandboxID, e.RunID, e.Type, e.At.UTC().Truncate(24 * time.Hour)}
		if _, ok := counts[k]; !ok {
			order = append(order, k)
		}
		counts[k]++
	}
	out := make([]EventCount, 0, len(order))
	for _, k := range order {
		out = append(out, EventCount{Tenant: k.tenant, Slug: k.slug, SandboxID: k.sb, RunID: k.run, Type: k.typ, Day: k.day, N: counts[k]})
	}
	return out, nil
}

// --- applies ---------------------------------------------------------------------------

func cloneApply(a *model.Apply) *model.Apply {
	c := *a
	c.Steps = append([]model.ApplyStep(nil), a.Steps...)
	c.Documents = append(json.RawMessage(nil), a.Documents...)
	if a.LeaseUntil != nil {
		t := *a.LeaseUntil
		c.LeaseUntil = &t
	}
	return &c
}

func (m *Memory) CreateApply(_ context.Context, a *model.Apply) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.applies {
		if e.Tenant == a.Tenant && e.Key == a.Key {
			return fmt.Errorf("%w: apply with key %q exists", ErrConflict, a.Key)
		}
	}
	a.Version, a.CreatedAt, a.UpdatedAt = 1, time.Now(), time.Now()
	m.applies[a.ID] = cloneApply(a)
	return nil
}

func (m *Memory) GetApply(_ context.Context, id string) (*model.Apply, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.applies[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneApply(a), nil
}

func (m *Memory) GetApplyByKey(_ context.Context, tenant, key string) (*model.Apply, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range m.applies {
		if a.Tenant == tenant && a.Key == key {
			return cloneApply(a), nil
		}
	}
	return nil, ErrNotFound
}

// updateApply is UpdateApply under the lock already held.
func (m *Memory) updateApply(a *model.Apply) error {
	cur, ok := m.applies[a.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != a.Version {
		return fmt.Errorf("%w: apply %s changed concurrently", ErrConflict, a.ID)
	}
	a.Version++
	a.UpdatedAt = time.Now()
	m.applies[a.ID] = cloneApply(a)
	return nil
}

func (m *Memory) UpdateApply(_ context.Context, a *model.Apply) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.updateApply(a)
}

func (m *Memory) ApplyStep(_ context.Context, a *model.Apply, step int, it *model.CatalogItem, expected int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if step < 0 || step >= len(a.Steps) {
		return fmt.Errorf("%w: step %d out of range", ErrConflict, step)
	}
	cur, ok := m.applies[a.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Version != a.Version {
		return fmt.Errorf("%w: apply %s changed concurrently", ErrConflict, a.ID)
	}
	st := &a.Steps[step]
	if it == nil {
		// A noop step confirms the revision it planned on, atomically with its progress.
		if current := m.currentRevision(st.Kind, st.Tenant, st.Name); current != expected {
			return fmt.Errorf("%w: %s %s/%s is at revision %d, expected %d", ErrConflict, st.Kind, st.Tenant, st.Name, current, expected)
		}
		st.Revision = expected
		return m.updateApply(a)
	}
	if next := m.nextRevisionNumber(it.Kind, it.Tenant, it.Name); st.NextRevision != 0 && next != st.NextRevision {
		return fmt.Errorf("%w: %s %s/%s would become revision %d, the plan promised %d", ErrConflict, it.Kind, it.Tenant, it.Name, next, st.NextRevision)
	}
	if err := m.putItem(it, expected); err != nil {
		return err
	}
	st.Revision = it.Revision
	return m.updateApply(a)
}

// currentRevision is the latest live revision of an item (0: absent or deleted); lock held.
func (m *Memory) currentRevision(kind, tenant, name string) int {
	revs := m.catalog[catalogKey(kind, tenant, name)]
	if len(revs) == 0 || revs[len(revs)-1].DeletedAt != nil {
		return 0
	}
	return revs[len(revs)-1].Revision
}

// nextRevisionNumber is what the next write of an item gets; lock held.
func (m *Memory) nextRevisionNumber(kind, tenant, name string) int {
	revs := m.catalog[catalogKey(kind, tenant, name)]
	if len(revs) == 0 {
		return 1
	}
	return revs[len(revs)-1].Revision + 1
}

func (m *Memory) ListApplies(_ context.Context, tenant string, limit int) ([]*model.Apply, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.Apply
	for _, a := range m.applies {
		if tenant == "" || a.Tenant == tenant {
			out = append(out, cloneApply(a))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// --- api keys ---------------------------------------------------------------------------

func cloneKey(k *model.APIKey) *model.APIKey {
	c := *k
	for _, p := range []**time.Time{&c.ExpiresAt, &c.RevokedAt, &c.LastUsedAt} {
		if *p != nil {
			t := **p
			*p = &t
		}
	}
	return &c
}

func (m *Memory) CreateAPIKey(_ context.Context, k *model.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.apiKeys[k.ID]; dup {
		return fmt.Errorf("%w: api key %s exists", ErrConflict, k.ID)
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	m.apiKeys[k.ID] = cloneKey(k)
	return nil
}

func (m *Memory) GetAPIKey(_ context.Context, id string) (*model.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneKey(k), nil
}

func (m *Memory) TouchAPIKey(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[id]
	if !ok {
		return ErrNotFound
	}
	t := at
	k.LastUsedAt = &t
	return nil
}

func (m *Memory) RevokeAPIKey(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[id]
	if !ok {
		return ErrNotFound
	}
	if k.RevokedAt == nil {
		t := at
		k.RevokedAt = &t
	}
	return nil
}

func (m *Memory) RetireAPIKey(_ context.Context, id, rotatedTo string, at time.Time, grace time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[id]
	if !ok {
		return ErrNotFound
	}
	k.RotatedTo = rotatedTo
	if grace <= 0 {
		if k.RevokedAt == nil {
			t := at
			k.RevokedAt = &t
		}
		return nil
	}
	end := at.Add(grace)
	if k.ExpiresAt == nil || end.Before(*k.ExpiresAt) {
		k.ExpiresAt = &end
	}
	return nil
}

func (m *Memory) ListAPIKeys(_ context.Context, tenant string) ([]*model.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.APIKey
	for _, k := range m.apiKeys {
		if tenant == "" || k.Tenant == tenant {
			out = append(out, cloneKey(k))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// --- credentials ------------------------------------------------------------------------

type memCredential struct {
	meta       model.Credential
	ciphertext []byte
}

func (m *Memory) PutCredential(_ context.Context, c *model.Credential, ciphertext []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := c.Tenant + "|" + c.Name
	now := time.Now()
	cur, ok := m.creds[key]
	if ok {
		c.Version, c.CreatedAt, c.CreatedBy, c.UpdatedAt = cur.meta.Version+1, cur.meta.CreatedAt, cur.meta.CreatedBy, now
	} else {
		c.Version, c.CreatedAt, c.UpdatedAt = 1, now, now
	}
	m.creds[key] = &memCredential{meta: *c, ciphertext: append([]byte(nil), ciphertext...)}
	return !ok, nil
}

func (m *Memory) GetCredential(_ context.Context, tenant, name string) (*model.Credential, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.creds[tenant+"|"+name]
	if !ok {
		return nil, nil, ErrNotFound
	}
	meta := cur.meta
	return &meta, append([]byte(nil), cur.ciphertext...), nil
}

func (m *Memory) ListCredentials(_ context.Context, tenant string) ([]*model.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*model.Credential
	for _, c := range m.creds {
		if c.meta.Tenant == tenant {
			meta := c.meta
			out = append(out, &meta)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) DeleteCredential(_ context.Context, tenant, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tenant + "|" + name
	if _, ok := m.creds[key]; !ok {
		return ErrNotFound
	}
	delete(m.creds, key)
	return nil
}

// --- Git repositories: last known state -------------------------------------------------------

func cloneGitSync(g *model.GitSync) *model.GitSync {
	c := *g
	if g.Check != nil {
		ck := *g.Check
		c.Check = &ck
	}
	if g.Sync != nil {
		sy := *g.Sync
		sy.Bundles = make([]model.GitSyncBundle, len(g.Sync.Bundles))
		for i, b := range g.Sync.Bundles {
			b.Errors = append([]string(nil), b.Errors...)
			sy.Bundles[i] = b
		}
		c.Sync = &sy
	}
	return &c
}

func (m *Memory) gitSync(tenant, name string) *model.GitSync {
	key := tenant + "|" + name
	g, ok := m.gitSyncs[key]
	if !ok {
		g = &model.GitSync{Tenant: tenant, Name: name}
		m.gitSyncs[key] = g
	}
	g.UpdatedAt = time.Now()
	return g
}

func (m *Memory) RecordGitCheck(_ context.Context, tenant, name string, c model.GitCheck) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gitSync(tenant, name).Check = &c
	return nil
}

func (m *Memory) RecordGitSync(_ context.Context, tenant, name string, r model.GitSyncResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := cloneGitSync(&model.GitSync{Sync: &r})
	m.gitSync(tenant, name).Sync = copied.Sync
	return nil
}

func (m *Memory) GetGitSync(_ context.Context, tenant, name string) (*model.GitSync, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.gitSyncs[tenant+"|"+name]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneGitSync(g), nil
}
