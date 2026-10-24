package store

import (
	"context"
	"sort"
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
	tenants   map[string]*sync.Mutex
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
		tenants:   map[string]*sync.Mutex{},
	}
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
	return b, nil
}

func cloneSandbox(s *model.Sandbox) *model.Sandbox {
	c := *s
	if s.Preview != nil {
		p := *s.Preview
		c.Preview = &p
	}
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
	c.LastActivity = s.LastActivity
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

func (m *Memory) CountSandboxes(_ context.Context, tenant string) (SandboxCounts, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var c SandboxCounts
	for _, s := range m.sandboxes {
		if s.Tenant != tenant {
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
