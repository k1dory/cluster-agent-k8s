package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"agent-sandbox/internal/model"
)

//go:embed migrations.sql
var migrations string

// Postgres is the production Store.
type Postgres struct {
	pool *pgxpool.Pool
	// lockers bounds how many WithTenantLock calls hold a pool connection at once, so the
	// queries they run through other connections always have some left (half the pool).
	lockers chan struct{}
}

// OpenPostgres connects and applies the schema (idempotent). Unless the URL sets pool_max_conns,
// the pool holds up to 16 connections; the leadership lease and the event listener use
// dedicated connections outside the pool.
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(url, "pool_max_conns") && cfg.MaxConns < 16 {
		cfg.MaxConns = 16
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, migrations); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool, lockers: make(chan struct{}, max(1, int(cfg.MaxConns)/2))}, nil
}

// dedicated opens a connection outside the pool for long-held session state (locks, LISTEN).
func (p *Postgres) dedicated(ctx context.Context) (*pgx.Conn, error) {
	return pgx.ConnectConfig(ctx, p.pool.Config().ConnConfig.Copy())
}

func (p *Postgres) Close() error { p.pool.Close(); return nil }

const sandboxCols = `id, name, slug, owner, tenant, repo, idle_timeout, wake_on_preview, status, ip, instance,
	pod_name, last_activity, created_at, expires_at, preview_port, preview_access, preview_host, error,
	agent_version, desired_version, env_version, revision, admin_grant,
	agent_ref, agent_revision, environment_ref, environment_revision, launch, connections`

func scanSandbox(row pgx.Row) (*model.Sandbox, error) {
	var s model.Sandbox
	var pPort *int
	var pAccess, pHost *string
	var launch, conns []byte
	err := row.Scan(&s.ID, &s.Name, &s.Slug, &s.Owner, &s.Tenant, &s.Repo, &s.IdleTimeout, &s.WakeOnPreview,
		&s.Status, &s.IP, &s.Instance, &s.PodName, &s.LastActivity, &s.CreatedAt, &s.ExpiresAt, &pPort, &pAccess, &pHost, &s.Error,
		&s.AgentVersion, &s.DesiredVersion, &s.EnvVersion, &s.Revision, &s.AdminGrant,
		&s.AgentRef, &s.AgentRevision, &s.EnvironmentRef, &s.EnvironmentRevision, &launch, &conns)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(launch) > 0 {
		s.Launch = &model.Launch{}
		if err := json.Unmarshal(launch, s.Launch); err != nil {
			return nil, fmt.Errorf("sandbox %s launch: %w", s.ID, err)
		}
	}
	if len(conns) > 0 {
		if err := json.Unmarshal(conns, &s.Connections); err != nil {
			return nil, fmt.Errorf("sandbox %s connections: %w", s.ID, err)
		}
	}
	if pPort != nil {
		s.Preview = &model.Preview{Port: *pPort}
		if pAccess != nil {
			s.Preview.Access = *pAccess
		}
		if pHost != nil {
			s.Preview.Host = *pHost
		}
	}
	return &s, nil
}

func previewCols(s *model.Sandbox) (*int, *string, *string) {
	if s.Preview == nil {
		return nil, nil, nil
	}
	return &s.Preview.Port, &s.Preview.Access, &s.Preview.Host
}

func launchCol(s *model.Sandbox) []byte {
	if s.Launch == nil {
		return nil
	}
	b, _ := json.Marshal(s.Launch)
	return b
}

func connectionsCol(s *model.Sandbox) []byte {
	if len(s.Connections) == 0 {
		return nil
	}
	b, _ := json.Marshal(s.Connections)
	return b
}

func (p *Postgres) CreateSandbox(ctx context.Context, s *model.Sandbox) error {
	port, access, host := previewCols(s)
	s.Revision = 1
	_, err := p.pool.Exec(ctx, `INSERT INTO sandboxes (`+sandboxCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30)`,
		s.ID, s.Name, s.Slug, s.Owner, s.Tenant, s.Repo, s.IdleTimeout, s.WakeOnPreview, s.Status, s.IP, s.Instance,
		s.PodName, s.LastActivity, s.CreatedAt, s.ExpiresAt, port, access, host, s.Error,
		s.AgentVersion, s.DesiredVersion, s.EnvVersion, s.Revision, s.AdminGrant,
		s.AgentRef, s.AgentRevision, s.EnvironmentRef, s.EnvironmentRevision, launchCol(s), connectionsCol(s))
	return err
}

// WithTenantLock holds a transaction-scoped advisory lock keyed by the tenant while fn runs.
// Other replicas calling it for the same tenant wait; the lock goes with the transaction.
func (p *Postgres) WithTenantLock(ctx context.Context, tenant string, fn func(ctx context.Context) error) error {
	select {
	case p.lockers <- struct{}{}:
		defer func() { <-p.lockers }()
	case <-ctx.Done():
		return ctx.Err()
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "tenant:"+tenant); err != nil {
		return err
	}
	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type pgLease struct {
	conn *pgx.Conn
	name string
	once sync.Once
}

func (l *pgLease) Ping(ctx context.Context) error {
	// A session-level advisory lock lives exactly as long as this connection: if the round trip
	// works the lock is still ours, if the connection is gone so is the leadership.
	var one int
	return l.conn.QueryRow(ctx, `SELECT 1`).Scan(&one)
}

func (l *pgLease) Release() {
	l.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = l.conn.Exec(ctx, `SELECT pg_advisory_unlock(hashtext($1))`, l.name)
		_ = l.conn.Close(ctx)
	})
}

// TryLead takes a session-level advisory lock on a dedicated connection (outside the pool, so
// it never starves request handlers). The lock is held as long as the connection lives, so a
// crashed replica loses leadership automatically.
func (p *Postgres) TryLead(ctx context.Context, name string) (Lease, bool, error) {
	conn, err := p.dedicated(ctx)
	if err != nil {
		return nil, false, err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, name).Scan(&got); err != nil {
		_ = conn.Close(ctx)
		return nil, false, err
	}
	if !got {
		_ = conn.Close(ctx)
		return nil, false, nil
	}
	return &pgLease{conn: conn, name: name}, true, nil
}

func (p *Postgres) GetOrCreateBlob(ctx context.Context, name string, create func() ([]byte, error)) ([]byte, error) {
	var data []byte
	err := p.pool.QueryRow(ctx, `SELECT data FROM blobs WHERE name=$1`, name).Scan(&data)
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	fresh, err := create()
	if err != nil {
		return nil, err
	}
	// Exactly one INSERT wins; everyone reads back whatever is stored.
	if _, err := p.pool.Exec(ctx, `INSERT INTO blobs (name, data) VALUES ($1,$2) ON CONFLICT (name) DO NOTHING`, name, fresh); err != nil {
		return nil, err
	}
	if err := p.pool.QueryRow(ctx, `SELECT data FROM blobs WHERE name=$1`, name).Scan(&data); err != nil {
		return nil, err
	}
	return data, nil
}

func (p *Postgres) PutBlob(ctx context.Context, name string, data []byte) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO blobs (name, data) VALUES ($1,$2) ON CONFLICT (name) DO UPDATE SET data=EXCLUDED.data, created_at=now()`, name, data)
	return err
}

func (p *Postgres) GetBlob(ctx context.Context, name string) ([]byte, error) {
	var data []byte
	err := p.pool.QueryRow(ctx, `SELECT data FROM blobs WHERE name=$1`, name).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return data, err
}

func (p *Postgres) DeleteBlob(ctx context.Context, name string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM blobs WHERE name=$1`, name)
	return err
}

func (p *Postgres) DeleteBlobsBefore(ctx context.Context, prefix string, t time.Time) (int, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM blobs WHERE left(name, length($1)) = $1 AND created_at < $2`, prefix, t)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

const eventsChannel = "agent_sandbox_events"

// ListenEvents feeds events appended by any replica to fn, in id order, until ctx ends.
// NOTIFY wakes the loop; the query by id guarantees nothing is skipped or duplicated even
// when notifications coalesce or the connection is replaced.
func (p *Postgres) ListenEvents(ctx context.Context, fn func(e *model.Event)) {
	var last int64
	_ = p.pool.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM events`).Scan(&last)
	for ctx.Err() == nil {
		if err := p.listenOnce(ctx, &last, fn); err != nil && ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}
}

func (p *Postgres) listenOnce(ctx context.Context, last *int64, fn func(e *model.Event)) error {
	conn, err := p.dedicated(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = conn.Close(cctx)
	}()
	if _, err := conn.Exec(ctx, `LISTEN `+eventsChannel); err != nil {
		return err
	}
	drain := func() error {
		for {
			evs, err := p.QueryEvents(ctx, Filter{AfterID: *last, Limit: 500})
			if err != nil {
				return err
			}
			for _, e := range evs {
				fn(e)
				*last = e.ID
			}
			if len(evs) < 500 {
				return nil
			}
		}
	}
	if err := drain(); err != nil {
		return err
	}
	for {
		// A timeout keeps the loop polling slowly even if a NOTIFY is lost.
		wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err := conn.WaitForNotification(wctx)
		cancel()
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := drain(); err != nil {
			return err
		}
	}
}

func (p *Postgres) GetSandbox(ctx context.Context, id string) (*model.Sandbox, error) {
	return scanSandbox(p.pool.QueryRow(ctx, `SELECT `+sandboxCols+` FROM sandboxes WHERE id=$1`, id))
}

func (p *Postgres) SandboxByPreviewHost(ctx context.Context, host string) (*model.Sandbox, error) {
	return scanSandbox(p.pool.QueryRow(ctx, `SELECT `+sandboxCols+` FROM sandboxes WHERE preview_host=$1`, host))
}

func (p *Postgres) ListSandboxes(ctx context.Context) ([]*model.Sandbox, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+sandboxCols+` FROM sandboxes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Sandbox
	for rows.Next() {
		s, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *Postgres) QuerySandboxes(ctx context.Context, f SandboxFilter) ([]*model.Sandbox, error) {
	var conds []string
	var args []any
	add := func(c string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(c, len(args)))
	}
	if f.Tenant != "" {
		add("tenant=$%d", f.Tenant)
	}
	if f.Owner != "" {
		add("owner=$%d", f.Owner)
	}
	if f.Slug != "" {
		add("slug=$%d", f.Slug)
	}
	if f.Status != "" {
		add("status=$%d", f.Status)
	}
	if f.Instance != 0 {
		add("instance=$%d", f.Instance)
	}
	if !f.Cursor.IsZero() {
		args = append(args, f.Cursor.At, f.Cursor.ID)
		conds = append(conds, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	q := `SELECT ` + sandboxCols + ` FROM sandboxes`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	rows, err := p.pool.Query(ctx, q+` ORDER BY created_at, id`+limitClause(f.Limit, 1000), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Sandbox
	for rows.Next() {
		s, err := scanSandbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *Postgres) CountSandboxes(ctx context.Context, tenant, slug string) (SandboxCounts, error) {
	var c SandboxCounts
	err := p.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status IN ($2,$3,$4)) FROM sandboxes WHERE tenant=$1 AND ($5 = '' OR slug=$5)`,
		tenant, model.StatusCreating, model.StatusWaking, model.StatusRunning, slug).Scan(&c.Total, &c.Awake)
	return c, err
}

func (p *Postgres) UpdateSandbox(ctx context.Context, s *model.Sandbox) error {
	port, access, host := previewCols(s)
	tag, err := p.pool.Exec(ctx, `UPDATE sandboxes SET name=$2, slug=$3, owner=$4, tenant=$5, repo=$6, idle_timeout=$7,
		wake_on_preview=$8, status=$9, ip=$10, instance=$11, pod_name=$12, last_activity=GREATEST(last_activity, $13), expires_at=$14,
		preview_port=$15, preview_access=$16, preview_host=$17, error=$18,
		agent_version=$19, desired_version=$20, env_version=$21, admin_grant=$23,
		agent_ref=$24, agent_revision=$25, environment_ref=$26, environment_revision=$27, launch=$28, connections=$29, revision=revision+1
		WHERE id=$1 AND revision=$22`,
		s.ID, s.Name, s.Slug, s.Owner, s.Tenant, s.Repo, s.IdleTimeout, s.WakeOnPreview, s.Status, s.IP, s.Instance,
		s.PodName, s.LastActivity, s.ExpiresAt, port, access, host, s.Error,
		s.AgentVersion, s.DesiredVersion, s.EnvVersion, s.Revision, s.AdminGrant,
		s.AgentRef, s.AgentRevision, s.EnvironmentRef, s.EnvironmentRevision, launchCol(s), connectionsCol(s))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var one int
		if err := p.pool.QueryRow(ctx, `SELECT 1 FROM sandboxes WHERE id=$1`, s.ID).Scan(&one); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return ErrConflict
	}
	s.Revision++
	return nil
}

func (p *Postgres) TouchSandbox(ctx context.Context, id string, at time.Time) error {
	tag, err := p.pool.Exec(ctx, `UPDATE sandboxes SET last_activity=GREATEST(last_activity, $2) WHERE id=$1`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DeleteSandbox(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM sandboxes WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const runCols = `id, sandbox_id, tenant, slug, task, status, exit_code, created_at, started_at, finished_at,
	model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, turns,
	agent_version, resume_of, session, agent_ref, agent_revision, environment_ref, environment_revision, mode`

func scanRun(row pgx.Row) (*model.Run, error) {
	var r model.Run
	u := &r.Usage
	err := row.Scan(&r.ID, &r.SandboxID, &r.Tenant, &r.Slug, &r.Task, &r.Status, &r.ExitCode, &r.CreatedAt, &r.StartedAt, &r.FinishedAt,
		&u.Model, &u.InputTokens, &u.OutputTokens, &u.CacheRead, &u.CacheWrite, &u.CostUSD, &u.Turns,
		&r.AgentVersion, &r.ResumeOf, &r.Session, &r.AgentRef, &r.AgentRevision, &r.EnvironmentRef, &r.EnvironmentRevision, &r.Mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (p *Postgres) CreateRun(ctx context.Context, r *model.Run) error {
	u := r.Usage
	_, err := p.pool.Exec(ctx, `INSERT INTO runs (`+runCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
		r.ID, r.SandboxID, r.Tenant, r.Slug, r.Task, r.Status, r.ExitCode, r.CreatedAt, r.StartedAt, r.FinishedAt,
		u.Model, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD, u.Turns,
		r.AgentVersion, r.ResumeOf, r.Session, r.AgentRef, r.AgentRevision, r.EnvironmentRef, r.EnvironmentRevision, r.Mode)
	return err
}

func (p *Postgres) GetRun(ctx context.Context, id string) (*model.Run, error) {
	return scanRun(p.pool.QueryRow(ctx, `SELECT `+runCols+` FROM runs WHERE id=$1`, id))
}

func (p *Postgres) UpdateRun(ctx context.Context, r *model.Run) error {
	u := r.Usage
	tag, err := p.pool.Exec(ctx, `UPDATE runs SET status=$2, exit_code=$3, started_at=$4, finished_at=$5,
		model=$6, input_tokens=$7, output_tokens=$8, cache_read_tokens=$9, cache_write_tokens=$10, cost_usd=$11, turns=$12,
		agent_version=$13, session=$14, agent_ref=$15, agent_revision=$16, environment_ref=$17, environment_revision=$18 WHERE id=$1`,
		r.ID, r.Status, r.ExitCode, r.StartedAt, r.FinishedAt, u.Model, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD, u.Turns,
		r.AgentVersion, r.Session, r.AgentRef, r.AgentRevision, r.EnvironmentRef, r.EnvironmentRevision)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) queryRuns(ctx context.Context, q string, args ...any) ([]*model.Run, error) {
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) ListRuns(ctx context.Context, sandboxID string) ([]*model.Run, error) {
	return p.queryRuns(ctx, `SELECT `+runCols+` FROM runs WHERE sandbox_id=$1 ORDER BY created_at`, sandboxID)
}

func (p *Postgres) ClaimQueuedRun(ctx context.Context, sandboxID string, startedAt time.Time) (*model.Run, error) {
	// One statement: pick the oldest queued run, skipping rows another poller is claiming.
	return scanRun(p.pool.QueryRow(ctx, `UPDATE runs SET status=$3, started_at=$4 WHERE id = (
			SELECT id FROM runs WHERE sandbox_id=$1 AND status=$2 ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING `+runCols, sandboxID, model.RunQueued, model.RunRunning, startedAt))
}

func (p *Postgres) RunningRun(ctx context.Context, sandboxID string) (*model.Run, error) {
	return scanRun(p.pool.QueryRow(ctx, `SELECT `+runCols+` FROM runs WHERE sandbox_id=$1 AND status=$2
		ORDER BY created_at LIMIT 1`, sandboxID, model.RunRunning))
}

func (p *Postgres) AppendEvent(ctx context.Context, e *model.Event) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	// The NOTIFY wakes every replica's ListenEvents so their SSE clients see this event.
	return p.pool.QueryRow(ctx, `WITH ins AS (
			INSERT INTO events (sandbox_id, tenant, slug, run_id, type, data, at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id)
		SELECT id FROM ins, pg_notify('`+eventsChannel+`', id::text)`,
		e.SandboxID, e.Tenant, e.Slug, e.RunID, e.Type, e.Data, e.At).Scan(&e.ID)
}

func (p *Postgres) ListEvents(ctx context.Context, sandboxID string, afterID int64, limit int) ([]*model.Event, error) {
	if limit <= 0 {
		limit = 1000
	}
	return p.queryEvents(ctx, `SELECT `+eventCols+` FROM events WHERE sandbox_id=$1 AND id>$2 ORDER BY id LIMIT $3`, sandboxID, afterID, limit)
}

const eventCols = `id, sandbox_id, tenant, slug, run_id, type, data, at`

func (p *Postgres) queryEvents(ctx context.Context, q string, args ...any) ([]*model.Event, error) {
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Event
	for rows.Next() {
		var e model.Event
		if err := rows.Scan(&e.ID, &e.SandboxID, &e.Tenant, &e.Slug, &e.RunID, &e.Type, &e.Data, &e.At); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// where builds the WHERE clause for a Filter. idCol/timeCol name the table's id and time columns.
func (f Filter) where(idCol, timeCol string, events bool) (string, []any) {
	var conds []string
	var args []any
	add := func(c string, v any) {
		args = append(args, v)
		conds = append(conds, fmt.Sprintf(c, len(args)))
	}
	if f.Tenant != "" {
		add("tenant=$%d", f.Tenant)
	}
	if f.Slug != "" {
		add("slug=$%d", f.Slug)
	}
	if f.SandboxID != "" {
		add("sandbox_id=$%d", f.SandboxID)
	}
	if f.RunID != "" {
		if events {
			add("run_id=$%d", f.RunID)
		} else {
			add("id=$%d", f.RunID)
		}
	}
	if events && f.RunScope != "" {
		add("(run_id = '' OR run_id = $%d)", f.RunScope)
	}
	if !events {
		if f.Status != "" {
			add("status=$%d", f.Status)
		}
		if !f.Cursor.IsZero() {
			args = append(args, f.Cursor.At, f.Cursor.ID)
			conds = append(conds, fmt.Sprintf("(created_at, id) > ($%d, $%d)", len(args)-1, len(args)))
		}
	}
	if !f.From.IsZero() {
		add(timeCol+">=$%d", f.From)
	}
	if !f.To.IsZero() {
		add(timeCol+"<$%d", f.To)
	}
	if events {
		if f.AfterID > 0 {
			add(idCol+">$%d", f.AfterID)
		}
		if len(f.Types) > 0 {
			add("type = ANY($%d)", f.Types)
		}
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func limitClause(n, def int) string {
	if n <= 0 {
		n = def
	}
	return fmt.Sprintf(" LIMIT %d", n)
}

func (p *Postgres) QueryRuns(ctx context.Context, f Filter) ([]*model.Run, error) {
	w, args := f.where("id", "created_at", false)
	return p.queryRuns(ctx, `SELECT `+runCols+` FROM runs`+w+` ORDER BY created_at, id`+limitClause(f.Limit, 100000), args...)
}

func (p *Postgres) QueryEvents(ctx context.Context, f Filter) ([]*model.Event, error) {
	w, args := f.where("id", "at", true)
	return p.queryEvents(ctx, `SELECT `+eventCols+` FROM events`+w+` ORDER BY id`+limitClause(f.Limit, 1000), args...)
}

func (p *Postgres) CountEvents(ctx context.Context, f Filter) ([]EventCount, error) {
	w, args := f.where("id", "at", true)
	rows, err := p.pool.Query(ctx, `SELECT tenant, slug, sandbox_id, run_id, type, date_trunc('day', at AT TIME ZONE 'UTC') AS day, count(*)
		FROM events`+w+` GROUP BY 1,2,3,4,5,6 ORDER BY 6`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EventCount
	for rows.Next() {
		var c EventCount
		if err := rows.Scan(&c.Tenant, &c.Slug, &c.SandboxID, &c.RunID, &c.Type, &c.Day, &c.N); err != nil {
			return nil, err
		}
		c.Day = time.Date(c.Day.Year(), c.Day.Month(), c.Day.Day(), 0, 0, 0, 0, time.UTC)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) ReserveIdempotent(ctx context.Context, key, bodyHash string) (*Idempotent, bool, error) {
	// Expired responses and abandoned reservations make room; then the INSERT is the lock:
	// exactly one concurrent caller gets a row back.
	_, _ = p.pool.Exec(ctx, `DELETE FROM idempotency WHERE created_at < now() - $1::interval
		OR (status = 0 AND created_at < now() - $2::interval)`, IdempotencyTTL.String(), IdempotencyStale.String())
	tag, err := p.pool.Exec(ctx, `INSERT INTO idempotency (key, body_hash, status, body, created_at) VALUES ($1,$2,0,'',now())
		ON CONFLICT (key) DO NOTHING`, key, bodyHash)
	if err != nil {
		return nil, false, err
	}
	if tag.RowsAffected() == 1 {
		return nil, true, nil
	}
	existing, err := p.GetIdempotent(ctx, key)
	if errors.Is(err, ErrNotFound) {
		// Released between our INSERT and SELECT; let the caller retry the reservation.
		return p.ReserveIdempotent(ctx, key, bodyHash)
	}
	return existing, false, err
}

func (p *Postgres) PutIdempotent(ctx context.Context, rec *Idempotent) error {
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO idempotency (key, body_hash, status, body, created_at) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (key) DO UPDATE SET status=EXCLUDED.status, body=EXCLUDED.body, created_at=EXCLUDED.created_at`,
		rec.Key, rec.BodyHash, rec.Status, rec.Body, rec.CreatedAt)
	return err
}

func (p *Postgres) ReleaseIdempotent(ctx context.Context, key string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM idempotency WHERE key=$1`, key)
	return err
}

func (p *Postgres) GetIdempotent(ctx context.Context, key string) (*Idempotent, error) {
	var rec Idempotent
	err := p.pool.QueryRow(ctx, `SELECT key, body_hash, status, body, created_at FROM idempotency WHERE key=$1 AND created_at >= now() - $2::interval`,
		key, IdempotencyTTL.String()).Scan(&rec.Key, &rec.BodyHash, &rec.Status, &rec.Body, &rec.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (p *Postgres) NextInstance(ctx context.Context) (int, error) {
	var n int64
	err := p.pool.QueryRow(ctx, `SELECT nextval('instance_seq')`).Scan(&n)
	return int(n), err
}

func (p *Postgres) CreateInstance(ctx context.Context, in *model.Instance) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO instances (n, sandbox_id, slug, tenant, pod_name, serial, issued_at, not_after, retired_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		in.N, in.SandboxID, in.Slug, in.Tenant, in.PodName, in.Serial, in.IssuedAt, in.NotAfter, in.RetiredAt)
	return err
}

const instCols = `n, sandbox_id, slug, tenant, pod_name, serial, issued_at, not_after, retired_at`

func scanInstance(row pgx.Row) (*model.Instance, error) {
	var in model.Instance
	err := row.Scan(&in.N, &in.SandboxID, &in.Slug, &in.Tenant, &in.PodName, &in.Serial, &in.IssuedAt, &in.NotAfter, &in.RetiredAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &in, nil
}

func (p *Postgres) InstanceBySerial(ctx context.Context, serial string) (*model.Instance, error) {
	return scanInstance(p.pool.QueryRow(ctx, `SELECT `+instCols+` FROM instances WHERE serial=$1`, serial))
}

func (p *Postgres) RetireInstance(ctx context.Context, n int) error {
	tag, err := p.pool.Exec(ctx, `UPDATE instances SET retired_at=COALESCE(retired_at, now()) WHERE n=$1`, n)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) ListInstances(ctx context.Context, sandboxID string) ([]*model.Instance, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+instCols+` FROM instances WHERE sandbox_id=$1 ORDER BY n`, sandboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Instance
	for rows.Next() {
		in, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// --- catalogue -------------------------------------------------------------------------

const itemCols = `kind, tenant, name, revision, description, spec, created_by, created_at, deleted_at, source`

func scanItem(row pgx.Row) (*model.CatalogItem, error) {
	var it model.CatalogItem
	var source []byte
	err := row.Scan(&it.Kind, &it.Tenant, &it.Name, &it.Revision, &it.Description, &it.Spec, &it.CreatedBy, &it.CreatedAt, &it.DeletedAt, &source)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(source) > 0 {
		var src model.Source
		if err := json.Unmarshal(source, &src); err != nil {
			return nil, fmt.Errorf("catalog item %s %s/%s@%d: source: %w", it.Kind, it.Tenant, it.Name, it.Revision, err)
		}
		it.Source = &src
	}
	return &it, nil
}

// sourceJSON renders an item's source for the source column (NULL when absent).
func sourceJSON(it *model.CatalogItem) ([]byte, error) {
	if it.Source == nil {
		return nil, nil
	}
	return json.Marshal(it.Source)
}

func (p *Postgres) PutItem(ctx context.Context, it *model.CatalogItem, expected int) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := putItemTx(ctx, tx, it, expected); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// putItemTx appends a revision inside tx (see PutItem).
func putItemTx(ctx context.Context, tx pgx.Tx, it *model.CatalogItem, expected int) error {
	// One writer per item at a time across replicas: the revision check and the insert are atomic.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "catalog:"+it.Kind+"|"+it.Tenant+"|"+it.Name); err != nil {
		return err
	}
	// latest: the highest number ever used (deleted included), so a number is never reused;
	// current: the latest live revision, what a conditional write compares against.
	var latest, current int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision), 0), COALESCE(max(revision) FILTER (WHERE deleted_at IS NULL), 0)
		FROM catalog_items WHERE kind=$1 AND tenant=$2 AND name=$3`, it.Kind, it.Tenant, it.Name).Scan(&latest, &current); err != nil {
		return err
	}
	if expected >= 0 && expected != current {
		return fmt.Errorf("%w: latest revision is %d, expected %d", ErrConflict, current, expected)
	}
	it.Revision = latest + 1
	it.DeletedAt = nil
	source, err := sourceJSON(it)
	if err != nil {
		return err
	}
	return tx.QueryRow(ctx, `INSERT INTO catalog_items (kind, tenant, name, revision, description, spec, created_by, created_at, source)
		VALUES ($1,$2,$3,$4,$5,$6,$7,now(),$8) RETURNING created_at`,
		it.Kind, it.Tenant, it.Name, it.Revision, it.Description, it.Spec, it.CreatedBy, source).Scan(&it.CreatedAt)
}

// --- applies ---------------------------------------------------------------------------

const applyCols = `id, key, tenant, status, doc, version, created_at, updated_at`

func scanApply(row pgx.Row) (*model.Apply, error) {
	var a model.Apply
	var doc []byte
	var id, key, tenant, status string
	var version int64
	var created, updated time.Time
	if err := row.Scan(&id, &key, &tenant, &status, &doc, &version, &created, &updated); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal(doc, &a); err != nil {
		return nil, fmt.Errorf("apply %s: %w", id, err)
	}
	a.ID, a.Key, a.Tenant, a.Status, a.Version, a.CreatedAt, a.UpdatedAt = id, key, tenant, status, version, created, updated
	return &a, nil
}

func (p *Postgres) CreateApply(ctx context.Context, a *model.Apply) error {
	a.Version, a.CreatedAt, a.UpdatedAt = 1, time.Now(), time.Now()
	doc, _ := json.Marshal(a)
	tag, err := p.pool.Exec(ctx, `INSERT INTO applies (id, key, tenant, status, doc, version, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,1,$6,$6) ON CONFLICT (tenant, key) DO NOTHING`, a.ID, a.Key, a.Tenant, a.Status, doc, a.CreatedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: apply with key %q exists", ErrConflict, a.Key)
	}
	return nil
}

func (p *Postgres) GetApply(ctx context.Context, id string) (*model.Apply, error) {
	return scanApply(p.pool.QueryRow(ctx, `SELECT `+applyCols+` FROM applies WHERE id=$1`, id))
}

func (p *Postgres) GetApplyByKey(ctx context.Context, tenant, key string) (*model.Apply, error) {
	return scanApply(p.pool.QueryRow(ctx, `SELECT `+applyCols+` FROM applies WHERE tenant=$1 AND key=$2`, tenant, key))
}

// updateApplyTx writes a guarded by its version, inside tx.
func updateApplyTx(ctx context.Context, tx pgx.Tx, a *model.Apply) error {
	doc, _ := json.Marshal(a)
	tag, err := tx.Exec(ctx, `UPDATE applies SET status=$2, doc=$3, version=version+1, updated_at=now() WHERE id=$1 AND version=$4`,
		a.ID, a.Status, doc, a.Version)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM applies WHERE id=$1`, a.ID).Scan(&one); err != nil {
			return ErrNotFound
		}
		return fmt.Errorf("%w: apply %s changed concurrently", ErrConflict, a.ID)
	}
	a.Version++
	a.UpdatedAt = time.Now()
	return nil
}

func (p *Postgres) UpdateApply(ctx context.Context, a *model.Apply) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := updateApplyTx(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) ApplyStep(ctx context.Context, a *model.Apply, step int, it *model.CatalogItem, expected int) error {
	if step < 0 || step >= len(a.Steps) {
		return fmt.Errorf("%w: step %d out of range", ErrConflict, step)
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	st := &a.Steps[step]
	if it == nil {
		// A noop step confirms the revision it planned on, atomically with its progress.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "catalog:"+st.Kind+"|"+st.Tenant+"|"+st.Name); err != nil {
			return err
		}
		var current int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision) FILTER (WHERE deleted_at IS NULL), 0) FROM catalog_items WHERE kind=$1 AND tenant=$2 AND name=$3`,
			st.Kind, st.Tenant, st.Name).Scan(&current); err != nil {
			return err
		}
		if current != expected {
			return fmt.Errorf("%w: %s %s/%s is at revision %d, expected %d", ErrConflict, st.Kind, st.Tenant, st.Name, current, expected)
		}
		st.Revision = expected
	} else {
		if err := putItemTx(ctx, tx, it, expected); err != nil {
			return err
		}
		if st.NextRevision != 0 && it.Revision != st.NextRevision {
			return fmt.Errorf("%w: %s %s/%s would become revision %d, the plan promised %d", ErrConflict, it.Kind, it.Tenant, it.Name, it.Revision, st.NextRevision)
		}
		st.Revision = it.Revision
	}
	if err := updateApplyTx(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (p *Postgres) ListApplies(ctx context.Context, tenant string, limit int) ([]*model.Apply, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+applyCols+` FROM applies WHERE ($1 = '' OR tenant=$1) ORDER BY created_at DESC`+limitClause(limit, 100), tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Apply
	for rows.Next() {
		a, err := scanApply(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) GetItem(ctx context.Context, kind, tenant, name string, revision int) (*model.CatalogItem, error) {
	if revision == 0 {
		// The latest row decides: once an item is deleted, its last row is deleted too.
		it, err := scanItem(p.pool.QueryRow(ctx, `SELECT `+itemCols+` FROM catalog_items WHERE kind=$1 AND tenant=$2 AND name=$3 ORDER BY revision DESC LIMIT 1`, kind, tenant, name))
		if err == nil && it.DeletedAt != nil {
			return nil, ErrNotFound
		}
		return it, err
	}
	return scanItem(p.pool.QueryRow(ctx, `SELECT `+itemCols+` FROM catalog_items WHERE kind=$1 AND tenant=$2 AND name=$3 AND revision=$4 AND deleted_at IS NULL`, kind, tenant, name, revision))
}

func (p *Postgres) queryItems(ctx context.Context, q string, args ...any) ([]*model.CatalogItem, error) {
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.CatalogItem
	for rows.Next() {
		it, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (p *Postgres) ListItems(ctx context.Context, kind, tenant string) ([]*model.CatalogItem, error) {
	// Latest row per name, then only the live ones: a deleted item's latest row is deleted.
	return p.queryItems(ctx, `SELECT `+itemCols+` FROM (SELECT DISTINCT ON (name) `+itemCols+` FROM catalog_items WHERE kind=$1 AND tenant=$2 ORDER BY name, revision DESC) latest
		WHERE deleted_at IS NULL ORDER BY name`, kind, tenant)
}

func (p *Postgres) ListKind(ctx context.Context, kind string) ([]*model.CatalogItem, error) {
	return p.queryItems(ctx, `SELECT `+itemCols+` FROM (SELECT DISTINCT ON (tenant, name) `+itemCols+` FROM catalog_items WHERE kind=$1 ORDER BY tenant, name, revision DESC) latest
		WHERE deleted_at IS NULL ORDER BY tenant, name`, kind)
}

func (p *Postgres) ListDeleted(ctx context.Context, kind, tenant string) ([]*model.CatalogItem, error) {
	return p.queryItems(ctx, `SELECT `+itemCols+` FROM (SELECT DISTINCT ON (name) `+itemCols+` FROM catalog_items WHERE kind=$1 AND tenant=$2 ORDER BY name, revision DESC) latest
		WHERE deleted_at IS NOT NULL ORDER BY name`, kind, tenant)
}

func (p *Postgres) ListRevisions(ctx context.Context, kind, tenant, name string) ([]*model.CatalogItem, error) {
	out, err := p.queryItems(ctx, `SELECT `+itemCols+` FROM catalog_items WHERE kind=$1 AND tenant=$2 AND name=$3 ORDER BY revision`, kind, tenant, name)
	if err == nil && len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, err
}

func (p *Postgres) DeleteItem(ctx context.Context, kind, tenant, name string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE catalog_items SET deleted_at = now() WHERE kind=$1 AND tenant=$2 AND name=$3 AND deleted_at IS NULL`, kind, tenant, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- api keys ---------------------------------------------------------------------------

const keyCols = `id, tenant, name, hash, created_by, created_at, expires_at, revoked_at, rotated_to, last_used_at, trust`

func scanKey(row pgx.Row) (*model.APIKey, error) {
	var k model.APIKey
	err := row.Scan(&k.ID, &k.Tenant, &k.Name, &k.Hash, &k.CreatedBy, &k.CreatedAt, &k.ExpiresAt, &k.RevokedAt, &k.RotatedTo, &k.LastUsedAt, &k.Trust)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (p *Postgres) CreateAPIKey(ctx context.Context, k *model.APIKey) error {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	tag, err := p.pool.Exec(ctx, `INSERT INTO api_keys (`+keyCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (id) DO NOTHING`,
		k.ID, k.Tenant, k.Name, k.Hash, k.CreatedBy, k.CreatedAt, k.ExpiresAt, k.RevokedAt, k.RotatedTo, k.LastUsedAt, k.Trust)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: api key %s exists", ErrConflict, k.ID)
	}
	return nil
}

func (p *Postgres) GetAPIKey(ctx context.Context, id string) (*model.APIKey, error) {
	return scanKey(p.pool.QueryRow(ctx, `SELECT `+keyCols+` FROM api_keys WHERE id=$1`, id))
}

func (p *Postgres) TouchAPIKey(ctx context.Context, id string, at time.Time) error {
	return p.keyExec(ctx, `UPDATE api_keys SET last_used_at=$2 WHERE id=$1`, id, at)
}

func (p *Postgres) RevokeAPIKey(ctx context.Context, id string, at time.Time) error {
	// COALESCE: an earlier revocation stands whatever this call carries.
	return p.keyExec(ctx, `UPDATE api_keys SET revoked_at=COALESCE(revoked_at, $2) WHERE id=$1`, id, at)
}

func (p *Postgres) RetireAPIKey(ctx context.Context, id, rotatedTo string, at time.Time, grace time.Duration) error {
	if grace <= 0 {
		return p.keyExec(ctx, `UPDATE api_keys SET rotated_to=$2, revoked_at=COALESCE(revoked_at, $3) WHERE id=$1`, id, rotatedTo, at)
	}
	return p.keyExec(ctx, `UPDATE api_keys SET rotated_to=$2, expires_at=LEAST(COALESCE(expires_at, $3::timestamptz), $3::timestamptz) WHERE id=$1`, id, rotatedTo, at.Add(grace))
}

// keyExec runs one UPDATE of api_keys and reports a missing row as ErrNotFound.
func (p *Postgres) keyExec(ctx context.Context, q string, args ...any) error {
	tag, err := p.pool.Exec(ctx, q, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DeleteAPIKey(ctx context.Context, id string) error {
	return p.keyExec(ctx, `DELETE FROM api_keys WHERE id=$1`, id)
}

func (p *Postgres) PruneTrustedAPIKeys(ctx context.Context, before time.Time) (int, error) {
	tag, err := p.pool.Exec(ctx, `DELETE FROM api_keys WHERE trust <> '' AND expires_at IS NOT NULL AND expires_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// IssueForToken: one row per token id and the key, in one transaction; the insert that finds
// the token's row is the second use, and the transaction is rolled back.
func (p *Postgres) IssueForToken(ctx context.Context, id string, expiresAt time.Time, k *model.APIKey) error {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
	if _, err := tx.Exec(ctx, `DELETE FROM token_uses WHERE expires_at < now()`); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO token_uses (id, expires_at, key_id) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`, id, expiresAt, k.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: token %s was used already", ErrConflict, id)
	}
	tag, err = tx.Exec(ctx, `INSERT INTO api_keys (`+keyCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (id) DO NOTHING`,
		k.ID, k.Tenant, k.Name, k.Hash, k.CreatedBy, k.CreatedAt, k.ExpiresAt, k.RevokedAt, k.RotatedTo, k.LastUsedAt, k.Trust)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("api key %s exists", k.ID)
	}
	return tx.Commit(ctx)
}

func (p *Postgres) TokenUse(ctx context.Context, id string) (string, error) {
	var key string
	err := p.pool.QueryRow(ctx, `SELECT key_id FROM token_uses WHERE id=$1`, id).Scan(&key)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return key, err
}

func (p *Postgres) ListAPIKeys(ctx context.Context, tenant string) ([]*model.APIKey, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+keyCols+` FROM api_keys WHERE ($1 = '' OR tenant=$1) ORDER BY created_at DESC, id`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.APIKey
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// --- credentials ------------------------------------------------------------------------

const credCols = `tenant, name, version, fingerprint, created_by, created_at, updated_at`

func scanCredential(row pgx.Row) (*model.Credential, error) {
	var c model.Credential
	err := row.Scan(&c.Tenant, &c.Name, &c.Version, &c.Fingerprint, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (p *Postgres) PutCredential(ctx context.Context, c *model.Credential, ciphertext []byte) (bool, error) {
	// One statement: an insert, or on conflict a replacement that bumps the version and keeps
	// who created it and when. xmax = 0 tells an insert from an update.
	var created bool
	err := p.pool.QueryRow(ctx, `INSERT INTO credentials (tenant, name, version, fingerprint, ciphertext, created_by, created_at, updated_at)
		VALUES ($1,$2,1,$3,$4,$5,now(),now())
		ON CONFLICT (tenant, name) DO UPDATE SET version=credentials.version+1, fingerprint=EXCLUDED.fingerprint, ciphertext=EXCLUDED.ciphertext, updated_at=now()
		RETURNING version, created_by, created_at, updated_at, (xmax = 0)`,
		c.Tenant, c.Name, c.Fingerprint, ciphertext, c.CreatedBy).Scan(&c.Version, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &created)
	return created, err
}

func (p *Postgres) GetCredential(ctx context.Context, tenant, name string) (*model.Credential, []byte, error) {
	var c model.Credential
	var ciphertext []byte
	err := p.pool.QueryRow(ctx, `SELECT `+credCols+`, ciphertext FROM credentials WHERE tenant=$1 AND name=$2`, tenant, name).
		Scan(&c.Tenant, &c.Name, &c.Version, &c.Fingerprint, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	return &c, ciphertext, nil
}

func (p *Postgres) ListCredentials(ctx context.Context, tenant string) ([]*model.Credential, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+credCols+` FROM credentials WHERE tenant=$1 ORDER BY name`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) DeleteCredential(ctx context.Context, tenant, name string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM credentials WHERE tenant=$1 AND name=$2`, tenant, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Git repositories: last known state -------------------------------------------------------

// recordGitHalf writes one half of the record: the document is created with that half, or
// its half is replaced in place (jsonb ||), the other half untouched, in one statement.
func (p *Postgres) recordGitHalf(ctx context.Context, tenant, name, half string, v any) error {
	doc, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO git_syncs (tenant, name, doc, updated_at) VALUES ($1,$2,jsonb_build_object($3::text, $4::jsonb),now())
		ON CONFLICT (tenant, name) DO UPDATE SET doc = git_syncs.doc || jsonb_build_object($3::text, $4::jsonb), updated_at = now()`, tenant, name, half, doc)
	return err
}

func (p *Postgres) RecordGitCheck(ctx context.Context, tenant, name string, c model.GitCheck) error {
	return p.recordGitHalf(ctx, tenant, name, "check", c)
}

func (p *Postgres) RecordGitSync(ctx context.Context, tenant, name string, r model.GitSyncResult) error {
	return p.recordGitHalf(ctx, tenant, name, "sync", r)
}

func (p *Postgres) RecordGitHook(ctx context.Context, tenant, name string, h model.GitHook) error {
	return p.recordGitHalf(ctx, tenant, name, "hook", h)
}

// RecordGitHookIf: the condition is in the statement, so an acceptance written between a
// read and this write is never overwritten.
func (p *Postgres) RecordGitHookIf(ctx context.Context, tenant, name string, h model.GitHook, job string, run int) (bool, error) {
	doc, err := json.Marshal(h)
	if err != nil {
		return false, err
	}
	tag, err := p.pool.Exec(ctx, `INSERT INTO git_syncs (tenant, name, doc, updated_at) VALUES ($1,$2,jsonb_build_object('hook', $3::jsonb),now())
		ON CONFLICT (tenant, name) DO UPDATE SET doc = git_syncs.doc || jsonb_build_object('hook', $3::jsonb), updated_at = now()
		WHERE git_syncs.doc->'hook' IS NULL
		   OR (git_syncs.doc->'hook'->>'job' = $4 AND COALESCE((git_syncs.doc->'hook'->>'run')::int, 0) <= $5)`, tenant, name, doc, job, run)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (p *Postgres) GetGitSync(ctx context.Context, tenant, name string) (*model.GitSync, error) {
	var doc []byte
	g := &model.GitSync{Tenant: tenant, Name: name}
	err := p.pool.QueryRow(ctx, `SELECT doc, updated_at FROM git_syncs WHERE tenant=$1 AND name=$2`, tenant, name).Scan(&doc, &g.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := decodeGitSync(doc, g); err != nil {
		return nil, err
	}
	g.Tenant, g.Name = tenant, name
	return g, nil
}

// decodeGitSync reads a record in the two-half form, and also one written before the halves
// existed (fields at the root, as an older replica still writes during a rolling upgrade):
// a half absent in the new form is taken from the root fields, a half present wins.
func decodeGitSync(doc []byte, g *model.GitSync) error {
	if err := json.Unmarshal(doc, g); err != nil {
		return err
	}
	var flat struct {
		Head       string                `json:"head"`
		CheckedAt  *time.Time            `json:"checked_at"`
		CheckError string                `json:"check_error"`
		Commit     string                `json:"commit"`
		Bundles    []model.GitSyncBundle `json:"bundles"`
		Status     string                `json:"status"`
		Error      string                `json:"error"`
		SyncedAt   *time.Time            `json:"synced_at"`
	}
	if err := json.Unmarshal(doc, &flat); err != nil {
		return nil // not the flat form either way; the new form was read above
	}
	if g.Check == nil && flat.CheckedAt != nil {
		g.Check = &model.GitCheck{Head: flat.Head, At: *flat.CheckedAt, Error: flat.CheckError}
	}
	if g.Sync == nil && flat.SyncedAt != nil {
		g.Sync = &model.GitSyncResult{Commit: flat.Commit, Bundles: flat.Bundles, Status: flat.Status, Error: flat.Error, At: *flat.SyncedAt}
	}
	return nil
}

// --- Git webhook jobs ---------------------------------------------------------------------------

const gitJobCols = `id, tenant, name, action, delivery, payload, status, attempts, run, owner, lease_until, outcome, error, created_at, updated_at`

func scanGitJob(row pgx.Row) (*model.GitJob, error) {
	var j model.GitJob
	err := row.Scan(&j.ID, &j.Tenant, &j.Name, &j.Action, &j.Delivery, &j.Payload, &j.Status, &j.Attempts, &j.Run, &j.Owner, &j.LeaseUntil, &j.Outcome, &j.Error, &j.CreatedAt, &j.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}

func (p *Postgres) EnqueueGitJob(ctx context.Context, j *model.GitJob) error {
	now := time.Now()
	j.Status, j.CreatedAt, j.UpdatedAt = model.GitJobPending, now, now
	tag, err := p.pool.Exec(ctx, `INSERT INTO git_jobs (id, tenant, name, action, delivery, payload, status, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8) ON CONFLICT (tenant, name, delivery) DO NOTHING`,
		j.ID, j.Tenant, j.Name, j.Action, j.Delivery, j.Payload, j.Status, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: delivery %s already has a job", ErrConflict, j.Delivery)
	}
	return nil
}

// ClaimGitJob: one statement picks the oldest waiting job and leases it; SKIP LOCKED keeps two
// replicas from picking the same row. A pending job waits until its lease_until (a retry's
// not-before) has passed; a running one until its lease lapsed.
func (p *Postgres) ClaimGitJob(ctx context.Context, owner string, now time.Time, lease time.Duration) (*model.GitJob, error) {
	return scanGitJob(p.pool.QueryRow(ctx, `WITH pick AS (
			SELECT id FROM git_jobs
			WHERE (status = 'pending' AND (lease_until IS NULL OR lease_until <= $2))
			   OR (status = 'running' AND lease_until IS NOT NULL AND lease_until <= $2)
			ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
		UPDATE git_jobs SET status = 'running', owner = $1, lease_until = $3, attempts = attempts + 1, run = run + 1, updated_at = $2
		FROM pick WHERE git_jobs.id = pick.id RETURNING `+qualified("git_jobs", gitJobCols), owner, now, now.Add(lease)))
}

// heldConflict is the error for a write by a holder the job no longer belongs to.
func (p *Postgres) heldConflict(ctx context.Context, id, owner string, run int) error {
	j, err := p.GetGitJob(ctx, id)
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: job %s is %s, run %d, owned by %q (not running under %q, run %d)", ErrConflict, id, j.Status, j.Run, j.Owner, owner, run)
}

func (p *Postgres) FinishGitJob(ctx context.Context, id, owner string, run int, status, outcome, errMsg string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE git_jobs SET status=$4, outcome=$5, error=$6, lease_until=NULL, updated_at=now()
		WHERE id=$1 AND owner=$2 AND run=$3 AND status='running'`, id, owner, run, status, outcome, errMsg)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return p.heldConflict(ctx, id, owner, run)
	}
	return nil
}

func (p *Postgres) RetryGitJob(ctx context.Context, id, owner string, run int, notBefore time.Time, errMsg string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE git_jobs SET status='pending', outcome='', error=$5, lease_until=$4, updated_at=now()
		WHERE id=$1 AND owner=$2 AND run=$3 AND status='running'`, id, owner, run, notBefore, errMsg)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return p.heldConflict(ctx, id, owner, run)
	}
	return nil
}

func (p *Postgres) RequeueGitJob(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE git_jobs SET status='pending', attempts=0, outcome='', error='', lease_until=NULL, updated_at=now()
		WHERE id=$1 AND status IN ('failed', 'pending')`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		j, err := p.GetGitJob(ctx, id)
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: job %s is %s, neither failed nor waiting", ErrConflict, id, j.Status)
	}
	return nil
}

func (p *Postgres) GetGitJob(ctx context.Context, id string) (*model.GitJob, error) {
	return scanGitJob(p.pool.QueryRow(ctx, `SELECT `+gitJobCols+` FROM git_jobs WHERE id=$1`, id))
}

func (p *Postgres) GetGitJobByDelivery(ctx context.Context, tenant, name, delivery string) (*model.GitJob, error) {
	return scanGitJob(p.pool.QueryRow(ctx, `SELECT `+gitJobCols+` FROM git_jobs WHERE tenant=$1 AND name=$2 AND delivery=$3`, tenant, name, delivery))
}

// qualified prefixes every column of a comma-separated list with the table name.
func qualified(table, cols string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = table + "." + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}
