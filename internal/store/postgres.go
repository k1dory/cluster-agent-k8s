package store

import (
	"context"
	_ "embed"
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
	agent_version, desired_version, env_version, revision`

func scanSandbox(row pgx.Row) (*model.Sandbox, error) {
	var s model.Sandbox
	var pPort *int
	var pAccess, pHost *string
	err := row.Scan(&s.ID, &s.Name, &s.Slug, &s.Owner, &s.Tenant, &s.Repo, &s.IdleTimeout, &s.WakeOnPreview,
		&s.Status, &s.IP, &s.Instance, &s.PodName, &s.LastActivity, &s.CreatedAt, &s.ExpiresAt, &pPort, &pAccess, &pHost, &s.Error,
		&s.AgentVersion, &s.DesiredVersion, &s.EnvVersion, &s.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
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

func (p *Postgres) CreateSandbox(ctx context.Context, s *model.Sandbox) error {
	port, access, host := previewCols(s)
	s.Revision = 1
	_, err := p.pool.Exec(ctx, `INSERT INTO sandboxes (`+sandboxCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
		s.ID, s.Name, s.Slug, s.Owner, s.Tenant, s.Repo, s.IdleTimeout, s.WakeOnPreview, s.Status, s.IP, s.Instance,
		s.PodName, s.LastActivity, s.CreatedAt, s.ExpiresAt, port, access, host, s.Error,
		s.AgentVersion, s.DesiredVersion, s.EnvVersion, s.Revision)
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

func (p *Postgres) CountSandboxes(ctx context.Context, tenant string) (SandboxCounts, error) {
	var c SandboxCounts
	err := p.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status IN ($2,$3,$4)) FROM sandboxes WHERE tenant=$1`,
		tenant, model.StatusCreating, model.StatusWaking, model.StatusRunning).Scan(&c.Total, &c.Awake)
	return c, err
}

func (p *Postgres) UpdateSandbox(ctx context.Context, s *model.Sandbox) error {
	port, access, host := previewCols(s)
	tag, err := p.pool.Exec(ctx, `UPDATE sandboxes SET name=$2, slug=$3, owner=$4, tenant=$5, repo=$6, idle_timeout=$7,
		wake_on_preview=$8, status=$9, ip=$10, instance=$11, pod_name=$12, last_activity=GREATEST(last_activity, $13), expires_at=$14,
		preview_port=$15, preview_access=$16, preview_host=$17, error=$18,
		agent_version=$19, desired_version=$20, env_version=$21, revision=revision+1
		WHERE id=$1 AND revision=$22`,
		s.ID, s.Name, s.Slug, s.Owner, s.Tenant, s.Repo, s.IdleTimeout, s.WakeOnPreview, s.Status, s.IP, s.Instance,
		s.PodName, s.LastActivity, s.ExpiresAt, port, access, host, s.Error,
		s.AgentVersion, s.DesiredVersion, s.EnvVersion, s.Revision)
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
	agent_version, resume_of, session`

func scanRun(row pgx.Row) (*model.Run, error) {
	var r model.Run
	u := &r.Usage
	err := row.Scan(&r.ID, &r.SandboxID, &r.Tenant, &r.Slug, &r.Task, &r.Status, &r.ExitCode, &r.CreatedAt, &r.StartedAt, &r.FinishedAt,
		&u.Model, &u.InputTokens, &u.OutputTokens, &u.CacheRead, &u.CacheWrite, &u.CostUSD, &u.Turns,
		&r.AgentVersion, &r.ResumeOf, &r.Session)
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
	_, err := p.pool.Exec(ctx, `INSERT INTO runs (`+runCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		r.ID, r.SandboxID, r.Tenant, r.Slug, r.Task, r.Status, r.ExitCode, r.CreatedAt, r.StartedAt, r.FinishedAt,
		u.Model, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD, u.Turns,
		r.AgentVersion, r.ResumeOf, r.Session)
	return err
}

func (p *Postgres) GetRun(ctx context.Context, id string) (*model.Run, error) {
	return scanRun(p.pool.QueryRow(ctx, `SELECT `+runCols+` FROM runs WHERE id=$1`, id))
}

func (p *Postgres) UpdateRun(ctx context.Context, r *model.Run) error {
	u := r.Usage
	tag, err := p.pool.Exec(ctx, `UPDATE runs SET status=$2, exit_code=$3, started_at=$4, finished_at=$5,
		model=$6, input_tokens=$7, output_tokens=$8, cache_read_tokens=$9, cache_write_tokens=$10, cost_usd=$11, turns=$12,
		agent_version=$13, session=$14 WHERE id=$1`,
		r.ID, r.Status, r.ExitCode, r.StartedAt, r.FinishedAt, u.Model, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD, u.Turns,
		r.AgentVersion, r.Session)
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
