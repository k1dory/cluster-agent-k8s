package store

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"
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
}

// OpenPostgres connects and applies the schema (idempotent).
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, migrations); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() error { p.pool.Close(); return nil }

const sandboxCols = `id, name, slug, owner, tenant, repo, idle_timeout, wake_on_preview, status, ip, instance,
	pod_name, last_activity, created_at, preview_port, preview_access, preview_host, error`

func scanSandbox(row pgx.Row) (*model.Sandbox, error) {
	var s model.Sandbox
	var pPort *int
	var pAccess, pHost *string
	err := row.Scan(&s.ID, &s.Name, &s.Slug, &s.Owner, &s.Tenant, &s.Repo, &s.IdleTimeout, &s.WakeOnPreview,
		&s.Status, &s.IP, &s.Instance, &s.PodName, &s.LastActivity, &s.CreatedAt, &pPort, &pAccess, &pHost, &s.Error)
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
	_, err := p.pool.Exec(ctx, `INSERT INTO sandboxes (`+sandboxCols+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		s.ID, s.Name, s.Slug, s.Owner, s.Tenant, s.Repo, s.IdleTimeout, s.WakeOnPreview, s.Status, s.IP, s.Instance,
		s.PodName, s.LastActivity, s.CreatedAt, port, access, host, s.Error)
	return err
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

func (p *Postgres) UpdateSandbox(ctx context.Context, s *model.Sandbox) error {
	port, access, host := previewCols(s)
	tag, err := p.pool.Exec(ctx, `UPDATE sandboxes SET name=$2, slug=$3, owner=$4, tenant=$5, repo=$6, idle_timeout=$7,
		wake_on_preview=$8, status=$9, ip=$10, instance=$11, pod_name=$12, last_activity=$13,
		preview_port=$14, preview_access=$15, preview_host=$16, error=$17 WHERE id=$1`,
		s.ID, s.Name, s.Slug, s.Owner, s.Tenant, s.Repo, s.IdleTimeout, s.WakeOnPreview, s.Status, s.IP, s.Instance,
		s.PodName, s.LastActivity, port, access, host, s.Error)
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
	model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, turns`

func scanRun(row pgx.Row) (*model.Run, error) {
	var r model.Run
	u := &r.Usage
	err := row.Scan(&r.ID, &r.SandboxID, &r.Tenant, &r.Slug, &r.Task, &r.Status, &r.ExitCode, &r.CreatedAt, &r.StartedAt, &r.FinishedAt,
		&u.Model, &u.InputTokens, &u.OutputTokens, &u.CacheRead, &u.CacheWrite, &u.CostUSD, &u.Turns)
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
	_, err := p.pool.Exec(ctx, `INSERT INTO runs (`+runCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		r.ID, r.SandboxID, r.Tenant, r.Slug, r.Task, r.Status, r.ExitCode, r.CreatedAt, r.StartedAt, r.FinishedAt,
		u.Model, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD, u.Turns)
	return err
}

func (p *Postgres) GetRun(ctx context.Context, id string) (*model.Run, error) {
	return scanRun(p.pool.QueryRow(ctx, `SELECT `+runCols+` FROM runs WHERE id=$1`, id))
}

func (p *Postgres) UpdateRun(ctx context.Context, r *model.Run) error {
	u := r.Usage
	tag, err := p.pool.Exec(ctx, `UPDATE runs SET status=$2, exit_code=$3, started_at=$4, finished_at=$5,
		model=$6, input_tokens=$7, output_tokens=$8, cache_read_tokens=$9, cache_write_tokens=$10, cost_usd=$11, turns=$12 WHERE id=$1`,
		r.ID, r.Status, r.ExitCode, r.StartedAt, r.FinishedAt, u.Model, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD, u.Turns)
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

func (p *Postgres) NextQueuedRun(ctx context.Context, sandboxID string) (*model.Run, error) {
	return scanRun(p.pool.QueryRow(ctx, `SELECT `+runCols+` FROM runs WHERE sandbox_id=$1 AND status=$2
		ORDER BY created_at LIMIT 1`, sandboxID, model.RunQueued))
}

func (p *Postgres) RunningRun(ctx context.Context, sandboxID string) (*model.Run, error) {
	return scanRun(p.pool.QueryRow(ctx, `SELECT `+runCols+` FROM runs WHERE sandbox_id=$1 AND status=$2
		ORDER BY created_at LIMIT 1`, sandboxID, model.RunRunning))
}

func (p *Postgres) AppendEvent(ctx context.Context, e *model.Event) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	return p.pool.QueryRow(ctx, `INSERT INTO events (sandbox_id, tenant, slug, run_id, type, data, at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
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
	return p.queryRuns(ctx, `SELECT `+runCols+` FROM runs`+w+` ORDER BY created_at`+limitClause(f.Limit, 100000), args...)
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
