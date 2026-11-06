package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
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
	if err := migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool, lockers: make(chan struct{}, max(1, int(cfg.MaxConns)/2))}, nil
}

// migration is one step of migrations.sql.
type migration struct {
	version int
	name    string
	sql     string
}

var (
	stepRe   = regexp.MustCompile(`(?m)^-- step (\d+): (.+)$`)
	alwaysRe = regexp.MustCompile(`(?m)^-- every start: .+$`)
)

// parseMigrations splits the schema file at its "-- step N: name" lines, and returns the
// "-- every start:" section that follows the last step separately. Steps must be numbered
// 1, 2, 3... in order: a gap or a duplicate is a mistake in the file, not something to skip.
func parseMigrations(src string) (steps []migration, always string, err error) {
	if loc := alwaysRe.FindStringIndex(src); loc != nil {
		src, always = src[:loc[0]], src[loc[1]:]
		if stepRe.MatchString(always) {
			return nil, "", fmt.Errorf("migrations: a step after the every-start section")
		}
	}
	locs := stepRe.FindAllStringSubmatchIndex(src, -1)
	if len(locs) == 0 {
		return nil, "", fmt.Errorf("migrations: no step markers")
	}
	for i, l := range locs {
		v, _ := strconv.Atoi(src[l[2]:l[3]])
		if v != i+1 {
			return nil, "", fmt.Errorf("migrations: step %d where step %d was expected", v, i+1)
		}
		end := len(src)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		steps = append(steps, migration{version: v, name: strings.TrimSpace(src[l[4]:l[5]]), sql: src[l[1]:end]})
	}
	return steps, always, nil
}

// migrate applies the steps a database has not recorded yet, under an advisory lock: replicas
// start together (a rollout recreates them at once), and CREATE ... IF NOT EXISTS is not safe
// against itself on a fresh database (two creators of one type collide on pg_type's unique
// index). One replica migrates, the others wait and find the steps recorded. A database at the
// latest step runs no DDL at all (only the every-start row repairs); one written by a newer release (a step this binary does not
// know) is left alone, so an older replica still starts during a rolling update.
func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	steps, always, err := parseMigrations(migrations)
	if err != nil {
		return err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('agent-sandbox:migrations'))`); err != nil {
		return err
	}
	merr := applySteps(ctx, conn.Conn(), steps)
	if merr == nil && strings.TrimSpace(always) != "" {
		if _, err := conn.Exec(ctx, always); err != nil {
			merr = fmt.Errorf("migrations, every-start repairs: %w", err)
		}
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock(hashtext('agent-sandbox:migrations'))`); err != nil && merr == nil {
		return err
	}
	return merr
}

func applySteps(ctx context.Context, conn *pgx.Conn, steps []migration) error {
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    integer PRIMARY KEY,
		name       text NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	applied := map[int]bool{}
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, st := range steps {
		if applied[st.version] {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, st.sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, st.version, st.name)
			return err
		})
		if err != nil {
			return fmt.Errorf("migration %d (%s): %w", st.version, st.name, err)
		}
	}
	return nil
}

// dedicated opens a connection outside the pool for long-held session state (locks, LISTEN).
func (p *Postgres) dedicated(ctx context.Context) (*pgx.Conn, error) {
	return pgx.ConnectConfig(ctx, p.pool.Config().ConnConfig.Copy())
}

func (p *Postgres) Close() error { p.pool.Close(); return nil }

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

const sandboxCols = `id, name, slug, owner, tenant, repo, idle_timeout, wake_on_preview, status, ip, instance,
	pod_name, last_activity, created_at, expires_at, preview_port, preview_access, preview_host, error,
	agent_version, desired_version, env_version, revision, admin_grant,
	agent_ref, agent_revision, environment_ref, environment_revision, launch, connections, preview_gen`

func scanSandbox(row pgx.Row) (*model.Sandbox, error) {
	var s model.Sandbox
	var pPort *int
	var pAccess, pHost *string
	var launch, conns []byte
	err := row.Scan(&s.ID, &s.Name, &s.Slug, &s.Owner, &s.Tenant, &s.Repo, &s.IdleTimeout, &s.WakeOnPreview,
		&s.Status, &s.IP, &s.Instance, &s.PodName, &s.LastActivity, &s.CreatedAt, &s.ExpiresAt, &pPort, &pAccess, &pHost, &s.Error,
		&s.AgentVersion, &s.DesiredVersion, &s.EnvVersion, &s.Revision, &s.AdminGrant,
		&s.AgentRef, &s.AgentRevision, &s.EnvironmentRef, &s.EnvironmentRevision, &launch, &conns, &s.PreviewGen)
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
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31)`,
		s.ID, s.Name, s.Slug, s.Owner, s.Tenant, s.Repo, s.IdleTimeout, s.WakeOnPreview, s.Status, s.IP, s.Instance,
		s.PodName, s.LastActivity, s.CreatedAt, s.ExpiresAt, port, access, host, s.Error,
		s.AgentVersion, s.DesiredVersion, s.EnvVersion, s.Revision, s.AdminGrant,
		s.AgentRef, s.AgentRevision, s.EnvironmentRef, s.EnvironmentRevision, launchCol(s), connectionsCol(s), s.PreviewGen)
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
// when notifications coalesce or the connection is replaced. ready is called once the starting
// cursor is known (see EventListener).
func (p *Postgres) ListenEvents(ctx context.Context, ready func(), fn func(e *model.Event)) {
	listenLoop(ctx, func(ctx context.Context) (int64, error) {
		var id int64
		err := p.pool.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM events`).Scan(&id)
		return id, err
	}, ready, func(ctx context.Context, last *int64) error { return p.listenOnce(ctx, last, fn) }, 2*time.Second)
}

// listenLoop is ListenEvents without the database: the cursor read, the readiness signal and
// one listening session, retried every wait until ctx ends.
func listenLoop(ctx context.Context, read func(context.Context) (int64, error), ready func(), once func(context.Context, *int64) error, wait time.Duration) {
	last, ok := listenStart(ctx, read, wait)
	if !ok {
		return
	}
	if ready != nil {
		ready()
	}
	for ctx.Err() == nil {
		if err := once(ctx, &last); err != nil && ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
		}
	}
}

// listenStart reads where the feed begins (the newest event now: older ones were published by
// whoever appended them), retrying until it succeeds. Starting from 0 after a failed read would
// replay the whole events table into the hub. ok=false when ctx ended first.
func listenStart(ctx context.Context, read func(context.Context) (int64, error), wait time.Duration) (int64, bool) {
	for {
		last, err := read(ctx)
		if err == nil {
			return last, true
		}
		select {
		case <-ctx.Done():
			return 0, false
		case <-time.After(wait):
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
		agent_ref=$24, agent_revision=$25, environment_ref=$26, environment_revision=$27, launch=$28, connections=$29, preview_gen=$30,
		revision=revision+1
		WHERE id=$1 AND revision=$22`,
		s.ID, s.Name, s.Slug, s.Owner, s.Tenant, s.Repo, s.IdleTimeout, s.WakeOnPreview, s.Status, s.IP, s.Instance,
		s.PodName, s.LastActivity, s.ExpiresAt, port, access, host, s.Error,
		s.AgentVersion, s.DesiredVersion, s.EnvVersion, s.Revision, s.AdminGrant,
		s.AgentRef, s.AgentRevision, s.EnvironmentRef, s.EnvironmentRevision, launchCol(s), connectionsCol(s), s.PreviewGen)
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
	agent_version, resume_of, session, agent_ref, agent_revision, environment_ref, environment_revision, mode,
	attempt, claimed_by, claim_acked`

func scanRun(row pgx.Row) (*model.Run, error) {
	var r model.Run
	u := &r.Usage
	err := row.Scan(&r.ID, &r.SandboxID, &r.Tenant, &r.Slug, &r.Task, &r.Status, &r.ExitCode, &r.CreatedAt, &r.StartedAt, &r.FinishedAt,
		&u.Model, &u.InputTokens, &u.OutputTokens, &u.CacheRead, &u.CacheWrite, &u.CostUSD, &u.Turns,
		&r.AgentVersion, &r.ResumeOf, &r.Session, &r.AgentRef, &r.AgentRevision, &r.EnvironmentRef, &r.EnvironmentRevision, &r.Mode,
		&r.Attempt, &r.ClaimedBy, &r.ClaimAcked)
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
	_, err := p.pool.Exec(ctx, `INSERT INTO runs (`+runCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)`,
		r.ID, r.SandboxID, r.Tenant, r.Slug, r.Task, r.Status, r.ExitCode, r.CreatedAt, r.StartedAt, r.FinishedAt,
		u.Model, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD, u.Turns,
		r.AgentVersion, r.ResumeOf, r.Session, r.AgentRef, r.AgentRevision, r.EnvironmentRef, r.EnvironmentRevision, r.Mode,
		r.Attempt, r.ClaimedBy, r.ClaimAcked)
	return err
}

func (p *Postgres) GetRun(ctx context.Context, id string) (*model.Run, error) {
	return scanRun(p.pool.QueryRow(ctx, `SELECT `+runCols+` FROM runs WHERE id=$1`, id))
}

// runExists turns "no row matched the condition" into ErrNotFound or ErrConflict.
func (p *Postgres) runExists(ctx context.Context, id string) error {
	if _, err := p.GetRun(ctx, id); err != nil {
		return err
	}
	return ErrConflict
}

func (p *Postgres) RecordRunUsage(ctx context.Context, id string, u model.Usage, total bool) error {
	// Add mirrors model.Usage.Add (an empty model keeps the recorded one); total replaces.
	tag, err := p.pool.Exec(ctx, `UPDATE runs SET
		model = CASE WHEN $2 THEN $3 WHEN $3 = '' THEN model ELSE $3 END,
		input_tokens = CASE WHEN $2 THEN 0 ELSE input_tokens END + $4,
		output_tokens = CASE WHEN $2 THEN 0 ELSE output_tokens END + $5,
		cache_read_tokens = CASE WHEN $2 THEN 0 ELSE cache_read_tokens END + $6,
		cache_write_tokens = CASE WHEN $2 THEN 0 ELSE cache_write_tokens END + $7,
		cost_usd = CASE WHEN $2 THEN 0 ELSE cost_usd END + $8,
		turns = CASE WHEN $2 THEN 0 ELSE turns END + $9
		WHERE id=$1 AND status <> ALL($10)`,
		id, total, u.Model, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD, u.Turns,
		[]string{string(model.RunDone), string(model.RunFailed)})
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return p.runExists(ctx, id)
	}
	return nil
}

func (p *Postgres) SetRunSession(ctx context.Context, id, session string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE runs SET session=$2 WHERE id=$1`, id, session)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) SettleRun(ctx context.Context, id string, from []model.RunStatus, to model.RunStatus, exitCode int, finishedAt time.Time, usage *model.Usage) (*model.Run, error) {
	return p.SettleRunWithEvents(ctx, Settle{RunID: id, From: from, To: to, ExitCode: exitCode, FinishedAt: finishedAt, Usage: usage})
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

func (p *Postgres) AppendQueuedTask(ctx context.Context, runID, text string) (*model.Run, error) {
	// The status condition is re-checked against a concurrent claim: once the runner has the
	// run, nothing is appended.
	r, err := scanRun(p.pool.QueryRow(ctx, `UPDATE runs SET task = task || $2 WHERE id=$1 AND status=$3
		RETURNING `+runCols, runID, text, model.RunQueued))
	if errors.Is(err, ErrNotFound) {
		if _, gerr := p.GetRun(ctx, runID); gerr != nil {
			return nil, gerr
		}
		return nil, ErrConflict
	}
	return r, err
}

func (p *Postgres) ReleaseRun(ctx context.Context, runID string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE runs SET status=$2, started_at=NULL WHERE id=$1 AND status=$3`,
		runID, model.RunQueued, model.RunRunning)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := p.GetRun(ctx, runID); err != nil {
			return err
		}
		return ErrConflict
	}
	return nil
}

func (p *Postgres) ClaimQueuedRun(ctx context.Context, sandboxID string, startedAt time.Time) (*model.Run, error) {
	// One statement: pick the oldest queued run, skipping rows another poller is claiming.
	return scanRun(p.pool.QueryRow(ctx, `UPDATE runs SET status=$3, started_at=$4, attempt=attempt+1 WHERE id = (
			SELECT id FROM runs WHERE sandbox_id=$1 AND status=$2 ORDER BY created_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING `+runCols, sandboxID, model.RunQueued, model.RunRunning, startedAt))
}

func (p *Postgres) QueuedRun(ctx context.Context, sandboxID string) (*model.Run, error) {
	return scanRun(p.pool.QueryRow(ctx, `SELECT `+runCols+` FROM runs WHERE sandbox_id=$1 AND status=$2
		ORDER BY created_at, id LIMIT 1`, sandboxID, model.RunQueued))
}

func (p *Postgres) ClaimRun(ctx context.Context, runID string, startedAt time.Time, session string, stamp RunStamp) (*model.Run, error) {
	r, err := scanRun(p.pool.QueryRow(ctx, `UPDATE runs SET status=$3, started_at=$4,
		session = CASE WHEN session = '' THEN $5 ELSE session END,
		agent_version=$6, agent_ref=$7, agent_revision=$8, environment_ref=$9, environment_revision=$10,
		attempt=attempt+1, claimed_by=$11, claim_acked=false
		WHERE id=$1 AND status=$2 RETURNING `+runCols, runID, model.RunQueued, model.RunRunning, startedAt, session,
		stamp.AgentVersion, stamp.AgentRef, stamp.AgentRevision, stamp.EnvironmentRef, stamp.EnvironmentRevision, stamp.Owner))
	if errors.Is(err, ErrNotFound) {
		if _, gerr := p.GetRun(ctx, runID); gerr != nil {
			return nil, gerr
		}
		return nil, ErrConflict
	}
	return r, err
}

func (p *Postgres) RunningRun(ctx context.Context, sandboxID string) (*model.Run, error) {
	return scanRun(p.pool.QueryRow(ctx, `SELECT `+runCols+` FROM runs WHERE sandbox_id=$1 AND status=$2
		ORDER BY created_at LIMIT 1`, sandboxID, model.RunRunning))
}

func (p *Postgres) AppendEvent(ctx context.Context, e *model.Event) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	// Readers page by id (ListenEvents, ?after=), so ids must become visible in order: with a
	// bare bigserial, writer A takes id 10, B takes 11 and commits first, a reader moves its
	// cursor to 11 and A's 10 is never read. The id is taken under a transaction-scoped lock
	// held to the commit, so the next writer's id is drawn only after this one is visible.
	// The lock is global, not per sandbox: the listener reads every sandbox's events with one
	// cursor. It is held for one INSERT: the batch is one implicit transaction, one round trip.
	// The NOTIFY wakes every replica's ListenEvents so their SSE clients see this event.
	b := &pgx.Batch{}
	b.Queue(eventsLockSQL)
	b.Queue(`WITH ins AS (
			INSERT INTO events (sandbox_id, tenant, slug, run_id, type, data, at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id)
		SELECT id FROM ins, pg_notify('`+eventsChannel+`', id::text)`,
		e.SandboxID, e.Tenant, e.Slug, e.RunID, e.Type, e.Data, e.At).QueryRow(func(row pgx.Row) error { return row.Scan(&e.ID) })
	return p.pool.SendBatch(ctx, b).Close()
}

// eventsLockSQL serialises event ids with their commits (see AppendEvent). Since migration
// step 10 the events table's trigger takes the same lock for every INSERT, including the bare
// ones of older replicas during a rolling update, and draws the id under it; taking it here
// first is harmless: the lock is re-entrant within a transaction.
const eventsLockSQL = `SELECT pg_advisory_xact_lock(hashtext('agent-sandbox:events'))`

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
	return p.queryRuns(ctx, `SELECT `+runCols+` FROM runs`+w+` ORDER BY created_at, id`+limitClause(min(f.Limit, MaxRunsPerQuery), MaxRunsPerQuery), args...)
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

// --- OAuth sign-ins -----------------------------------------------------------------------

const oauthCols = `tenant, name, provider, status, generation, verification_url, user_code, login_expires_at, account_id,
	expires_at, refreshed_at, next_at, error, created_by, created_at, updated_at, lease_owner, lease_until`

func scanOAuth(row pgx.Row, extra ...any) (*model.OAuthCredential, error) {
	var c model.OAuthCredential
	dest := append([]any{&c.Tenant, &c.Name, &c.Provider, &c.Status, &c.Generation, &c.VerificationURL, &c.UserCode, &c.LoginExpiresAt,
		&c.AccountID, &c.ExpiresAt, &c.RefreshedAt, &c.NextAt, &c.Error, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt, &c.LeaseOwner, &c.LeaseUntil}, extra...)
	if err := row.Scan(dest...); err != nil {
		return nil, err
	}
	return &c, nil
}

func (p *Postgres) PutOAuthCredential(ctx context.Context, c *model.OAuthCredential, ciphertext []byte) (bool, error) {
	// One statement: a new sign-in, or the old row replaced whole (the generation bumped so a
	// replica still polling or refreshing the old one cannot save over it, the lease dropped,
	// the creation kept). xmax = 0 tells an insert from an update.
	var created bool
	err := p.pool.QueryRow(ctx, `INSERT INTO oauth_credentials (tenant, name, provider, status, generation, verification_url, user_code,
			login_expires_at, account_id, expires_at, refreshed_at, next_at, error, ciphertext, created_by, created_at, updated_at, lease_owner, lease_until)
		VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now(),now(),'',NULL)
		ON CONFLICT (tenant, name) DO UPDATE SET provider=EXCLUDED.provider, status=EXCLUDED.status, generation=oauth_credentials.generation+1,
			verification_url=EXCLUDED.verification_url, user_code=EXCLUDED.user_code, login_expires_at=EXCLUDED.login_expires_at,
			account_id=EXCLUDED.account_id, expires_at=EXCLUDED.expires_at, refreshed_at=EXCLUDED.refreshed_at, next_at=EXCLUDED.next_at,
			error=EXCLUDED.error, ciphertext=EXCLUDED.ciphertext, created_by=EXCLUDED.created_by, updated_at=now(), lease_owner='', lease_until=NULL
		RETURNING generation, created_at, updated_at, (xmax = 0)`,
		c.Tenant, c.Name, c.Provider, c.Status, c.VerificationURL, c.UserCode, c.LoginExpiresAt, c.AccountID, c.ExpiresAt, c.RefreshedAt,
		c.NextAt, c.Error, ciphertext, c.CreatedBy).Scan(&c.Generation, &c.CreatedAt, &c.UpdatedAt, &created)
	c.LeaseOwner, c.LeaseUntil = "", nil
	return created, err
}

func (p *Postgres) GetOAuthCredential(ctx context.Context, tenant, name string) (*model.OAuthCredential, []byte, error) {
	var ciphertext []byte
	c, err := scanOAuth(p.pool.QueryRow(ctx, `SELECT `+oauthCols+`, ciphertext FROM oauth_credentials WHERE tenant=$1 AND name=$2`, tenant, name), &ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	return c, ciphertext, nil
}

func (p *Postgres) listOAuth(ctx context.Context, q string, args ...any) ([]*model.OAuthCredential, error) {
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.OAuthCredential
	for rows.Next() {
		c, err := scanOAuth(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) ListOAuthCredentials(ctx context.Context, tenant string) ([]*model.OAuthCredential, error) {
	return p.listOAuth(ctx, `SELECT `+oauthCols+` FROM oauth_credentials WHERE tenant=$1 ORDER BY name`, tenant)
}

func (p *Postgres) DeleteOAuthCredential(ctx context.Context, tenant, name string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM oauth_credentials WHERE tenant=$1 AND name=$2`, tenant, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DueOAuthCredentials(ctx context.Context, now time.Time, limit int) ([]*model.OAuthCredential, error) {
	if limit <= 0 {
		limit = 100
	}
	return p.listOAuth(ctx, `SELECT `+oauthCols+` FROM oauth_credentials
		WHERE status <> 'failed' AND next_at <= $1 AND (lease_owner = '' OR lease_until IS NULL OR lease_until <= $1)
		ORDER BY next_at LIMIT $2`, now, limit)
}

func (p *Postgres) LeaseOAuthCredential(ctx context.Context, tenant, name string, gen int, owner string, now, until time.Time) (*model.OAuthCredential, []byte, error) {
	// The lease is taken in the statement that checks it is free: two replicas racing for the
	// same row are serialized by the row lock, and the second finds the first one's lease.
	var ciphertext []byte
	c, err := scanOAuth(p.pool.QueryRow(ctx, `UPDATE oauth_credentials SET lease_owner=$4, lease_until=$6
		WHERE tenant=$1 AND name=$2 AND generation=$3 AND (lease_owner='' OR lease_owner=$4 OR lease_until IS NULL OR lease_until <= $5)
		RETURNING `+oauthCols+`, ciphertext`, tenant, name, gen, owner, now, until), &ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		var cur int
		switch err := p.pool.QueryRow(ctx, `SELECT generation FROM oauth_credentials WHERE tenant=$1 AND name=$2`, tenant, name).Scan(&cur); {
		case errors.Is(err, pgx.ErrNoRows):
			return nil, nil, ErrNotFound
		case err != nil:
			return nil, nil, err
		case cur != gen:
			return nil, nil, ErrNotFound
		}
		return nil, nil, ErrConflict
	}
	if err != nil {
		return nil, nil, err
	}
	return c, ciphertext, nil
}

func (p *Postgres) SaveOAuthCredential(ctx context.Context, c *model.OAuthCredential, ciphertext []byte, owner string) error {
	if owner == "" {
		return ErrConflict
	}
	saved, err := scanOAuth(p.pool.QueryRow(ctx, `UPDATE oauth_credentials SET status=$5, verification_url=$6, user_code=$7, login_expires_at=$8,
			account_id=$9, expires_at=$10, refreshed_at=$11, next_at=$12, error=$13, ciphertext=$14, updated_at=now(), lease_owner='', lease_until=NULL
		WHERE tenant=$1 AND name=$2 AND generation=$3 AND lease_owner=$4
		RETURNING `+oauthCols, c.Tenant, c.Name, c.Generation, owner, c.Status, c.VerificationURL, c.UserCode, c.LoginExpiresAt,
		c.AccountID, c.ExpiresAt, c.RefreshedAt, c.NextAt, c.Error, ciphertext))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	*c = *saved
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

// RotateAPIKey: see Atomics. The old key and its earlier successor are locked for the
// transaction, so a concurrent use (TouchAPIKey) of that successor either lands first and is
// seen, or waits until the withdrawal is decided.
func (p *Postgres) RotateAPIKey(ctx context.Context, oldID string, next *model.APIKey, at time.Time, opts RotateOptions) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	old, err := scanKey(tx.QueryRow(ctx, `SELECT `+keyCols+` FROM api_keys WHERE id=$1 FOR UPDATE`, oldID))
	if err != nil {
		return err
	}
	if old.RevokedAt != nil || !old.Active(at) {
		return ErrKeyInactive
	}
	if old.RotatedTo != "" {
		prev, err := scanKey(tx.QueryRow(ctx, `SELECT `+keyCols+` FROM api_keys WHERE id=$1 FOR UPDATE`, old.RotatedTo))
		switch {
		case errors.Is(err, ErrNotFound):
		case err != nil:
			return err
		case prev.LastUsedAt != nil || prev.RotatedTo != "":
			// Used, or rotated on in turn (its holder has the next key): the branch is taken,
			// even if that successor is no longer active itself.
			return &SuccessorInUseError{ID: prev.ID}
		case prev.RevokedAt != nil || !prev.Active(at):
		default:
			if _, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at=COALESCE(revoked_at, $2) WHERE id=$1`, prev.ID, at); err != nil {
				return err
			}
		}
	}
	// The expiry before the first rotation: recorded then, read back on a retry.
	var recorded bool
	var orig *time.Time
	if err := tx.QueryRow(ctx, `SELECT original_expires_at IS NOT NULL,
		CASE WHEN original_expires_at = 'infinity' THEN NULL ELSE original_expires_at END FROM api_keys WHERE id=$1`, oldID).Scan(&recorded, &orig); err != nil {
		return err
	}
	if !recorded && old.RotatedTo == "" {
		orig, recorded = old.ExpiresAt, true
	}
	if opts.InheritExpiry {
		exp := old.ExpiresAt
		if recorded {
			exp = orig
		}
		if exp != nil && !exp.After(at) {
			return ErrKeyInactive
		}
		next.ExpiresAt = earliest(exp, next.ExpiresAt)
	}
	if next.CreatedAt.IsZero() {
		next.CreatedAt = at
	}
	tag, err := tx.Exec(ctx, `INSERT INTO api_keys (`+keyCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (id) DO NOTHING`,
		next.ID, next.Tenant, next.Name, next.Hash, next.CreatedBy, next.CreatedAt, next.ExpiresAt, next.RevokedAt, next.RotatedTo, next.LastUsedAt, next.Trust)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: api key %s exists", ErrConflict, next.ID)
	}
	if recorded {
		// NULL would read as "not recorded": a key without expiry is kept as infinity.
		if _, err := tx.Exec(ctx, `UPDATE api_keys SET original_expires_at=COALESCE($2::timestamptz, 'infinity') WHERE id=$1`, oldID, orig); err != nil {
			return err
		}
	}
	if opts.Grace <= 0 {
		_, err = tx.Exec(ctx, `UPDATE api_keys SET rotated_to=$2, revoked_at=COALESCE(revoked_at, $3) WHERE id=$1`, oldID, next.ID, at)
	} else {
		_, err = tx.Exec(ctx, `UPDATE api_keys SET rotated_to=$2, expires_at=LEAST(COALESCE(expires_at, $3::timestamptz), $3::timestamptz) WHERE id=$1`, oldID, next.ID, at.Add(opts.Grace))
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// LockedAPIKey: see Atomics. FOR UPDATE waits for the transaction holding the row and then
// reads the version it committed (READ COMMITTED re-reads the updated row).
func (p *Postgres) LockedAPIKey(ctx context.Context, id string) (*model.APIKey, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	k, err := scanKey(tx.QueryRow(ctx, `SELECT `+keyCols+` FROM api_keys WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return nil, err
	}
	return k, tx.Commit(ctx)
}

// SwapBlob: see Atomics.
func (p *Postgres) SwapBlob(ctx context.Context, name string, old, data []byte) (bool, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE blobs SET data=$3 WHERE name=$1 AND data=$2`, name, old, data)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}
	var one int
	if err := p.pool.QueryRow(ctx, `SELECT 1 FROM blobs WHERE name=$1`, name).Scan(&one); errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	} else if err != nil {
		return false, err
	}
	return false, nil
}

// BindInstance: see Atomics. The sandbox row is locked first, so every bootstrap of the
// sandbox, on any replica, runs one after the other.
func (p *Postgres) BindInstance(ctx context.Context, b InstanceBinding, issue func(n int, existing *model.Instance) (*model.Instance, error)) (*BoundInstance, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	var current string
	if err := tx.QueryRow(ctx, `SELECT pod_name FROM sandboxes WHERE id=$1 FOR UPDATE`, b.SandboxID).Scan(&current); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT `+instCols+` FROM instances WHERE sandbox_id=$1 AND pod_name=$2 AND retired_at IS NULL ORDER BY n FOR UPDATE`, b.SandboxID, b.PodName)
	if err != nil {
		return nil, err
	}
	var live []*model.Instance
	for rows.Next() {
		in, err := scanInstance(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		live = append(live, in)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var reuse *model.Instance
	for _, in := range live {
		if in.Serial == b.Serial {
			reuse = in // ORDER BY n: the newest wins
		}
	}
	var n int
	if reuse != nil {
		n = reuse.N
	} else {
		var n64 int64
		if err := tx.QueryRow(ctx, `SELECT nextval('instance_seq')`).Scan(&n64); err != nil {
			return nil, err
		}
		n = int(n64)
	}
	var existing *model.Instance
	if reuse != nil {
		c := *reuse
		existing = &c
	}
	in, err := issue(n, existing)
	if err != nil {
		return nil, err
	}
	out := &BoundInstance{Reused: reuse != nil}
	if reuse == nil {
		in.N = n
		tag, err := tx.Exec(ctx, `INSERT INTO instances (n, sandbox_id, slug, tenant, pod_name, serial, issued_at, not_after, retired_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			in.N, in.SandboxID, in.Slug, in.Tenant, in.PodName, in.Serial, in.IssuedAt, in.NotAfter, in.RetiredAt)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			return nil, fmt.Errorf("%w: instance %d or serial %s is issued", ErrConflict, in.N, in.Serial)
		}
		out.Instance = in
	} else {
		out.Instance = reuse
	}
	for _, o := range live {
		if o.N != n {
			out.Retired = append(out.Retired, o.N)
		}
	}
	if len(out.Retired) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE instances SET retired_at=COALESCE(retired_at, now()) WHERE n = ANY($1)`, out.Retired); err != nil {
			return nil, err
		}
	}
	if err := tx.QueryRow(ctx, `UPDATE sandboxes SET instance=$2, pod_name=CASE WHEN pod_name='' THEN $3 ELSE pod_name END, revision=revision+1
		WHERE id=$1 RETURNING pod_name`, b.SandboxID, n, b.PodName).Scan(&out.Current); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// FirstUseAPIKey: see Atomics. The UPDATE waits for a rotation holding the row and then
// re-checks its WHERE on what that rotation committed.
func (p *Postgres) FirstUseAPIKey(ctx context.Context, id string, at time.Time) error {
	tag, err := p.pool.Exec(ctx, `UPDATE api_keys SET last_used_at=$2
		WHERE id=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $2)`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var one int
	if err := p.pool.QueryRow(ctx, `SELECT 1 FROM api_keys WHERE id=$1`, id).Scan(&one); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	return ErrKeyInactive
}

// errNoRunMatch: a conditional run write matched no row; the caller tells why.
var errNoRunMatch = errors.New("no run matched")

// insertEventsTx appends events of one run inside tx, stamped with the run's tenant and slug
// when they have none, and wakes every replica's listener once (NOTIFY is delivered at commit).
// The ids are drawn under the events lock AppendEvent takes, held to tx's commit: readers page
// by id, and an id drawn here must not become visible after a higher one another writer drew
// later. Callers insert their events last, so the lock is held only for the tail of tx.
func insertEventsTx(ctx context.Context, tx pgx.Tx, tenant, slug string, evs []*model.Event) error {
	if len(evs) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	b.Queue(eventsLockSQL)
	for _, e := range evs {
		if e.At.IsZero() {
			e.At = time.Now()
		}
		if e.Tenant == "" && e.Slug == "" {
			e.Tenant, e.Slug = tenant, slug
		}
		b.Queue(`INSERT INTO events (sandbox_id, tenant, slug, run_id, type, data, at) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			e.SandboxID, e.Tenant, e.Slug, e.RunID, e.Type, e.Data, e.At).QueryRow(func(row pgx.Row) error { return row.Scan(&e.ID) })
	}
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT pg_notify('`+eventsChannel+`', $1)`, strconv.FormatInt(evs[len(evs)-1].ID, 10))
	return err
}

func (p *Postgres) AppendRunOutput(ctx context.Context, b *OutputBatch) (*OutputResult, error) {
	chain := outputChain(b.Lines)
	var res *OutputResult
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		res = &OutputResult{}
		var sandbox, tenant, slug string
		var status model.RunStatus
		var attempt int
		// The run's row lock serialises the batches of a run: two replicas handling the same
		// batch at once (a retry racing the original) see each other's progress.
		err := tx.QueryRow(ctx, `SELECT sandbox_id, tenant, slug, status, attempt FROM runs WHERE id=$1 FOR UPDATE`, b.RunID).
			Scan(&sandbox, &tenant, &slug, &status, &attempt)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && sandbox != b.SandboxID {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if b.Attempt > 0 && b.Attempt != attempt {
			return ErrStaleAttempt
		}
		if b.BatchID != "" {
			// Both records of the batch's progress, each only within its retention (see
			// batchResume): an expired one is not there, whatever cleanup has run.
			var rec *batchProgress
			var got batchProgress
			err := tx.QueryRow(ctx, `SELECT lines, hash, complete FROM run_output_batches WHERE run_id=$1 AND batch_id=$2
				AND touched_at >= now() - $3::interval`, b.RunID, b.BatchID, outputBatchTTL.String()).
				Scan(&got.lines, &got.hash, &got.complete)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
			case err != nil:
				return err
			default:
				rec = &got
			}
			legacy := -1 // a batch an older release stored or continued
			err = tx.QueryRow(ctx, `SELECT status FROM idempotency WHERE key=$1 AND created_at >= now() - $2::interval`,
				legacyBatchKey(b.RunID, b.BatchID), IdempotencyTTL.String()).Scan(&legacy)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if res.Skipped, err = batchResume(rec, legacy, b, chain); err != nil {
				return err
			}
		}
		rest := b.Lines[res.Skipped:]
		// Usage as RecordRunUsage would apply it line by line; a run already done or failed has
		// its final usage and takes none (no error: the lines are still stored).
		if u, replace, ok := batchUsage(rest); ok && status != model.RunDone && status != model.RunFailed {
			if _, err := tx.Exec(ctx, `UPDATE runs SET
				model = CASE WHEN $2 THEN $3 WHEN $3 = '' THEN model ELSE $3 END,
				input_tokens = CASE WHEN $2 THEN 0 ELSE input_tokens END + $4,
				output_tokens = CASE WHEN $2 THEN 0 ELSE output_tokens END + $5,
				cache_read_tokens = CASE WHEN $2 THEN 0 ELSE cache_read_tokens END + $6,
				cache_write_tokens = CASE WHEN $2 THEN 0 ELSE cache_write_tokens END + $7,
				cost_usd = CASE WHEN $2 THEN 0 ELSE cost_usd END + $8,
				turns = CASE WHEN $2 THEN 0 ELSE turns END + $9
				WHERE id=$1`,
				b.RunID, replace, u.Model, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD, u.Turns); err != nil {
				return err
			}
		}
		if s := batchSession(rest); s != "" {
			if _, err := tx.Exec(ctx, `UPDATE runs SET session=$2 WHERE id=$1 AND session <> $2`, b.RunID, s); err != nil {
				return err
			}
		}
		if b.BatchID != "" {
			// Every call under the id, a retry that stores nothing included, keeps its progress for
			// another outputBatchTTL: a runner retries for as long as its harness lives. Once whole,
			// a batch stays whole.
			if _, err := tx.Exec(ctx, `INSERT INTO run_output_batches (run_id, batch_id, lines, hash, complete, touched_at) VALUES ($1,$2,$3,$4,$5,now())
				ON CONFLICT (run_id, batch_id) DO UPDATE SET lines=EXCLUDED.lines, hash=EXCLUDED.hash,
					complete = (run_output_batches.complete AND run_output_batches.touched_at >= now() - $6::interval) OR EXCLUDED.complete,
					touched_at=now()`,
				b.RunID, b.BatchID, len(b.Lines), chain[len(b.Lines)], !b.Partial, outputBatchTTL.String()); err != nil {
				return err
			}
			// The form an older replica reads, in the same transaction.
			if _, err := tx.Exec(ctx, `INSERT INTO idempotency (key, status, body, created_at) VALUES ($1,$2,'',now())
				ON CONFLICT (key) DO UPDATE SET status=EXCLUDED.status, created_at=now()`, legacyBatchKey(b.RunID, b.BatchID), len(b.Lines)); err != nil {
				return err
			}
		}
		// The events last: they take the events lock, held to the commit.
		at := time.Now()
		for _, l := range rest {
			res.Events = append(res.Events, &model.Event{SandboxID: b.SandboxID, RunID: b.RunID, Type: model.EventRunOutput, Data: l.Data, At: at})
		}
		if err := insertEventsTx(ctx, tx, tenant, slug, res.Events); err != nil {
			return err
		}
		res.Accepted = len(rest)
		return faultAt(p, FaultOutput)
	})
	if err != nil {
		return nil, err
	}
	if b.BatchID != "" && res.Skipped == 0 && res.Accepted > 0 {
		// A new batch makes room for itself: progress older than any retry is dropped.
		_, _ = p.pool.Exec(ctx, `DELETE FROM run_output_batches WHERE touched_at < now() - $1::interval`, outputBatchTTL.String())
	}
	return res, nil
}

func (p *Postgres) SettleRunWithEvents(ctx context.Context, s Settle) (*model.Run, error) {
	states := make([]string, len(s.From))
	for i, f := range s.From {
		states[i] = string(f)
	}
	var u model.Usage
	if s.Usage != nil {
		u = *s.Usage
	}
	var out *model.Run
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if f := s.Sandbox; f != nil {
			// FOR SHARE: a transition of the sandbox (a wake) waits for this commit.
			var status model.SandboxStatus
			var rev int64
			err := tx.QueryRow(ctx, `SELECT status, revision FROM sandboxes WHERE id=$1 FOR SHARE`, f.ID).Scan(&status, &rev)
			if errors.Is(err, pgx.ErrNoRows) || err == nil && (status != f.Status || f.Revision != 0 && rev != f.Revision) {
				return ErrFenced
			}
			if err != nil {
				return err
			}
		}
		r, err := scanRun(tx.QueryRow(ctx, `UPDATE runs SET status=$3, exit_code=$4, finished_at=$5,
			model = CASE WHEN $6 THEN $7 ELSE model END,
			input_tokens = CASE WHEN $6 THEN $8 ELSE input_tokens END,
			output_tokens = CASE WHEN $6 THEN $9 ELSE output_tokens END,
			cache_read_tokens = CASE WHEN $6 THEN $10 ELSE cache_read_tokens END,
			cache_write_tokens = CASE WHEN $6 THEN $11 ELSE cache_write_tokens END,
			cost_usd = CASE WHEN $6 THEN $12 ELSE cost_usd END,
			turns = CASE WHEN $6 THEN $13 ELSE turns END
			WHERE id=$1 AND status = ANY($2) AND ($14 = 0 OR attempt = $14) RETURNING `+runCols,
			s.RunID, states, s.To, s.ExitCode, s.FinishedAt, s.Usage != nil,
			u.Model, u.InputTokens, u.OutputTokens, u.CacheRead, u.CacheWrite, u.CostUSD, u.Turns, s.Attempt))
		if errors.Is(err, ErrNotFound) {
			return errNoRunMatch
		}
		if err != nil {
			return err
		}
		out = r
		if err := insertEventsTx(ctx, tx, r.Tenant, r.Slug, s.Events); err != nil {
			return err
		}
		return faultAt(p, FaultSettle)
	})
	if errors.Is(err, errNoRunMatch) {
		cur, gerr := p.GetRun(ctx, s.RunID)
		if gerr != nil {
			return nil, gerr
		}
		if s.Attempt > 0 && cur.Attempt != s.Attempt {
			return nil, ErrStaleAttempt
		}
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *Postgres) ReclaimRun(ctx context.Context, sandboxID, owner string) (*model.Run, error) {
	r, _, err := p.ClaimRunFor(ctx, sandboxID, "", time.Time{}, "", RunStamp{Owner: owner})
	return r, err
}

// claimLockSQL serialises the claims of one sandbox (ClaimRunFor): the reclaim check and the
// claim it falls back to are one decision.
const claimLockSQL = `SELECT pg_advisory_xact_lock(hashtext('agent-sandbox:claim:' || $1))`

func (p *Postgres) ClaimRunFor(ctx context.Context, sandboxID, runID string, startedAt time.Time, session string, stamp RunStamp) (*model.Run, *model.Event, error) {
	var out *model.Run
	var start *model.Event
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, claimLockSQL, sandboxID); err != nil {
			return err
		}
		if stamp.Owner != "" {
			// The owner's running runs are locked before anything is decided: an acknowledgement
			// or a settle holding a row's lock is waited for, and the row is read again after it
			// (Read Committed re-checks a locked row), so a claim confirmed or settled meanwhile
			// is never handed out again under a new attempt.
			rows, err := tx.Query(ctx, `SELECT id, claim_acked FROM runs WHERE sandbox_id=$1 AND status=$2 AND claimed_by=$3
				ORDER BY created_at, id FOR UPDATE`, sandboxID, model.RunRunning, stamp.Owner)
			if err != nil {
				return err
			}
			unacked, busy := "", false
			for rows.Next() {
				var id string
				var acked bool
				if err := rows.Scan(&id, &acked); err != nil {
					rows.Close()
					return err
				}
				if !acked && unacked == "" {
					unacked = id
				}
				busy = busy || acked
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			if unacked != "" {
				r, err := scanRun(tx.QueryRow(ctx, `UPDATE runs SET attempt=attempt+1
					WHERE id=$1 AND status=$2 AND claimed_by=$3 AND NOT claim_acked RETURNING `+runCols, unacked, model.RunRunning, stamp.Owner))
				if err != nil {
					return err
				}
				out = r
				return nil
			}
			if busy {
				return ErrOwnerBusy
			}
		}
		if runID == "" {
			return ErrNotFound
		}
		r, err := scanRun(tx.QueryRow(ctx, `UPDATE runs SET status=$3, started_at=$4,
			session = CASE WHEN session = '' THEN $5 ELSE session END,
			agent_version=$6, agent_ref=$7, agent_revision=$8, environment_ref=$9, environment_revision=$10,
			attempt=attempt+1, claimed_by=$11, claim_acked=false
			WHERE id=$1 AND sandbox_id=$12 AND status=$2 RETURNING `+runCols, runID, model.RunQueued, model.RunRunning, startedAt, session,
			stamp.AgentVersion, stamp.AgentRef, stamp.AgentRevision, stamp.EnvironmentRef, stamp.EnvironmentRevision, stamp.Owner, sandboxID))
		if errors.Is(err, ErrNotFound) {
			return errNoRunMatch
		}
		if err != nil {
			return err
		}
		out = r
		start = &model.Event{SandboxID: sandboxID, RunID: r.ID, Type: model.EventRunStart, Data: r.AgentVersion}
		return insertEventsTx(ctx, tx, r.Tenant, r.Slug, []*model.Event{start})
	})
	if errors.Is(err, errNoRunMatch) {
		cur, gerr := p.GetRun(ctx, runID)
		if gerr != nil {
			return nil, nil, gerr
		}
		if cur.SandboxID != sandboxID {
			return nil, nil, ErrNotFound
		}
		return nil, nil, ErrConflict
	}
	if err != nil {
		return nil, nil, err
	}
	return out, start, nil
}

func (p *Postgres) AckRunClaim(ctx context.Context, runID string, attempt int) error {
	tag, err := p.pool.Exec(ctx, `UPDATE runs SET claim_acked=true WHERE id=$1 AND attempt=$2`, runID, attempt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := p.GetRun(ctx, runID); err != nil {
			return err
		}
		return ErrStaleAttempt
	}
	return nil
}

func (p *Postgres) EnsureRunEvent(ctx context.Context, e *model.Event) (bool, error) {
	added := false
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var tenant, slug string
		// The run's row lock: two replicas repairing the same run append one event.
		err := tx.QueryRow(ctx, `SELECT tenant, slug FROM runs WHERE id=$1 FOR UPDATE`, e.RunID).Scan(&tenant, &slug)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM events WHERE sandbox_id=$1 AND type=$2 AND run_id=$3)`,
			e.SandboxID, e.Type, e.RunID).Scan(&exists); err != nil || exists {
			return err
		}
		added = true
		return insertEventsTx(ctx, tx, tenant, slug, []*model.Event{e})
	})
	return added && err == nil, err
}
