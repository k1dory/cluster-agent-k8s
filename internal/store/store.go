// Package store persists sandboxes, runs, events and issued identities.
package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"agent-sandbox/internal/model"
)

// Cursor is an opaque page cursor: the (created_at, id) of the last item of a page. It keeps
// working when that item is later deleted or no longer matches the filter.
type Cursor struct {
	At time.Time
	ID string
}

// Encode renders the cursor for clients.
func (c Cursor) Encode() string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(c.At.UnixNano(), 10) + ":" + c.ID))
}

// IsZero reports an unset cursor.
func (c Cursor) IsZero() bool { return c.ID == "" }

// ParseCursor decodes what Encode produced.
func ParseCursor(s string) (Cursor, error) {
	if s == "" {
		return Cursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, fmt.Errorf("malformed cursor")
	}
	ns, id, ok := strings.Cut(string(raw), ":")
	n, err2 := strconv.ParseInt(ns, 10, 64)
	if !ok || err2 != nil || id == "" {
		return Cursor{}, fmt.Errorf("malformed cursor")
	}
	return Cursor{At: time.Unix(0, n), ID: id}, nil
}

// after reports whether (at, id) sorts after the cursor.
func (c Cursor) after(at time.Time, id string) bool {
	if c.IsZero() {
		return true
	}
	if at.Equal(c.At) {
		return id > c.ID
	}
	return at.After(c.At)
}

// Filter selects runs or events across sandboxes for accounting and tracing.
// Empty fields match everything; From/To bound CreatedAt (runs) or At (events).
type Filter struct {
	Tenant    string
	Slug      string
	SandboxID string
	RunID     string
	Status    string   // runs only
	Types     []string // events only
	// RunScope (events only): keep events of this run and events addressed to no run (run_id ""),
	// applied in the store before LIMIT.
	RunScope string
	From, To time.Time
	AfterID  int64  // events only: pagination cursor
	Cursor   Cursor // runs only: page cursor
	Limit    int
}

// SandboxFilter selects sandboxes for a list page.
type SandboxFilter struct {
	Tenant, Owner, Slug, Status string
	Cursor                      Cursor
	Limit                       int
}

// SandboxCounts is what quotas are checked against.
type SandboxCounts struct {
	Total int // records, any status
	Awake int // creating, waking, running
}

// Idempotent is a reservation of an Idempotency-Key and, once the request finished, its
// stored 2xx response. Status 0 means "in progress".
type Idempotent struct {
	Key       string
	BodyHash  string // sha256 of the request body: the same key with another body is an error
	Status    int
	Body      []byte
	CreatedAt time.Time
}

// InProgress reports a reserved key whose request has not finished.
func (i *Idempotent) InProgress() bool { return i.Status == 0 }

// EventCount is one row of a GROUP BY over events.
type EventCount struct {
	Tenant, Slug, SandboxID, RunID, Type string
	Day                                  time.Time // UTC midnight of the event
	N                                    int64
}

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// Store is the persistence interface. Postgres is the production implementation,
// Memory is used for tests and local development.
type Store interface {
	CreateSandbox(ctx context.Context, s *model.Sandbox) error
	GetSandbox(ctx context.Context, id string) (*model.Sandbox, error)
	ListSandboxes(ctx context.Context) ([]*model.Sandbox, error)
	// QuerySandboxes returns one page matching f, ordered by creation.
	QuerySandboxes(ctx context.Context, f SandboxFilter) ([]*model.Sandbox, error)
	// CountSandboxes counts a tenant's sandboxes without paging.
	CountSandboxes(ctx context.Context, tenant string) (SandboxCounts, error)
	UpdateSandbox(ctx context.Context, s *model.Sandbox) error
	DeleteSandbox(ctx context.Context, id string) error
	SandboxByPreviewHost(ctx context.Context, host string) (*model.Sandbox, error)

	CreateRun(ctx context.Context, r *model.Run) error
	GetRun(ctx context.Context, id string) (*model.Run, error)
	UpdateRun(ctx context.Context, r *model.Run) error
	ListRuns(ctx context.Context, sandboxID string) ([]*model.Run, error)
	// QueryRuns returns runs matching f across sandboxes, oldest first.
	QueryRuns(ctx context.Context, f Filter) ([]*model.Run, error)
	// ClaimQueuedRun atomically moves the oldest queued run of the sandbox to running and
	// returns it; concurrent callers never get the same run. ErrNotFound when none is queued.
	ClaimQueuedRun(ctx context.Context, sandboxID string, startedAt time.Time) (*model.Run, error)
	RunningRun(ctx context.Context, sandboxID string) (*model.Run, error)

	AppendEvent(ctx context.Context, e *model.Event) error
	ListEvents(ctx context.Context, sandboxID string, afterID int64, limit int) ([]*model.Event, error)
	// QueryEvents returns events matching f across sandboxes, by id ascending.
	QueryEvents(ctx context.Context, f Filter) ([]*model.Event, error)
	// CountEvents groups matching events by tenant, slug, sandbox, run, type and day.
	CountEvents(ctx context.Context, f Filter) ([]EventCount, error)

	// NextInstance atomically allocates the next instance number.
	NextInstance(ctx context.Context) (int, error)
	CreateInstance(ctx context.Context, in *model.Instance) error
	InstanceBySerial(ctx context.Context, serial string) (*model.Instance, error)
	RetireInstance(ctx context.Context, n int) error
	ListInstances(ctx context.Context, sandboxID string) ([]*model.Instance, error)

	// ReserveIdempotent atomically claims key for this body. reserved=true means the caller
	// owns the key and must finish with PutIdempotent or ReleaseIdempotent; otherwise existing
	// is the earlier reservation or stored response.
	ReserveIdempotent(ctx context.Context, key, bodyHash string) (existing *Idempotent, reserved bool, err error)
	// PutIdempotent records the finished response under a reserved key.
	PutIdempotent(ctx context.Context, rec *Idempotent) error
	// ReleaseIdempotent drops a reservation whose request failed, so a retry may run.
	ReleaseIdempotent(ctx context.Context, key string) error
	GetIdempotent(ctx context.Context, key string) (*Idempotent, error)

	Close() error
}

// IdempotencyTTL is how long a stored response is replayed.
const IdempotencyTTL = 24 * time.Hour

// IdempotencyStale is how long an unfinished reservation blocks retries before it is
// considered abandoned (the process died mid-request) and may be taken over.
const IdempotencyStale = 2 * time.Minute
