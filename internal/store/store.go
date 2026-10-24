// Package store persists sandboxes, runs, events and issued identities.
package store

import (
	"context"
	"errors"
	"time"

	"agent-sandbox/internal/model"
)

// Filter selects runs or events across sandboxes for accounting and tracing.
// Empty fields match everything; From/To bound CreatedAt (runs) or At (events).
type Filter struct {
	Tenant    string
	Slug      string
	SandboxID string
	RunID     string
	Status    string   // runs only
	Types     []string // events only
	From, To  time.Time
	AfterID   int64  // events only: pagination cursor
	Cursor    string // runs only: id of the last run of the previous page
	Limit     int
}

// SandboxFilter selects sandboxes for a list page.
type SandboxFilter struct {
	Tenant, Owner, Slug, Status string
	Cursor                      string // id of the last sandbox of the previous page
	Limit                       int
}

// Idempotent is a stored response, replayed when a client repeats a request with the same key.
type Idempotent struct {
	Key       string
	Status    int
	Body      []byte
	CreatedAt time.Time
}

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
	UpdateSandbox(ctx context.Context, s *model.Sandbox) error
	DeleteSandbox(ctx context.Context, id string) error
	SandboxByPreviewHost(ctx context.Context, host string) (*model.Sandbox, error)

	CreateRun(ctx context.Context, r *model.Run) error
	GetRun(ctx context.Context, id string) (*model.Run, error)
	UpdateRun(ctx context.Context, r *model.Run) error
	ListRuns(ctx context.Context, sandboxID string) ([]*model.Run, error)
	// QueryRuns returns runs matching f across sandboxes, oldest first.
	QueryRuns(ctx context.Context, f Filter) ([]*model.Run, error)
	NextQueuedRun(ctx context.Context, sandboxID string) (*model.Run, error)
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

	// PutIdempotent stores a response under key; GetIdempotent returns ErrNotFound when unknown or expired.
	PutIdempotent(ctx context.Context, rec *Idempotent) error
	GetIdempotent(ctx context.Context, key string) (*Idempotent, error)

	Close() error
}

// IdempotencyTTL is how long a stored response is replayed.
const IdempotencyTTL = 24 * time.Hour
