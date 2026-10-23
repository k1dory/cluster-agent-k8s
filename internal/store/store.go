// Package store persists sandboxes, runs, events and issued identities.
package store

import (
	"context"
	"errors"

	"agent-sandbox/internal/model"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// Store is the persistence interface. Postgres is the production implementation,
// Memory is used for tests and local development.
type Store interface {
	CreateSandbox(ctx context.Context, s *model.Sandbox) error
	GetSandbox(ctx context.Context, id string) (*model.Sandbox, error)
	ListSandboxes(ctx context.Context) ([]*model.Sandbox, error)
	UpdateSandbox(ctx context.Context, s *model.Sandbox) error
	DeleteSandbox(ctx context.Context, id string) error
	SandboxByPreviewHost(ctx context.Context, host string) (*model.Sandbox, error)

	CreateRun(ctx context.Context, r *model.Run) error
	GetRun(ctx context.Context, id string) (*model.Run, error)
	UpdateRun(ctx context.Context, r *model.Run) error
	ListRuns(ctx context.Context, sandboxID string) ([]*model.Run, error)
	NextQueuedRun(ctx context.Context, sandboxID string) (*model.Run, error)
	RunningRun(ctx context.Context, sandboxID string) (*model.Run, error)

	AppendEvent(ctx context.Context, e *model.Event) error
	ListEvents(ctx context.Context, sandboxID string, afterID int64, limit int) ([]*model.Event, error)

	// NextInstance atomically allocates the next instance number.
	NextInstance(ctx context.Context) (int, error)
	CreateInstance(ctx context.Context, in *model.Instance) error
	InstanceBySerial(ctx context.Context, serial string) (*model.Instance, error)
	RetireInstance(ctx context.Context, n int) error
	ListInstances(ctx context.Context, sandboxID string) ([]*model.Instance, error)

	Close() error
}
