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
	Instance                    int // current agent (identity) number; 0 = any
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

// ErrConflict is returned by UpdateSandbox when the row changed since it was read (the
// revision in the record is stale), and by PutItem when the expected revision is not the
// latest. Callers reload and reapply their change.
var ErrConflict = errors.New("changed concurrently")

// Applies persists apply records. ApplyStep is the heart of recovery: it writes an item
// revision (PutItem semantics with an expected current revision) and the apply's progress in
// one transaction, guarded by the apply's version, so a step is either fully applied and
// recorded or not at all, and two replicas cannot both commit the same step.
type Applies interface {
	// CreateApply stores a new apply; ErrConflict when its key already exists in its tenant.
	CreateApply(ctx context.Context, a *Apply) error
	GetApply(ctx context.Context, id string) (*Apply, error)
	// GetApplyByKey finds the apply submitted under key in tenant.
	GetApplyByKey(ctx context.Context, tenant, key string) (*Apply, error)
	// UpdateApply writes a if its Version still matches the stored one, then increments it;
	// ErrConflict otherwise.
	UpdateApply(ctx context.Context, a *Apply) error
	// ApplyStep, in one transaction: checks that the step's item is at revision expected (its
	// latest live revision; 0 = absent or deleted), appends it as a new revision when it is not
	// nil (a nil it is a noop step: the check alone), refuses the write when the revision it
	// would get differs from the step's NextRevision (history moved), and records a with the
	// step's Revision filled in, guarded by a.Version like UpdateApply. ErrConflict on any
	// mismatch, with nothing written.
	ApplyStep(ctx context.Context, a *Apply, step int, it *model.CatalogItem, expected int) error
	ListApplies(ctx context.Context, tenant string, limit int) ([]*Apply, error)
}

// APIKeys persists tenant API keys. Only the hash of a secret is ever stored. Every change
// is one narrow, atomic operation: a key is never written back from a copy, so a revocation
// cannot be undone by a concurrent use or rotation that read the key before it.
type APIKeys interface {
	CreateAPIKey(ctx context.Context, k *model.APIKey) error
	GetAPIKey(ctx context.Context, id string) (*model.APIKey, error)
	// TouchAPIKey records a use (last_used_at only).
	TouchAPIKey(ctx context.Context, id string, at time.Time) error
	// RevokeAPIKey ends the key at `at` unless it was revoked earlier (an earlier revocation
	// stands). ErrNotFound for an unknown key.
	RevokeAPIKey(ctx context.Context, id string, at time.Time) error
	// RetireAPIKey marks the key replaced by rotatedTo: revoked at `at` when grace is 0, else
	// expiring at `at`+grace (sooner if it already expires sooner). A revocation already
	// recorded stands. ErrNotFound for an unknown key.
	RetireAPIKey(ctx context.Context, id, rotatedTo string, at time.Time, grace time.Duration) error
	// ListAPIKeys returns a tenant's keys, newest first ("" = every tenant).
	ListAPIKeys(ctx context.Context, tenant string) ([]*model.APIKey, error)
}

// Credentials persists tenant-brought secrets, encrypted by the caller: the store sees
// ciphertext and metadata only.
type Credentials interface {
	// PutCredential adds or replaces (tenant, name): a replacement bumps Version and keeps
	// CreatedAt and CreatedBy; c comes back with the stored metadata. created reports an add.
	PutCredential(ctx context.Context, c *model.Credential, ciphertext []byte) (created bool, err error)
	// GetCredential returns the metadata and the ciphertext; ErrNotFound when absent.
	GetCredential(ctx context.Context, tenant, name string) (*model.Credential, []byte, error)
	// ListCredentials returns a scope's metadata, by name.
	ListCredentials(ctx context.Context, tenant string) ([]*model.Credential, error)
	// DeleteCredential removes one; ErrNotFound when absent.
	DeleteCredential(ctx context.Context, tenant, name string) error
}

// GitSyncs persists the last known state of each GitRepository (model.GitSync): one record
// per (tenant, name) with two halves written independently. Each Record call replaces its
// half whole and leaves the other untouched, atomically, with no read before the write: a
// check and a sync of the same repository may run at once, and a failed read never costs a
// record.
type GitSyncs interface {
	RecordGitCheck(ctx context.Context, tenant, name string, c model.GitCheck) error
	RecordGitSync(ctx context.Context, tenant, name string, r model.GitSyncResult) error
	RecordGitHook(ctx context.Context, tenant, name string, h model.GitHook) error
	// RecordGitHookIf writes the hook half only while the record's hook is absent or belongs
	// to job (the delivery accepted last is still that one), atomically; false when another
	// delivery was accepted meanwhile and the record keeps its summary.
	RecordGitHookIf(ctx context.Context, tenant, name string, h model.GitHook, job string) (bool, error)
	// GetGitSync returns the record; ErrNotFound when the repository was never checked or synced.
	GetGitSync(ctx context.Context, tenant, name string) (*model.GitSync, error)
}

// GitJobs persists webhook actions (model.GitJob) so an accepted delivery survives the replica
// that accepted it. Enqueue is idempotent per delivery (ErrConflict names the existing job);
// Claim hands one job to one replica at a time: a pending one whose wait is over, or a running
// one whose lease lapsed, atomically, under a new lease; Finish, Retry and Requeue move it on.
// Finish and Retry are the holder's only (owner and attempt as claimed): a lapsed lease taken
// over elsewhere, or claimed again by the same replica, refuses the former attempt's writes.
type GitJobs interface {
	EnqueueGitJob(ctx context.Context, j *model.GitJob) error
	// ClaimGitJob returns the next job for owner with a lease until now+lease, incrementing
	// Attempts; ErrNotFound when none is waiting. A pending job whose LeaseUntil is in the
	// future (a retry scheduled by RetryGitJob) is not waiting yet.
	ClaimGitJob(ctx context.Context, owner string, now time.Time, lease time.Duration) (*model.GitJob, error)
	// FinishGitJob records the outcome of the attempt the caller holds (ErrConflict when the
	// job is not running under that owner and attempt).
	FinishGitJob(ctx context.Context, id, owner string, attempt int, status, outcome, errMsg string) error
	// RetryGitJob puts the attempt the caller holds back to pending, to be claimed no earlier
	// than notBefore, keeping Attempts and recording why (ErrConflict as for Finish).
	RetryGitJob(ctx context.Context, id, owner string, attempt int, notBefore time.Time, errMsg string) error
	// RequeueGitJob makes a failed job, or a pending one waiting for its next attempt, due now
	// with Attempts reset (ErrConflict when the job is running or done): a redelivery of a
	// delivery whose job gave up or waits.
	RequeueGitJob(ctx context.Context, id string) error
	GetGitJob(ctx context.Context, id string) (*model.GitJob, error)
	// GetGitJobByDelivery finds the job of a delivery (tenant, name, delivery key).
	GetGitJobByDelivery(ctx context.Context, tenant, name, delivery string) (*model.GitJob, error)
}

// Apply is model.Apply (aliased so the store's doc reads on its own).
type Apply = model.Apply

// Catalog is the narrow interface the configuration catalogue needs: append-only revisions
// of named items per (kind, tenant), with a compare-and-append on the latest revision.
// Revision numbers are never reused: DeleteItem marks the live revisions deleted and keeps
// them, and the next PutItem under the same name continues from the highest number ever used.
type Catalog interface {
	// PutItem appends a revision. expected: -1 accepts any current state, 0 requires that the
	// item does not exist (or is deleted), N requires that the latest live revision is N.
	// On success it fills Revision and CreatedAt; on a mismatch it returns ErrConflict.
	PutItem(ctx context.Context, it *model.CatalogItem, expected int) error
	// GetItem returns live revision n (0 = latest) of an item; ErrNotFound when absent or deleted.
	GetItem(ctx context.Context, kind, tenant, name string, revision int) (*model.CatalogItem, error)
	// ListItems returns the latest live revision of every item of kind in tenant (tenant "" = shared).
	ListItems(ctx context.Context, kind, tenant string) ([]*model.CatalogItem, error)
	// ListRevisions returns every revision of an item in order, deleted ones included (they
	// carry DeletedAt); ErrNotFound when the name was never written.
	ListRevisions(ctx context.Context, kind, tenant, name string) ([]*model.CatalogItem, error)
	// DeleteItem marks every live revision of an item deleted; ErrNotFound when none is live.
	DeleteItem(ctx context.Context, kind, tenant, name string) error
	// ListKind returns the latest live revision of every item of kind in every tenant (for
	// in-memory snapshots of small, decision-critical kinds: bindings, tenant settings).
	ListKind(ctx context.Context, kind string) ([]*model.CatalogItem, error)
	// ListDeleted returns the last revision of every deleted item of kind in tenant (DeletedAt
	// set): what the drift report needs to notice a managed item that is gone.
	ListDeleted(ctx context.Context, kind, tenant string) ([]*model.CatalogItem, error)
}

// Lease is a held leadership lock. Ping fails once the lock is lost (connection gone), at
// which point the holder must stop acting as leader. Release gives the lock up.
type Lease interface {
	Ping(ctx context.Context) error
	Release()
}

// EventListener is implemented by stores that can tell this process about events other
// processes appended (Postgres LISTEN/NOTIFY). fn is called for every new event, in id order,
// until ctx ends. Replicas use it to feed their local event hub.
type EventListener interface {
	ListenEvents(ctx context.Context, fn func(e *model.Event))
}

// Store is the persistence interface. Postgres is the production implementation,
// Memory is used for tests and local development.
type Store interface {
	// CreateSandbox inserts the record and sets its Revision to 1.
	CreateSandbox(ctx context.Context, s *model.Sandbox) error
	GetSandbox(ctx context.Context, id string) (*model.Sandbox, error)
	ListSandboxes(ctx context.Context) ([]*model.Sandbox, error)
	// QuerySandboxes returns one page matching f, ordered by creation.
	QuerySandboxes(ctx context.Context, f SandboxFilter) ([]*model.Sandbox, error)
	// CountSandboxes counts a tenant's sandboxes without paging; slug "" counts every slug.
	CountSandboxes(ctx context.Context, tenant, slug string) (SandboxCounts, error)
	// UpdateSandbox writes the record if its Revision still matches the stored one, then
	// increments it (in the store and in s). ErrConflict otherwise.
	UpdateSandbox(ctx context.Context, s *model.Sandbox) error
	// TouchSandbox records activity without bumping the revision: it happens on every allowed
	// egress request and must never make another writer's update fail.
	TouchSandbox(ctx context.Context, id string, at time.Time) error
	DeleteSandbox(ctx context.Context, id string) error
	SandboxByPreviewHost(ctx context.Context, host string) (*model.Sandbox, error)

	// WithTenantLock runs fn while holding a lock shared by every replica for that tenant,
	// so a quota check and the allocation it guards cannot interleave with another one.
	WithTenantLock(ctx context.Context, tenant string, fn func(ctx context.Context) error) error
	// TryLead attempts to take the named leadership lock. held=false means another replica has it.
	TryLead(ctx context.Context, name string) (lease Lease, held bool, err error)
	// GetOrCreateBlob returns the stored bytes under name, creating them with create when
	// absent. Exactly one creator wins across replicas (the shared agent CA key lives here).
	GetOrCreateBlob(ctx context.Context, name string, create func() ([]byte, error)) ([]byte, error)
	// PutBlob stores (or replaces) bytes under name; GetBlob reads them (ErrNotFound when
	// absent); DeleteBlob removes one; DeleteBlobsBefore removes every blob whose name has the
	// prefix and which was created before t (file transfers that were never collected).
	PutBlob(ctx context.Context, name string, data []byte) error
	GetBlob(ctx context.Context, name string) ([]byte, error)
	DeleteBlob(ctx context.Context, name string) error
	DeleteBlobsBefore(ctx context.Context, prefix string, t time.Time) (int, error)

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

	// The catalogue uses only this part (see Catalog); the full Store embeds it for wiring.
	Catalog
	Applies
	APIKeys
	Credentials
	GitSyncs
	GitJobs

	Close() error
}

// IdempotencyTTL is how long a stored response is replayed.
const IdempotencyTTL = 24 * time.Hour

// IdempotencyStale is how long an unfinished reservation blocks retries before it is
// considered abandoned (the process died mid-request) and may be taken over.
const IdempotencyStale = 2 * time.Minute
