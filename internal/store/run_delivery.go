package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"agent-sandbox/internal/model"
)

// RunDelivery is how a run's state moves together with what its runner and its clients are
// told about it. Every operation is one transaction: a replica that dies, or a write that
// fails, leaves either all of it or none, so an acknowledged batch always carries its usage, a
// settled run always carries its events, and a retry finds exactly what was committed.
type RunDelivery interface {
	// AppendRunOutput stores a batch of output lines of a run with the usage and session they
	// carry, in one transaction. With a BatchID, the batch's progress is recorded in the same
	// transaction and a repeated call (a retry after a lost response, on any replica, even
	// concurrently) stores only the lines past it; a body that differs from the one recorded
	// under that id is refused with ErrBatchMismatch. Usage is applied while the run is not done
	// or failed (see RecordRunUsage), the session in every status (see SetRunSession).
	// ErrNotFound when the run is absent or belongs to another sandbox; ErrStaleAttempt when
	// b.Attempt is set and the run has been handed out again since.
	AppendRunOutput(ctx context.Context, b *OutputBatch) (*OutputResult, error)
	// SettleRunWithEvents is SettleRun and the events that announce the transition, in one
	// transaction: the events are appended only when the run moved, and the run moves only when
	// they are appended. Events get the run's tenant and slug when they have none, and their ids.
	// ErrStaleAttempt when s.Attempt is set and the run has been handed out again since.
	SettleRunWithEvents(ctx context.Context, s Settle) (*model.Run, error)
	// ReclaimRun hands a run out again to the owner that claimed it, when the owner has not
	// confirmed it got it (AckRunClaim): the response of the claim was lost and the runner asks
	// again. The attempt is incremented, so whatever held the earlier one cannot write. Only
	// the oldest such run of the sandbox; ErrNotFound when there is none.
	ReclaimRun(ctx context.Context, sandboxID, owner string) (*model.Run, error)
	// AckRunClaim records that the owner of attempt has the run: it is not handed out again.
	// ErrStaleAttempt when the run is at another attempt, ErrNotFound when it is absent.
	AckRunClaim(ctx context.Context, runID string, attempt int) error
	// EnsureRunEvent appends e (a run's event, e.RunID set) unless the run already has an event
	// of that type, atomically against a concurrent call; reports whether it appended. The
	// repair of a command whose event a replica of an older release, or a crash, failed to write.
	EnsureRunEvent(ctx context.Context, e *model.Event) (bool, error)
}

// ErrBatchMismatch: the X-Batch-Id was already used for a different body.
var ErrBatchMismatch = errors.New("batch id was already used with a different body")

// ErrStaleAttempt: the run was handed out again (ReclaimRun) after the caller's attempt; its
// writes are refused. It is an ErrConflict.
var ErrStaleAttempt = fmt.Errorf("%w: the run was handed out again since this attempt", ErrConflict)

// OutputLine is one line of a batch and what it carries.
type OutputLine struct {
	Data       string
	Usage      *model.Usage // nil: the line carries none
	UsageTotal bool         // Usage is the harness's running total: replace, not add
	Session    string       // "" when the line names no session
}

// OutputBatch is one POST of output lines.
type OutputBatch struct {
	SandboxID, RunID string
	BatchID          string // "" = no retry protection
	Attempt          int    // > 0: refuse when the run is at another attempt
	Lines            []OutputLine
}

// OutputResult: Skipped lines were stored by an earlier call under the same batch id, Events
// are the ones this call appended (for the local hub).
type OutputResult struct {
	Accepted, Skipped int
	Events            []*model.Event
}

// Settle is a SettleRun with its events (see SettleRunWithEvents).
type Settle struct {
	RunID      string
	From       []model.RunStatus
	To         model.RunStatus
	ExitCode   int
	FinishedAt time.Time
	Usage      *model.Usage
	Attempt    int // > 0: only while the run is at this attempt
	Events     []*model.Event
}

// outputChain is the running hash of a batch's lines: chain[n] covers the first n. A retry is
// the same batch when its first n lines hash to what was recorded with n.
func outputChain(lines []OutputLine) []string {
	out := make([]string, len(lines)+1)
	var prev []byte
	for i, l := range lines {
		h := sha256.New()
		h.Write(prev)
		h.Write([]byte(l.Data))
		prev = h.Sum(nil)
		out[i+1] = hex.EncodeToString(prev)
	}
	return out
}

// batchUsage folds the usage of a batch's lines into one write with the effect of applying them
// in order: replace when a total appears (and add what follows it), add otherwise.
func batchUsage(lines []OutputLine) (u model.Usage, replace, any bool) {
	for _, l := range lines {
		if l.Usage == nil {
			continue
		}
		any = true
		if l.UsageTotal {
			u, replace = *l.Usage, true
			continue
		}
		u.Add(*l.Usage)
	}
	return u, replace, any
}

// batchSession is the last session a batch names ("" when none).
func batchSession(lines []OutputLine) string {
	s := ""
	for _, l := range lines {
		if l.Session != "" {
			s = l.Session
		}
	}
	return s
}

// outputBatchTTL is how long a batch's progress is kept: a runner retries a batch for minutes,
// never for a day.
const outputBatchTTL = IdempotencyTTL
