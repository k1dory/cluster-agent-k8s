package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
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
	// the oldest such run of the sandbox; ErrNotFound when there is none. It is ClaimRunFor
	// with no run to fall back to.
	ReclaimRun(ctx context.Context, sandboxID, owner string) (*model.Run, error)
	// ClaimRunFor is the whole claim decision of one /agent/runs/next, serialised per sandbox:
	// the run stamp.Owner claimed and never confirmed, handed out again (start nil);
	// ErrOwnerBusy while the owner executes a run it confirmed; or else ClaimRun of runID (the
	// oldest queued run the caller read), with its run.start (data: the agent version) appended
	// in the same transaction and returned as start: a run is never handed to a runner before
	// the event that says it started exists, and a reclaim appends no second one. Decided apart, a retry
	// overlapping the request whose response was lost could miss the claim being made and take
	// the next queued run, executing a continuation before the run it continues. ErrConflict
	// when runID is no longer queued, ErrNotFound when it is absent, not the sandbox's, or "".
	ClaimRunFor(ctx context.Context, sandboxID, runID string, startedAt time.Time, session string, stamp RunStamp) (r *model.Run, start *model.Event, err error)
	// AckRunClaim records that the owner of attempt has the run: it is not handed out again.
	// ErrStaleAttempt when the run is at another attempt, ErrNotFound when it is absent.
	AckRunClaim(ctx context.Context, runID string, attempt int) error
	// EnsureRunEvent appends e (a run's event, e.RunID set) unless the run already has an event
	// of that type, atomically against a concurrent call; reports whether it appended. The
	// repair of a command whose event a replica of an older release, or a crash, failed to write.
	EnsureRunEvent(ctx context.Context, e *model.Event) (bool, error)
}

// ErrOwnerBusy: the owner is executing a run it confirmed (ClaimRunFor): it gets no other run
// until that one is settled. A request of it that was delayed past its own retry would
// otherwise start the next run (a continuation, before the session it continues is known). It
// is an ErrNotFound: there is no work for the owner now.
var ErrOwnerBusy = fmt.Errorf("%w: the owner is executing a run it confirmed", ErrNotFound)

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
	// Partial: the body was cut short (a 413) and Lines is only its beginning, so a later call
	// under the same id may carry more. A batch stored whole takes no other body, longer or not.
	Partial bool
}

// batchProgress is what is recorded of a batch id: how many lines are stored, the hash of
// those lines, and whether they were the whole body.
type batchProgress struct {
	lines    int
	hash     string
	complete bool
}

// resume is how many lines of b were stored already under its id, or ErrBatchMismatch when b
// is not that batch again: another body, fewer lines, or, against a batch stored whole, any
// body but the same whole one (more lines, or a cut-off one: a 413 must not reopen it).
func (rec batchProgress) resume(b *OutputBatch, chain []string) (int, error) {
	if rec.lines > len(b.Lines) || chain[rec.lines] != rec.hash || rec.complete && (b.Partial || len(b.Lines) != rec.lines) {
		return 0, ErrBatchMismatch
	}
	return rec.lines, nil
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
	// Sandbox, when set: only while the run's sandbox is still in this status (and at this
	// revision, unless 0; ErrFenced otherwise), checked in the same transaction and held against a concurrent
	// change of the sandbox until the commit. A stop cancels the run of the pod it stopped,
	// never that of a replacement another replica started after finishing the stop.
	Sandbox *SandboxFence
}

// SandboxFence is a sandbox as a writer observed it: its status, and its revision unless 0.
type SandboxFence struct {
	ID       string
	Status   model.SandboxStatus
	Revision int64
}

// ErrFenced: the sandbox moved on from the state the settle was fenced on. It is an ErrConflict.
var ErrFenced = fmt.Errorf("%w: the sandbox moved on since it was observed", ErrConflict)

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

// legacyBatchKey is where a release before run_output_batches recorded a batch's progress: an
// idempotency record whose status is the number of lines stored, with no hash. It is still
// read (a batch stored by an older replica, retried after the upgrade, must not be stored
// again) and still written (an older replica of a rolling update reads only it).
func legacyBatchKey(runID, batchID string) string { return "batch|" + runID + "|" + batchID }

// legacyResume is resume for a legacy record of n lines: no hash to compare, so its count is
// trusted, as the release that wrote it did.
func legacyResume(n int, b *OutputBatch) (int, error) {
	if n > len(b.Lines) {
		return 0, ErrBatchMismatch
	}
	return n, nil
}

// outputBatchTTL is how long a batch's progress is kept after the last call under its id. A
// runner retries a batch for as long as its harness lives, with at most 30 s between attempts
// (postBackoffMax in cmd/agent-runner), so every retry renews it long before it runs out.
const outputBatchTTL = IdempotencyTTL

// Fault points of the RunDelivery transactions: the last step before the commit, after every
// write of the operation. A failure injected there rolls the whole operation back.
const (
	FaultOutput = "output" // AppendRunOutput
	FaultSettle = "settle" // SettleRunWithEvents
)

var faults sync.Map // Store → func(point string) error

// SetFaultHook makes fn run at every fault point of st's RunDelivery transactions (a *Memory or
// a *Postgres, not a wrapper); an error it returns fails the operation there, rolled back. nil
// removes it. For tests: the failures a replica meets between its writes and its commit.
func SetFaultHook(st Store, fn func(point string) error) {
	if fn == nil {
		faults.Delete(st)
		return
	}
	faults.Store(st, fn)
}

func faultAt(st Store, point string) error {
	if fn, ok := faults.Load(st); ok {
		return fn.(func(string) error)(point)
	}
	return nil
}
