package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// An Idempotency-Key binds a request to what it creates through the reservation's seed: the
// first sandbox (or run) a keyed request creates is named KeyedID(seed, prefix) instead of a
// random id. The seed survives a takeover of an abandoned reservation, so the attempt that
// takes over names its resource as the abandoned one did: it finds that one (the API reads it
// back) or, if it raced a holder that was slow rather than dead, the store refuses the second
// insert of the same id. Either way the key never yields two resources.
//
// Only the first id of each prefix is keyed: a request may create more of the same kind on
// the way (a wake that queues the resume of an interrupted run), and those stay random.

type keyedIDsKey struct{}

type keyedIDs struct {
	seed string
	mu   sync.Mutex
	used map[string]bool
}

// WithKeyedIDs returns ctx carrying seed for the request's first id of each prefix.
func WithKeyedIDs(ctx context.Context, seed string) context.Context {
	if seed == "" {
		return ctx
	}
	return context.WithValue(ctx, keyedIDsKey{}, &keyedIDs{seed: seed, used: map[string]bool{}})
}

// KeyedID is the id a keyed request's first resource of prefix gets: the shape of newID's, 48
// bits of the seed's hash instead of 48 random bits.
func KeyedID(seed, prefix string) string {
	sum := sha256.Sum256([]byte(prefix + "|" + seed))
	return prefix + "_" + hex.EncodeToString(sum[:6])
}

// idFor is newID, or the keyed id when ctx carries a seed whose prefix is still unused.
func idFor(ctx context.Context, prefix string) string {
	k, _ := ctx.Value(keyedIDsKey{}).(*keyedIDs)
	if k == nil {
		return newID(prefix)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.used[prefix] {
		return newID(prefix)
	}
	k.used[prefix] = true
	return KeyedID(k.seed, prefix)
}

// keyedSeed is the seed ctx carries, "" without one.
func keyedSeed(ctx context.Context) string {
	if k, _ := ctx.Value(keyedIDsKey{}).(*keyedIDs); k != nil {
		return k.seed
	}
	return ""
}

// WakeForKeyedRun wakes the sandbox of a run an earlier attempt of a keyed request queued, when
// the run still waits and the sandbox sleeps: that attempt may have died between the insert and
// its wake, and nothing else wakes a sandbox for queued work.
// An error means the sandbox could not be inspected or the wake did not get to start it: the
// caller must answer as failed (not store a success the wake may never follow).
func (o *Orchestrator) WakeForKeyedRun(ctx context.Context, run *model.Run) error {
	waits, err := o.keyedRunWaits(ctx, run)
	if err != nil {
		return err
	}
	if waits {
		return o.keyedWake(ctx, run.SandboxID, run.ID)
	}
	return nil
}

// keyedWake is wakeForRun for a keyed request, whose success every retry replays and a replay
// wakes nothing: a wake that failed before it moved the sandbox (its read, its tenant lock, an
// ended context) is returned, so the request is answered as failed and its retry wakes again.
// A wake whose outcome the sandbox shows is not an error here, as for wakeForRun: a runtime
// failure is recorded on it (status error, the run starts on the next wake), a revoked slug
// or a status that refuses a start (deleting, stopping) answers the same on every retry.
func (o *Orchestrator) keyedWake(ctx context.Context, sandboxID, runID string) error {
	_, err := o.Wake(ctx, sandboxID)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrRuntime) || errors.Is(err, ErrForbidden) || errors.Is(err, ErrConflict) {
		o.Log.Warn("wake for run failed", "sandbox", sandboxID, "run", runID, "err", err)
		return nil
	}
	return err
}

func (o *Orchestrator) keyedRunWaits(ctx context.Context, run *model.Run) (bool, error) {
	if run.Status != model.RunQueued {
		return false, nil
	}
	sb, err := o.Store.GetSandbox(ctx, run.SandboxID)
	if err != nil {
		return false, err
	}
	return sb.Status == model.StatusSleeping || sb.Status == model.StatusError, nil
}

// insertRun records a queued run and its run.queued event. A keyed request's run (the one
// named from its seed) and its event are one store write (CreateKeyedRun): an attempt that
// finds the run later finds the user turn the conversation shows for it too.
func (o *Orchestrator) insertRun(ctx context.Context, r *model.Run) error {
	e := model.Event{SandboxID: r.SandboxID, RunID: r.ID, Type: model.EventRunQueued, Data: r.ResumeOf}
	if seed := keyedSeed(ctx); seed == "" || r.ID != KeyedID(seed, "run") {
		if err := o.Store.CreateRun(ctx, r); err != nil {
			return err
		}
		o.emit(ctx, e)
		return nil
	}
	e.Tenant, e.Slug = r.Tenant, r.Slug
	if err := o.Store.CreateKeyedRun(ctx, r, &e); err != nil {
		return err
	}
	if o.Hub != nil && !o.ListenerPublishes {
		o.Hub.Publish(e)
	}
	return nil
}

// A keyed message's delivery is recorded on its reservation (store.KeyedResults), so every
// attempt of the request delivers it once: as input to a run in progress, joined to a queued
// task, or as a new run. The note is written under Say's sandbox lock right after the delivery
// and checked under it before one; a new run is found by its keyed id as well, should the note
// be missing. It lives as long as the reservation does.
type saidRecord struct {
	Run string `json:"run"`
	How string `json:"how"`
}

// keyedSaid returns the delivery an earlier attempt of this keyed message made; said=false
// when there is none (or no key).
func (o *Orchestrator) keyedSaid(ctx context.Context, sandboxID string) (run *model.Run, how string, wake, said bool, err error) {
	seed := keyedSeed(ctx)
	if seed == "" {
		return nil, "", false, false, nil
	}
	_, note, err := o.Store.KeyedResult(ctx, seed)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, "", false, false, err
	}
	if note != "" {
		var rec saidRecord
		if err := json.Unmarshal([]byte(note), &rec); err != nil {
			return nil, "", false, false, err
		}
		if run, err = o.Store.GetRun(ctx, rec.Run); err != nil {
			return nil, "", false, false, err
		}
		how = rec.How
	} else {
		run, err = o.Store.GetRun(ctx, KeyedID(seed, "run"))
		if errors.Is(err, store.ErrNotFound) || err == nil && run.SandboxID != sandboxID {
			return nil, "", false, false, nil
		}
		if err != nil {
			return nil, "", false, false, err
		}
		how = DeliveredNew
		if run.ResumeOf != "" {
			how = DeliveredResumed
		}
	}
	waits, err := o.keyedRunWaits(ctx, run)
	if err != nil {
		return nil, "", false, false, err
	}
	return run, how, waits, true, nil
}

// recordSaid notes a keyed message's delivery. On a context of its own: the delivery has
// happened, and a client that hangs up now must not leave its retry to deliver it again.
func (o *Orchestrator) recordSaid(ctx context.Context, sandboxID string, run *model.Run, how string) {
	seed := keyedSeed(ctx)
	if seed == "" {
		return
	}
	ctx, cancel := detached(ctx)
	defer cancel()
	b, _ := json.Marshal(saidRecord{Run: run.ID, How: how})
	if err := o.Store.NoteKeyedSaid(ctx, seed, string(b)); err != nil {
		o.Log.Warn("record keyed message delivery", "sandbox", sandboxID, "run", run.ID, "err", err)
	}
}

// detachedTimeout bounds what a keyed request finishes after its client may have gone.
const detachedTimeout = 30 * time.Second

// detached is ctx without its cancellation (values kept), bounded.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
}

// insertSandbox creates the record; a keyed request's sandbox is recorded on its reservation
// in the same transaction (see store.KeyedResults).
func (o *Orchestrator) insertSandbox(ctx context.Context, sb *model.Sandbox) error {
	if seed := keyedSeed(ctx); seed != "" && sb.ID == KeyedID(seed, "sb") {
		return o.Store.CreateKeyedSandbox(ctx, sb, seed)
	}
	return o.Store.CreateSandbox(ctx, sb)
}

// wakeKeyed wakes the sandbox for a run just queued. Under an Idempotency-Key the wake does
// not end with the client: the request's success is stored for every retry to replay, and a
// replay wakes nothing, so a wake cut short by a hang-up would leave the run waiting in a
// sleeping sandbox. For the same reason a keyed wake that did not get to start the sandbox
// is returned (keyedWake); without a key it is logged, as wakeForRun does.
func (o *Orchestrator) wakeKeyed(ctx context.Context, sandboxID, runID string) error {
	if keyedSeed(ctx) == "" {
		o.wakeForRun(ctx, sandboxID, runID)
		return nil
	}
	ctx, cancel := detached(ctx)
	defer cancel()
	return o.keyedWake(ctx, sandboxID, runID)
}

// KeyedSandbox is what an earlier attempt of the keyed create in ctx made: the sandbox, or
// gone=true when it was created and has been deleted since (it is not created again).
// found=false when no attempt created one. An error means that could not be established (a
// read failed): the caller answers as failed, never as "nothing created", since a fresh
// creation would then resolve inputs the existing sandbox no longer needs (and fail on a
// definition deleted since) or race the one that exists.
func (o *Orchestrator) KeyedSandbox(ctx context.Context) (sb *model.Sandbox, gone, found bool, err error) {
	seed := keyedSeed(ctx)
	if seed == "" {
		return nil, false, false, nil
	}
	id := KeyedID(seed, "sb")
	sb, err = o.Store.GetSandbox(ctx, id)
	if err == nil {
		return sb, false, true, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, false, false, err
	}
	created, _, err := o.Store.KeyedResult(ctx, seed)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false, false, nil // no live reservation has the seed: nothing to find
	}
	if err != nil {
		return nil, false, false, err
	}
	if created != id {
		return nil, false, false, nil
	}
	// The record says the sandbox was created, but the first read may have come before that
	// creation committed: a slow attempt's insert (sandbox and record, one transaction) can
	// land between the two reads. Read again: the record is written with the sandbox, and a
	// keyed sandbox once created is never inserted again, so absent now means deleted.
	sb, err = o.Store.GetSandbox(ctx, id)
	switch {
	case err == nil:
		return sb, false, true, nil
	case errors.Is(err, store.ErrNotFound):
		return nil, true, true, nil
	default:
		return nil, false, false, err
	}
}

// ResumeKeyedCreate finishes the provisioning of a sandbox an earlier attempt of the keyed
// create inserted and did not get to provision (it lost its client or its process between
// the insert and the pod). It goes through startPod, which provisions the volume under the
// tenant lock a Delete takes, as Create does. A sandbox past creating is returned as it is.
// After a failure the sandbox is returned only when it shows the outcome itself (the start
// began, or its failure is recorded, as Create reports a runtime failure); while it is still
// creating the error is returned, so the request is answered as failed and retried, never
// stored as a success that nothing provisioned.
func (o *Orchestrator) ResumeKeyedCreate(ctx context.Context, sb *model.Sandbox) (*model.Sandbox, error) {
	if sb.Status != model.StatusCreating {
		return sb, nil
	}
	o.remember(sb)
	started, err := o.startPod(ctx, sb.ID)
	if err == nil {
		return started, nil
	}
	cur, gerr := o.Store.GetSandbox(ctx, sb.ID)
	if gerr != nil || cur.Status == model.StatusCreating {
		return nil, err
	}
	return cur, nil
}
