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
func (o *Orchestrator) WakeForKeyedRun(ctx context.Context, run *model.Run) {
	if o.keyedRunWaits(ctx, run) {
		o.wakeForRun(ctx, run.SandboxID, run.ID)
	}
}

func (o *Orchestrator) keyedRunWaits(ctx context.Context, run *model.Run) bool {
	if run.Status != model.RunQueued {
		return false
	}
	sb, err := o.Store.GetSandbox(ctx, run.SandboxID)
	return err == nil && (sb.Status == model.StatusSleeping || sb.Status == model.StatusError)
}

// A keyed message's delivery is recorded under its seed, so every attempt of the request
// delivers it once: as input to a run in progress, joined to a queued task, or as a new run.
// The record is written under Say's sandbox lock right after the delivery, and checked under it
// before one; a new run is found by its keyed id as well, should the record be missing.
const saidPrefix = "idempotency-said/"

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
	b, err := o.Store.GetBlob(ctx, saidPrefix+sandboxID+"/"+seed)
	switch {
	case err == nil:
		var rec saidRecord
		if err := json.Unmarshal(b, &rec); err != nil {
			return nil, "", false, false, err
		}
		if run, err = o.Store.GetRun(ctx, rec.Run); err != nil {
			return nil, "", false, false, err
		}
		how = rec.How
	case errors.Is(err, store.ErrNotFound):
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
	default:
		return nil, "", false, false, err
	}
	return run, how, o.keyedRunWaits(ctx, run), true, nil
}

// recordSaid records a keyed message's delivery. On a context of its own: the delivery has
// happened, and a client that hangs up now must not leave its retry to deliver it again.
func (o *Orchestrator) recordSaid(ctx context.Context, sandboxID string, run *model.Run, how string) {
	seed := keyedSeed(ctx)
	if seed == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	b, _ := json.Marshal(saidRecord{Run: run.ID, How: how})
	if err := o.Store.PutBlob(ctx, saidPrefix+sandboxID+"/"+seed, b); err != nil {
		o.Log.Warn("record keyed message delivery", "sandbox", sandboxID, "run", run.ID, "err", err)
	}
	// A record outlives its key by nothing: past IdempotencyTTL no attempt can ask for it.
	_, _ = o.Store.DeleteBlobsBefore(ctx, saidPrefix, time.Now().Add(-store.IdempotencyTTL))
}
