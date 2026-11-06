package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
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
