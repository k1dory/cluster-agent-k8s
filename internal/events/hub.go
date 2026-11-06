// Package events fans sandbox events out to live subscribers (SSE clients, long-polls).
package events

import (
	"sync"

	"agent-sandbox/internal/model"
)

// Hub is a per-sandbox broadcast channel set.
type Hub struct {
	mu    sync.Mutex
	subs  map[string]map[chan model.Event]filter
	wakes map[string]map[chan struct{}]filter
}

// filter is the set of event types a subscriber takes; nil takes every type.
type filter map[string]bool

// New returns an empty hub.
func New() *Hub {
	return &Hub{subs: map[string]map[chan model.Event]filter{}, wakes: map[string]map[chan struct{}]filter{}}
}

// All is the subscription key that receives every sandbox's events (tenant-wide traces).
const All = "*"

// Subscribe returns a channel receiving events for sandboxID (or All) and a cancel func.
func (h *Hub) Subscribe(sandboxID string) (<-chan model.Event, func()) {
	return h.subscribe(sandboxID, nil)
}

// SubscribeTypes is Subscribe restricted to the given event types, filtered before the buffer:
// a caller waiting for one answer (an fs.result) does not lose it to a burst of run output
// filling the channel, which Publish drops on rather than block.
func (h *Hub) SubscribeTypes(sandboxID string, types ...string) (<-chan model.Event, func()) {
	f := filter{}
	for _, t := range types {
		f[t] = true
	}
	return h.subscribe(sandboxID, f)
}

func (h *Hub) subscribe(sandboxID string, f filter) (<-chan model.Event, func()) {
	ch := make(chan model.Event, 64)
	h.mu.Lock()
	if h.subs[sandboxID] == nil {
		h.subs[sandboxID] = map[chan model.Event]filter{}
	}
	h.subs[sandboxID][ch] = f
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if m := h.subs[sandboxID]; m != nil {
			delete(m, ch)
			if len(m) == 0 {
				delete(h.subs, sandboxID)
			}
		}
		h.mu.Unlock()
	}
}

// Publish delivers e to current subscribers without blocking (slow clients drop events;
// they recover from the persisted log via ?after=).
func (h *Hub) Publish(e model.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, key := range [2]string{e.SandboxID, All} {
		for ch, f := range h.subs[key] {
			if f != nil && !f[e.Type] {
				continue
			}
			select {
			case ch <- e:
			default:
			}
		}
		for ch, f := range h.wakes[key] {
			if f != nil && !f[e.Type] {
				continue
			}
			select {
			case ch <- struct{}{}:
			default: // a wake-up is already pending: the reader will see this event too
			}
		}
	}
}

// Wake returns a channel signalled when an event for sandboxID (or All) of one of types
// (none: every type) is published, and a cancel func. It carries no events: a stream reads
// them from the durable log from its own cursor. Signals coalesce in a one-slot buffer, so a
// burst is one wake-up and none is lost however slow the reader is; Subscribe's buffer, by
// contrast, drops events on a stalled reader, and a stream that sent from it skipped them
// for good (the client's Last-Event-ID moved past the gap).
func (h *Hub) Wake(sandboxID string, types ...string) (<-chan struct{}, func()) {
	var f filter
	if len(types) > 0 {
		f = filter{}
		for _, t := range types {
			f[t] = true
		}
	}
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	if h.wakes[sandboxID] == nil {
		h.wakes[sandboxID] = map[chan struct{}]filter{}
	}
	h.wakes[sandboxID][ch] = f
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if m := h.wakes[sandboxID]; m != nil {
			delete(m, ch)
			if len(m) == 0 {
				delete(h.wakes, sandboxID)
			}
		}
		h.mu.Unlock()
	}
}

// Waiting is how many Wake subscriptions key has: streams following it right now.
func (h *Hub) Waiting(key string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.wakes[key])
}
