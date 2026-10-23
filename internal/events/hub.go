// Package events fans sandbox events out to live subscribers (SSE clients, long-polls).
package events

import (
	"sync"

	"agent-sandbox/internal/model"
)

// Hub is a per-sandbox broadcast channel set.
type Hub struct {
	mu   sync.Mutex
	subs map[string]map[chan model.Event]struct{}
}

// New returns an empty hub.
func New() *Hub { return &Hub{subs: map[string]map[chan model.Event]struct{}{}} }

// Subscribe returns a channel receiving events for sandboxID and a cancel func.
func (h *Hub) Subscribe(sandboxID string) (<-chan model.Event, func()) {
	ch := make(chan model.Event, 64)
	h.mu.Lock()
	if h.subs[sandboxID] == nil {
		h.subs[sandboxID] = map[chan model.Event]struct{}{}
	}
	h.subs[sandboxID][ch] = struct{}{}
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
	for ch := range h.subs[e.SandboxID] {
		select {
		case ch <- e:
		default:
		}
	}
}
