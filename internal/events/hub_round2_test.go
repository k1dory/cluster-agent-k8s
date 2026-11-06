package events

import (
	"testing"

	"agent-sandbox/internal/model"
)

// Wake coalesces a burst into one pending signal and never blocks Publish: the reader goes to
// the durable log, so one wake-up covers however many events came meanwhile.
func TestWakeCoalescesAndFiltersRound2(t *testing.T) {
	h := New()
	wake, cancel := h.Wake("sb1", model.EventInput)
	defer cancel()
	for i := 0; i < 1000; i++ {
		h.Publish(model.Event{SandboxID: "sb1", Type: model.EventInput})
	}
	select {
	case <-wake:
	default:
		t.Fatal("no wake-up after a burst")
	}
	select {
	case <-wake:
		t.Fatal("a burst left more than one wake-up")
	default:
	}
	h.Publish(model.Event{SandboxID: "sb1", Type: model.EventRunOutput})
	h.Publish(model.Event{SandboxID: "sb2", Type: model.EventInput})
	select {
	case <-wake:
		t.Fatal("woken by an event of another type or sandbox")
	default:
	}
	all, cancelAll := h.Wake(All)
	defer cancelAll()
	h.Publish(model.Event{SandboxID: "sb9", Type: model.EventStatus})
	select {
	case <-all:
	default:
		t.Fatal("All was not woken")
	}
	cancel()
	cancelAll()
	if len(h.wakes) != 0 {
		t.Fatalf("cancel left %d wake keys", len(h.wakes))
	}
}
