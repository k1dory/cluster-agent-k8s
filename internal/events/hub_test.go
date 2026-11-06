package events

import (
	"testing"

	"agent-sandbox/internal/model"
)

func drain(ch <-chan model.Event) []model.Event {
	var out []model.Event
	for {
		select {
		case e := <-ch:
			out = append(out, e)
		default:
			return out
		}
	}
}

func TestPublishReachesSandboxAndAllSubscribers(t *testing.T) {
	h := New()
	one, cancelOne := h.Subscribe("sb1")
	all, cancelAll := h.Subscribe(All)
	defer cancelAll()
	h.Publish(model.Event{SandboxID: "sb1", Type: model.EventRunOutput, Data: "a"})
	h.Publish(model.Event{SandboxID: "sb2", Type: model.EventRunOutput, Data: "b"})
	if got := drain(one); len(got) != 1 || got[0].Data != "a" {
		t.Fatalf("sandbox subscriber: %+v", got)
	}
	if got := drain(all); len(got) != 2 {
		t.Fatalf("all subscriber: %+v", got)
	}
	cancelOne()
	h.Publish(model.Event{SandboxID: "sb1", Type: model.EventRunOutput})
	if got := drain(one); len(got) != 0 {
		t.Fatalf("delivered after cancel: %+v", got)
	}
	if _, ok := h.subs["sb1"]; ok {
		t.Fatal("empty subscriber set kept after the last cancel")
	}
}

// A full buffer drops events rather than block Publish; a typed subscription keeps its buffer
// for the types it asked for, so a burst of output cannot push out the answer it waits for.
func TestTypedSubscriptionSurvivesAnOutputBurst(t *testing.T) {
	h := New()
	plain, cancelPlain := h.Subscribe("sb")
	defer cancelPlain()
	typed, cancelTyped := h.SubscribeTypes("sb", model.EventFSResult)
	defer cancelTyped()
	for range 500 {
		h.Publish(model.Event{SandboxID: "sb", Type: model.EventRunOutput, Data: "line"})
	}
	h.Publish(model.Event{SandboxID: "sb", Type: model.EventFSResult, Data: "answer"})
	got := drain(plain)
	if len(got) != 64 {
		t.Fatalf("plain subscriber buffered %d events, want the 64 that fit", len(got))
	}
	for _, e := range got {
		if e.Type == model.EventFSResult {
			t.Fatal("the answer fit in a buffer full of output")
		}
	}
	if got := drain(typed); len(got) != 1 || got[0].Data != "answer" {
		t.Fatalf("typed subscriber: %+v", got)
	}
}
