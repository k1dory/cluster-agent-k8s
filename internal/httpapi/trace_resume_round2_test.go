package httpapi

import (
	"context"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"
)

var rawFrameID = regexp.MustCompile(`(?m)^id: (\S+)$`)

// A bounded trace stream follows live past ?to; a reconnect used to capture a new head and
// re-apply the window up to it, so a live event persisted but not yet delivered when the
// connection broke (outside the window) was skipped for good. The frames carry the original
// boundary now and a resume keeps it.
func TestBoundedTraceResumeKeepsItsBoundaryRound2(t *testing.T) {
	s := newStack(t)
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	in := appendAt(t, s, t0, "inside")
	stream := func(lastEventID string) (*stallWriter, func()) {
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest("GET", "/v1/trace?"+windowQuery(t0).Encode(), nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer t0k")
		if lastEventID != "" {
			req.Header.Set("Last-Event-ID", lastEventID)
		}
		w := newStallWriter()
		done := make(chan struct{})
		go func() { defer close(done); s.p.Routes().ServeHTTP(w, req) }()
		return w, func() { cancel(); <-done }
	}
	w, stop := stream("")
	waitBody(t, w, in)
	live := appendAt(t, s, t0.Add(time.Hour), "live, outside the window")
	waitBody(t, w, live)
	stop() // the connection breaks
	ids := rawFrameID.FindAllStringSubmatch(w.String(), -1)
	last := ids[len(ids)-1][1]
	missed := appendAt(t, s, t0.Add(2*time.Hour), "persisted while disconnected, outside the window")

	w2, stop2 := stream(last)
	defer stop2()
	got := waitBodyFor(t, w2, missed, 3*time.Second)
	if len(got) != 1 || got[0] != missed {
		t.Fatalf("the resume from %q: frames %v, want [%d]", last, got, missed)
	}
}

// A bounded trace with no matching history used to give its client no cursor at all (the
// boundary travelled only with events): after a disconnect the resume captured a new head,
// the window excluded an event committed meanwhile outside ?to, and it was skipped for good.
// The stream opens with a checkpoint frame carrying the boundary now.
func TestEmptyBoundedTraceResumeKeepsItsBoundaryRound2(t *testing.T) {
	s := newStack(t)
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	appendAt(t, s, t0.Add(-time.Hour), "before the window: no matching history")
	open := func(lastEventID string) (*stallWriter, func()) {
		ctx, cancel := context.WithCancel(context.Background())
		req := httptest.NewRequest("GET", "/v1/trace?"+windowQuery(t0).Encode(), nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer t0k")
		if lastEventID != "" {
			req.Header.Set("Last-Event-ID", lastEventID)
		}
		w := newStallWriter()
		done := make(chan struct{})
		go func() { defer close(done); s.p.Routes().ServeHTTP(w, req) }()
		return w, func() { cancel(); <-done }
	}
	w, stop := open("")
	var last string
	for deadline := time.Now().Add(3 * time.Second); last == "" && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if ids := rawFrameID.FindAllStringSubmatch(w.String(), -1); len(ids) > 0 {
			last = ids[len(ids)-1][1]
		}
	}
	stop()
	if last == "" || len(frameIDs(w.String())) != 0 {
		t.Fatalf("an empty bounded stream: %q (want a checkpoint frame and no event)", w.String())
	}
	missed := appendAt(t, s, t0.Add(time.Hour), "committed while disconnected, outside the window")
	w2, stop2 := open(last)
	defer stop2()
	if got := waitBodyFor(t, w2, missed, 3*time.Second); len(got) != 1 || got[0] != missed {
		t.Fatalf("the resume from %q: frames %v, want [%d]", last, got, missed)
	}
}
