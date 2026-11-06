package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"agent-sandbox/internal/events"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// hookedHead is the memory store with hooks on the head read and the log reads of a trace
// stream; it is an EventHead like both real stores.
type hookedHead struct {
	store.Store
	head  func(ctx context.Context) (int64, error)
	query func()
}

func (h *hookedHead) LastEventID(ctx context.Context) (int64, error) { return h.head(ctx) }

func (h *hookedHead) QueryEvents(ctx context.Context, f store.Filter) ([]*model.Event, error) {
	if h.query != nil {
		h.query()
	}
	return h.Store.QueryEvents(ctx, f)
}

var _ store.EventHead = (*hookedHead)(nil)

func windowQuery(t0 time.Time) url.Values {
	return url.Values{"stream": {"true"}, "sandbox": {"sbw"}, "type": {"input"},
		"from": {t0.Add(-10 * time.Minute).Format(time.RFC3339)}, "to": {t0.Add(10 * time.Minute).Format(time.RFC3339)}}
}

func appendAt(t *testing.T, s *stack, at time.Time, data string) int64 {
	t.Helper()
	e := model.Event{SandboxID: "sbw", Tenant: "alice", Slug: "backend-dev", Type: model.EventInput, Data: data, At: at}
	if err := s.orch.Store.AppendEvent(context.Background(), &e); err != nil {
		t.Fatal(err)
	}
	s.p.Hub.Publish(e)
	return e.ID
}

// An event appended once the trace stream is subscribed is live, whatever its time. The head
// used to be read after the subscription: an event appended in between became part of the
// head, the window excluded it from the replay and the cursor moved past it. The event is
// appended here at the first moment the hub has the stream's subscription, from whichever
// read of the store comes first after it. Two are appended: H+1 outside the window, then
// H+2 inside it (times and ids disagree across replicas). A replay that was not bounded to
// the head sent H+2 and moved its cursor past H+1 for good.
func TestTraceStreamKeepsAnEventAppendedWhileItStartsRound2(t *testing.T) {
	s := newStack(t)
	mem := s.orch.Store
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	in := appendAt(t, s, t0, "inside")
	var once sync.Once
	var outside, raced atomic.Int64
	inject := func() {
		if s.p.Hub.Waiting(events.All) > 0 {
			once.Do(func() {
				outside.Store(appendAt(t, s, t0.Add(time.Hour), "appended while the stream starts, outside the window"))
				raced.Store(appendAt(t, s, t0.Add(time.Minute), "appended while the stream starts, inside the window"))
			})
		}
	}
	s.orch.Store = &hookedHead{Store: mem, query: inject, head: func(ctx context.Context) (int64, error) {
		inject()
		return mem.(store.EventHead).LastEventID(ctx)
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("GET", "/v1/trace?"+windowQuery(t0).Encode(), nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer t0k")
	w := newStallWriter()
	done := make(chan struct{})
	go func() { defer close(done); s.p.Routes().ServeHTTP(w, req) }()
	waitBody(t, w, in)
	deadline := time.Now().Add(5 * time.Second)
	for raced.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if raced.Load() == 0 {
		t.Fatal("the stream never subscribed")
	}
	got := waitBodyFor(t, w, raced.Load(), 3*time.Second)
	cancel()
	<-done
	if want := fmt.Sprint([]int64{in, outside.Load(), raced.Load()}); fmt.Sprint(got) != want {
		t.Fatalf("frames %v, want %s (both appended after the subscription are live)", got, want)
	}
}

// waitBodyFor is waitBody with its own deadline, reporting instead of hanging.
func waitBodyFor(t *testing.T, w *stallWriter, last int64, d time.Duration) []int64 {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		ids := frameIDs(w.String())
		if len(ids) > 0 && ids[len(ids)-1] >= last {
			return ids
		}
		if time.Now().After(deadline) {
			t.Fatalf("frames %v: event %d never arrived", ids, last)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A failed head read used to answer 500 before the stream began, which sandboxctl takes as
// final: a store outage lasting through one reconnect stopped the watcher. It is the stream's
// error frame now, and the reconnect from the same cursor resumes with exactly the rest.
func TestTraceHeadFailureIsAnErrorFrameRound2(t *testing.T) {
	s := newStack(t)
	mem := s.orch.Store
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	first := appendAt(t, s, t0, "seen before the outage")
	second := appendAt(t, s, t0.Add(time.Minute), "after the cursor")
	appendAt(t, s, t0.Add(time.Hour), "outside the window")
	var down atomic.Bool // read by the handler: atomic, so a stream outliving its request cannot race the flip
	down.Store(true)
	s.orch.Store = &hookedHead{Store: mem, head: func(ctx context.Context) (int64, error) {
		if down.Load() {
			return 0, errors.New("connection reset")
		}
		return mem.(store.EventHead).LastEventID(ctx)
	}}
	get := func() (int, string) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest("GET", "/v1/trace?"+windowQuery(t0).Encode(), nil).WithContext(ctx)
		req.Header.Set("Authorization", "Bearer t0k")
		req.Header.Set("Last-Event-ID", strconv.FormatInt(first, 10))
		rec := httptest.NewRecorder()
		s.p.Routes().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	code, body := get()
	if code != 200 || !strings.Contains(body, "event: error\n") || len(frameIDs(body)) != 0 {
		t.Fatalf("a failed head read: %d %q", code, body)
	}
	down.Store(false)
	code, body = get()
	if ids := frameIDs(body); code != 200 || len(ids) != 1 || ids[0] != second {
		t.Fatalf("the reconnect from %d: %d %v %q", first, code, ids, body)
	}
}
