package httpapi

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// stallWriter is a streaming ResponseWriter whose Write blocks until released: a client that
// stopped reading (its TCP window full) without disconnecting.
type stallWriter struct {
	hdr  http.Header
	mu   sync.Mutex
	gate chan struct{} // closed: writes go through
	buf  bytes.Buffer
}

func newStallWriter() *stallWriter {
	w := &stallWriter{hdr: http.Header{}, gate: make(chan struct{})}
	close(w.gate)
	return w
}

func (s *stallWriter) stall() {
	s.mu.Lock()
	s.gate = make(chan struct{})
	s.mu.Unlock()
}

func (s *stallWriter) release() {
	s.mu.Lock()
	close(s.gate)
	s.mu.Unlock()
}

func (s *stallWriter) Header() http.Header { return s.hdr }
func (s *stallWriter) WriteHeader(int)     {}
func (s *stallWriter) Flush()              {}
func (s *stallWriter) Write(b []byte) (int, error) {
	s.mu.Lock()
	g := s.gate
	s.mu.Unlock()
	<-g
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(b)
}
func (s *stallWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

var frameID = regexp.MustCompile(`(?m)^id: (\d+)(?::\d+)?$`)

// checkpointFrame is a bounded trace's cursor-only frame: no event, not counted.
var checkpointFrame = regexp.MustCompile(`(?m)^id: \S+\nevent: checkpoint\n\n`)

func frameIDs(body string) []int64 {
	var out []int64
	for _, m := range frameID.FindAllStringSubmatch(checkpointFrame.ReplaceAllString(body, ""), -1) {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		out = append(out, n)
	}
	return out
}

// appendInputs appends n input events to a sandbox's log and publishes them, the way the
// orchestrator emits: what a stream must deliver, every one, in order.
func appendInputs(t *testing.T, s *stack, sb model.Sandbox, n int) []int64 {
	t.Helper()
	var ids []int64
	for i := 0; i < n; i++ {
		e := model.Event{SandboxID: sb.ID, Tenant: sb.Owner, Slug: sb.Slug, Type: model.EventInput, Data: "m" + strconv.Itoa(i)}
		if err := s.orch.Store.AppendEvent(context.Background(), &e); err != nil {
			t.Fatal(err)
		}
		s.p.Hub.Publish(e)
		ids = append(ids, e.ID)
	}
	return ids
}

func streamSandbox(t *testing.T, s *stack) model.Sandbox {
	t.Helper()
	resp, body := call(t, "POST", s.platform.URL+"/v1/sandboxes", "t0k", map[string]any{"name": "sse", "slug": "backend-dev", "owner": "alice"}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	var sb model.Sandbox
	mustJSON(t, body, &sb)
	return sb
}

// only checks that frames come in strictly increasing id order and keeps those in want (the
// sandbox's own lifecycle events may interleave).
func only(t *testing.T, got, want []int64) []int64 {
	t.Helper()
	in := map[int64]bool{}
	for _, id := range want {
		in[id] = true
	}
	var out []int64
	for i, id := range got {
		if i > 0 && id <= got[i-1] {
			t.Fatalf("frame %d: id %d after %d, out of order", i, id, got[i-1])
		}
		if in[id] {
			out = append(out, id)
		}
	}
	return out
}

func waitBody(t *testing.T, w *stallWriter, last int64) []int64 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		ids := frameIDs(w.String())
		if len(ids) > 0 && ids[len(ids)-1] >= last {
			return ids
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream stopped at %v, want up to %d", ids, last)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A stream whose client stalls past the hub's 64-slot buffer used to drop the overflow: the
// client then stored a later id and a reconnect never returned the gap. Every stream now
// reads the durable log from the last frame sent, so the stall only delays frames.
func TestStreamsSurviveAStalledClientRound2(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"events", "/v1/sandboxes/%s/events"},
		{"messages", "/v1/sandboxes/%s/messages/stream"},
		{"trace", "/v1/trace?stream=true&sandbox=%s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t)
			sb := streamSandbox(t, s)
			before := appendInputs(t, s, sb, 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest("GET", strings.Replace(tc.path, "%s", sb.ID, 1), nil).WithContext(ctx)
			req.Header.Set("Authorization", "Bearer t0k")
			req.Header.Set("Last-Event-ID", strconv.FormatInt(before[0]-1, 10))
			w := newStallWriter()
			done := make(chan struct{})
			go func() { defer close(done); s.p.Routes().ServeHTTP(w, req) }()
			waitBody(t, w, before[0]) // replay done: the stream now follows live
			w.stall()
			want := append(before, appendInputs(t, s, sb, 1)...)
			time.Sleep(50 * time.Millisecond) // the handler is blocked writing that frame
			want = append(want, appendInputs(t, s, sb, 300)...)
			w.release()
			got := only(t, waitBody(t, w, want[len(want)-1]), want)
			if len(got) != len(want) {
				t.Fatalf("got %d of %d frames (every event, the stall only delays them)", len(got), len(want))
			}
			cancel()
			<-done

			// A reconnect from a frame in the middle returns exactly the rest.
			mid := want[len(want)/2]
			ctx2, cancel2 := context.WithCancel(context.Background())
			defer cancel2()
			req2 := httptest.NewRequest("GET", strings.Replace(tc.path, "%s", sb.ID, 1), nil).WithContext(ctx2)
			req2.Header.Set("Authorization", "Bearer t0k")
			req2.Header.Set("Last-Event-ID", strconv.FormatInt(mid, 10))
			w2 := newStallWriter()
			done2 := make(chan struct{})
			go func() { defer close(done2); s.p.Routes().ServeHTTP(w2, req2) }()
			got2 := only(t, waitBody(t, w2, want[len(want)-1]), want)
			if rest := want[len(want)/2+1:]; len(got2) != len(rest) || got2[0] != rest[0] {
				t.Fatalf("resume after %d: %d frames starting %d, want %d from %d", mid, len(got2), got2[0], len(rest), rest[0])
			}
			cancel2()
			<-done2
		})
	}
}

// failingEvents fails every event read after the first n: the log becomes unreadable mid-stream.
type failingEvents struct {
	store.Store
	mu sync.Mutex
	n  int
}

func (f *failingEvents) QueryEvents(ctx context.Context, q store.Filter) ([]*model.Event, error) {
	f.mu.Lock()
	f.n--
	n := f.n
	f.mu.Unlock()
	if n < 0 {
		return nil, errors.New("connection refused")
	}
	return f.Store.QueryEvents(ctx, q)
}

// A failed read of the log used to end the replay silently and leave the client waiting on
// live frames only; it now ends the stream with an error frame, so the client reconnects.
func TestStreamEndsWithAnErrorFrameWhenTheLogFailsRound2(t *testing.T) {
	s := newStack(t)
	sb := streamSandbox(t, s)
	s.orch.Store = &failingEvents{Store: s.orch.Store, n: 0}
	req := httptest.NewRequest("GET", "/v1/sandboxes/"+sb.ID+"/events", nil)
	req.Header.Set("Authorization", "Bearer t0k")
	w := newStallWriter()
	done := make(chan struct{})
	go func() { defer close(done); s.p.Routes().ServeHTTP(w, req) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream kept running on an unreadable log")
	}
	if body := w.String(); !strings.Contains(body, "event: error") || strings.Contains(body, "connection refused") {
		t.Fatalf("body %q: want an error frame without the internal error", body)
	}
}
