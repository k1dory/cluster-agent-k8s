package httpapi

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// A trace stream with ?to used to replay the window and only then follow live past it; the
// first round of this PR cleared ?to before the replay, so a historical window also streamed
// every persisted event after it. The replay keeps the window again; what is appended after
// the stream subscribed is live and still delivered.
func TestTraceStreamReplayKeepsTheWindowRound2(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	add := func(at time.Time, data string) int64 {
		e := model.Event{SandboxID: "sbw", Tenant: "alice", Slug: "backend-dev", Type: model.EventInput, Data: data, At: at}
		if err := s.orch.Store.AppendEvent(ctx, &e); err != nil {
			t.Fatal(err)
		}
		s.p.Hub.Publish(e)
		return e.ID
	}
	add(t0.Add(-time.Hour), "before")
	in := add(t0, "inside")
	beyond := add(t0.Add(time.Hour), "after the window")

	q := url.Values{"stream": {"true"}, "sandbox": {"sbw"}, "type": {"input"},
		"from": {t0.Add(-10 * time.Minute).Format(time.RFC3339)}, "to": {t0.Add(10 * time.Minute).Format(time.RFC3339)}}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req := httptest.NewRequest("GET", "/v1/trace?"+q.Encode(), nil).WithContext(sctx)
	req.Header.Set("Authorization", "Bearer t0k")
	w := newStallWriter()
	done := make(chan struct{})
	go func() { defer close(done); s.p.Routes().ServeHTTP(w, req) }()
	waitBody(t, w, in)
	time.Sleep(50 * time.Millisecond) // the replay has had its chance to run past the window
	live := add(t0.Add(2*time.Hour), "live")
	got := waitBody(t, w, live)
	cancel()
	<-done
	if fmt.Sprint(got) != fmt.Sprint([]int64{in, live}) {
		t.Fatalf("frames %v, want [%d %d] (the persisted event %d is outside the window)", got, in, live, beyond)
	}
}
