package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// abortingStream: frame 5 (a bounded trace's id, `5:2`) on a 200 that is then reset, a 200
// that ends without a frame, another reset, then frame 6 on a stream that stays open. It
// records when every reconnect came and the Last-Event-ID it carried.
func abortingStream(t *testing.T, event, frame5, frame6 string) (*httptest.Server, func() ([]string, []time.Time)) {
	var mu sync.Mutex
	var resumes []string
	var at []time.Time
	conns := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		conns++
		n := conns
		if n > 1 {
			resumes = append(resumes, r.Header.Get("Last-Event-ID"))
			at = append(at, time.Now())
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		switch n {
		case 1:
			fmt.Fprintf(w, "id: 5:2\nevent: %s\ndata: %s\n\n", event, frame5)
			fl.Flush()
			panic(http.ErrAbortHandler) // the connection is reset mid-body
		case 2:
			fl.Flush() // a 200 that ends before any frame
		case 3:
			fmt.Fprint(w, "id: 6:2\nevent: ")
			fl.Flush()
			panic(http.ErrAbortHandler) // truncated inside a frame
		case 4:
			fmt.Fprintf(w, "id: 6:2\nevent: %s\ndata: %s\n\n", event, frame6)
			fl.Flush()
			<-r.Context().Done()
		default:
			fl.Flush()
			<-r.Context().Done()
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() ([]string, []time.Time) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), resumes...), append([]time.Time(nil), at...)
	}
}

// checkBackoff: every reconnect resumed from frame 5's own id, and the waits between the
// failed attempts grew (the old followers reconnected at once, or every second flat).
func checkBackoff(t *testing.T, resumes []string, at []time.Time) {
	t.Helper()
	if len(resumes) < 3 || fmt.Sprintf("%q", resumes[:3]) != `["5:2" "5:2" "5:2"]` {
		t.Fatalf("reconnects sent Last-Event-ID %q, want 5:2 each time until frame 6", resumes)
	}
	g1, g2 := at[1].Sub(at[0]), at[2].Sub(at[1])
	if g1 < followRetry || g2 < g1*3/2 {
		t.Fatalf("waits between reconnects %s, %s: no backoff (want ≥%s, then growing)", g1, g2, followRetry)
	}
}

func TestFollowBacksOffABrokenBodyRound2(t *testing.T) {
	old := followRetry
	followRetry = 50 * time.Millisecond
	t.Cleanup(func() { followRetry = old })
	srv, seen := abortingStream(t, "status", `{"id":5,"sandbox_id":"sb","type":"status"}`, `{"id":6,"sandbox_id":"sb","type":"status"}`)
	c := &cli{base: srv.URL, token: "t", http: srv.Client()}
	done := make(chan error, 1)
	go func() {
		done <- c.follow("/v1/trace?stream=true", false, func(e model.Event) bool { return e.ID == 6 })
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		r, _ := seen()
		t.Fatalf("frame 6 never arrived; reconnects %q", r)
	}
	r, at := seen()
	checkBackoff(t, r, at)
}

func TestFollowMessagesBacksOffABrokenBodyRound2(t *testing.T) {
	old := followRetry
	followRetry = 50 * time.Millisecond
	t.Cleanup(func() { followRetry = old })
	srv, seen := abortingStream(t, "assistant", `{"id":5,"role":"assistant","text":"hi"}`, `{"id":6,"role":"assistant","text":"again"}`)
	c := &cli{base: srv.URL, token: "t", http: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.followMessages(ctx, "sb", 0, false, newChatState()); close(done) }()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if r, _ := seen(); len(r) >= 3 {
			break
		}
	}
	time.Sleep(100 * time.Millisecond) // a reconnect at once would show up as a fourth
	cancel()
	<-done
	r, at := seen()
	checkBackoff(t, r, at)
}
