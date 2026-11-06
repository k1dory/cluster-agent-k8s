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

// outageStream: frame 5 and the error frame, then two connections answered 503 before any
// stream (the database still down: the sandbox lookup or the token check fails), then frame 6
// and the end of that response. It records the Last-Event-ID of every reconnect.
func outageStream(t *testing.T, event, frame5, frame6 string) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var resumes []string
	conns := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		conns++
		n := conns
		if n > 1 {
			resumes = append(resumes, r.Header.Get("Last-Event-ID"))
		}
		mu.Unlock()
		switch {
		case n == 1:
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "id: 5\nevent: %s\ndata: %s\n\n", event, frame5)
			fmt.Fprint(w, "event: error\ndata: {\"code\":\"internal\",\"error\":\"reading the event log failed\"}\n\n")
		case n <= 3:
			http.Error(w, `{"error":"the database is unavailable","code":"internal"}`, http.StatusServiceUnavailable)
		case n == 4:
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "id: 6\nevent: %s\ndata: %s\n\n", event, frame6)
		default:
			w.Header().Set("Content-Type", "text/event-stream")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), resumes...)
	}
}

// Both followers used to stop at the first non-200 answer: a database outage that outlasted
// the error frame's reconnect (a 500/503 from the sandbox lookup or the token check, before
// any stream) ended the watcher. A 5xx is retried with the same cursor now.
func TestFollowRetriesAnOutageWithTheCursorRound2(t *testing.T) {
	fastRetry(t)
	srv, resumes := outageStream(t, "status", `{"id":5,"sandbox_id":"sb","type":"status","data":"running"}`,
		`{"id":6,"sandbox_id":"sb","type":"status","data":"sleeping"}`)
	c := &cli{base: srv.URL, token: "t", http: srv.Client()}
	done := make(chan error, 1)
	go func() {
		done <- c.follow("/v1/sandboxes/sb/events", false, func(e model.Event) bool { return e.ID == 6 })
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("follow ended on the outage: %v (reconnects %q)", err, resumes())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("frame 6 never arrived; reconnects %q", resumes())
	}
	if r := fmt.Sprintf("%q", resumes()); r != `["5" "5" "5"]` {
		t.Fatalf("reconnects sent Last-Event-ID %s, want 5 every time", r)
	}
}

func TestFollowMessagesRetriesAnOutageWithTheCursorRound2(t *testing.T) {
	fastRetry(t)
	srv, resumes := outageStream(t, "assistant", `{"id":5,"role":"assistant","text":"hi"}`, `{"id":6,"role":"assistant","text":"again"}`)
	c := &cli{base: srv.URL, token: "t", http: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.followMessages(ctx, "sb", 0, false, newChatState()); close(done) }()
	// The reconnect after frame 6 carries 6: the frame was delivered.
	for deadline := time.Now().Add(10 * time.Second); len(resumes()) < 4 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if r := fmt.Sprintf("%q", resumes()); r != `["5" "5" "5" "6"]` {
		t.Fatalf("reconnects sent Last-Event-ID %s, want 5, 5, 5 and then 6", r)
	}
}
