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

// erroringStream serves a valid frame (id 5) and then sandboxd's error frame on the first
// connection, and records the Last-Event-ID of every later one, answering it with frame 6.
func erroringStream(t *testing.T, event, frame5, frame6 string) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var resumes []string
	conns := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		mu.Lock()
		conns++
		n := conns
		if n > 1 {
			resumes = append(resumes, r.Header.Get("Last-Event-ID"))
		}
		mu.Unlock()
		if n == 1 {
			fmt.Fprintf(w, "id: 5\nevent: %s\ndata: %s\n\n", event, frame5)
			fmt.Fprint(w, ": keepalive\n\n")
			fmt.Fprint(w, "event: error\ndata: {\"code\":\"internal\",\"request_id\":\"r1\",\"error\":\"reading the event log failed; reconnect with Last-Event-ID to resume\"}\n\n")
			return
		}
		fmt.Fprintf(w, "id: 6\nevent: %s\ndata: %s\n\n", event, frame6)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), resumes...)
	}
}

func fastRetry(t *testing.T) {
	old := followRetry
	followRetry = 10 * time.Millisecond
	t.Cleanup(func() { followRetry = old })
}

// The error frame sandboxd ends a stream with used to decode as an event with id 0: the cursor
// went back to 0 and the reconnect replayed the whole history. The cursor stays on the last
// real frame now.
func TestFollowKeepsTheCursorOverAnErrorFrameRound2(t *testing.T) {
	fastRetry(t)
	srv, resumes := erroringStream(t, "status", `{"id":5,"sandbox_id":"sb","type":"status","data":"running"}`,
		`{"id":6,"sandbox_id":"sb","type":"status","data":"sleeping"}`)
	c := &cli{base: srv.URL, token: "t", http: srv.Client()}
	var seen []int64
	done := make(chan error, 1)
	go func() {
		done <- c.follow("/v1/sandboxes/sb/events", false, func(e model.Event) bool {
			seen = append(seen, e.ID)
			return e.ID == 6
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("follow never got frame 6; resumes %v", resumes())
	}
	if r := resumes(); len(r) != 1 || r[0] != "5" {
		t.Fatalf("reconnects sent Last-Event-ID %q, want [\"5\"]", r)
	}
	if fmt.Sprint(seen) != "[5 6]" {
		t.Fatalf("events %v", seen)
	}
}

func TestFollowMessagesKeepsTheCursorOverAnErrorFrameRound2(t *testing.T) {
	fastRetry(t)
	srv, resumes := erroringStream(t, "assistant", `{"id":5,"role":"assistant","text":"hi"}`, `{"id":6,"role":"assistant","text":"again"}`)
	c := &cli{base: srv.URL, token: "t", http: srv.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.followMessages(ctx, "sb", 0, false, newChatState()); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for len(resumes()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if r := resumes(); len(r) == 0 || r[0] != "5" {
		t.Fatalf("reconnects sent Last-Event-ID %q, want \"5\" first", r)
	}
}
