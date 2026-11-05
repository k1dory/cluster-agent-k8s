package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// smallSpool shrinks the spool's bounds for a test.
func smallSpool(t *testing.T, maxBytes, maxLines, reserveBytes, reserveLines int) {
	t.Helper()
	b, l, rb, rl := spoolMaxBytes, spoolMaxLines, spoolReserveBytes, spoolReserveLines
	spoolMaxBytes, spoolMaxLines, spoolReserveBytes, spoolReserveLines = maxBytes, maxLines, reserveBytes, reserveLines
	t.Cleanup(func() { spoolMaxBytes, spoolMaxLines, spoolReserveBytes, spoolReserveLines = b, l, rb, rl })
}

// While the control plane stalls the spool stays within its bounds: ordinary stream-json
// messages (every one carries session_id) and blank lines are dropped like any other output
// past them; turn ends and usage go into the bounded reserve, and past it are dropped too.
func TestSpoolStaysBoundedUnderSaturation(t *testing.T) {
	smallSpool(t, 10_000, 100, 2_000, 10)
	stall := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-stall:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(stall)
	s := newOutputSpool(t.Context(), &client{base: srv.URL, http: srv.Client()}, "run_saturated")
	defer s.stop()
	bounded := func(what string) {
		t.Helper()
		s.mu.Lock()
		defer s.mu.Unlock()
		// The bounds, the reserve and the drop notices (one per drop announced, none here: no
		// line fitted after the first drop).
		if s.bytes > spoolMaxBytes+spoolReserveBytes || len(s.lines) > spoolMaxLines+spoolReserveLines+1 {
			t.Fatalf("%s: the spool holds %d lines, %d bytes", what, len(s.lines), s.bytes)
		}
	}
	for i := range 10_000 {
		s.add(fmt.Sprintf(`{"type":"assistant","session_id":"sess_1","message":{"content":[{"type":"text","text":"message %d"}]}}`, i))
	}
	bounded("session-bearing messages")
	for range 100_000 {
		s.add("")
	}
	bounded("blank lines")
	result := `{"type":"result","session_id":"sess_1","usage":{"input_tokens":1,"output_tokens":1}}`
	for range 1_000 {
		s.add(result)
	}
	bounded("turn ends")
	s.mu.Lock()
	kept := strings.Count(strings.Join(s.lines, "\n"), `"type":"result"`)
	s.mu.Unlock()
	if kept == 0 {
		t.Fatal("no turn end was kept in the reserve")
	}
}
