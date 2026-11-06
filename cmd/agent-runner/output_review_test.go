package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
)

// fastBackoff makes the output's retries quick for a test.
func fastBackoff(t *testing.T) {
	t.Helper()
	base, ceiling := postBackoffBase, postBackoffMax
	postBackoffBase, postBackoffMax = 20*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { postBackoffBase, postBackoffMax = base, ceiling })
}

// batchStore plays the control plane's /events: lines are stored per X-Batch-Id, and a retry of
// a batch skips the lines already stored, as the gateway does.
type batchStore struct {
	mu     sync.Mutex
	lines  []string
	stored map[string]int
}

func (b *batchStore) store(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stored == nil {
		b.stored = map[string]int{}
	}
	id := r.Header.Get("X-Batch-Id")
	in := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	b.lines = append(b.lines, in[min(b.stored[id], len(in)):]...)
	b.stored[id] = len(in)
}

// A control plane that refuses the output for longer than the old retries lasted (≈7 s) still
// receives every line, exactly once and in order: the sender retries for as long as the run is
// alive, under the same batch id. One batch is stored and its acknowledgement lost (a 500 after
// the write): its retry must not duplicate it.
func TestOutputSurvivesARefusingControlPlane(t *testing.T) {
	fastBackoff(t)
	const outage = 8 * time.Second
	var st batchStore
	start := time.Now()
	lostAck := false
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if time.Since(start) < outage {
			http.Error(w, "control plane restarting", http.StatusServiceUnavailable)
			return
		}
		st.store(r)
		mu.Lock()
		first := !lostAck
		lostAck = true
		mu.Unlock()
		if first {
			http.Error(w, "stored, then the answer was lost", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	var want []string
	var in strings.Builder
	for i := range 500 {
		l := fmt.Sprintf("line %03d", i)
		want = append(want, l)
		in.WriteString(l + "\n")
	}
	pr, pw := io.Pipe()
	go func() {
		// Half before the outage is noticed, half during it.
		half := len(in.String()) / 2
		_, _ = io.WriteString(pw, in.String()[:half])
		time.Sleep(time.Second)
		_, _ = io.WriteString(pw, in.String()[half:])
		_ = pw.Close()
	}()
	streamOutput(t.Context(), &client{base: srv.URL, http: srv.Client()}, "run_outage", pr, nil)
	st.mu.Lock()
	defer st.mu.Unlock()
	if strings.Join(st.lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("delivered %d lines, want %d exactly once in order; first: %q", len(st.lines), len(want), st.lines[:min(5, len(st.lines))])
	}
}

// A full spool drops lines with one notice and keeps the lines that carry the run's state.
func TestOutputSpoolDropsWithANoticeAndKeepsTheState(t *testing.T) {
	old := spoolMaxBytes
	spoolMaxBytes = 100
	defer func() { spoolMaxBytes = old }()
	release := make(chan struct{})
	var st batchStore
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		st.store(r)
	}))
	defer srv.Close()
	s := newOutputSpool(t.Context(), &client{base: srv.URL, http: srv.Client()}, "run_full")
	s.add(strings.Repeat("a", 60)) // taken by the sender, which then waits on the server
	time.Sleep(spoolBatchDelay + 200*time.Millisecond)
	s.add(strings.Repeat("b", 60))
	s.add(strings.Repeat("c", 60)) // over the limit: dropped
	s.add(strings.Repeat("d", 60)) // dropped
	turnEnd := harness.ACPLine{Type: harness.ACPTurnEnd, StopReason: "end_turn"}.String()
	s.add(turnEnd) // vital: kept although the spool is full
	close(release)
	s.close(5 * time.Second)
	got := strings.Join(st.lines, "\n")
	for _, w := range []string{strings.Repeat("a", 60), strings.Repeat("b", 60), turnEnd, "dropped 2 output line(s), 120 bytes"} {
		if !strings.Contains(got, w) {
			t.Fatalf("missing %q in\n%s", w, got)
		}
	}
	if strings.Contains(got, "ccc") || strings.Count(got, "dropped") != 1 {
		t.Fatalf("drops: %s", got)
	}
}

// An agent that sends thousands of notifications while the control plane stalls keeps its
// connection: the notifications are taken from the SDK's queue (1024 deep, overflow closes the
// connection) at once, whatever the network does, and all of them arrive once it answers.
func TestACPFloodDuringAStalledControlPlaneKeepsTheConnection(t *testing.T) {
	fastBackoff(t)
	_, cp, _ := setupACP(t, "")
	t.Setenv("ACP_FAKE_AGENT", "")
	t.Setenv("ACP_FLOOD_HELPER", "agent")
	t.Setenv("HARNESS_CMD", `exec "`+os.Args[0]+`" -test.run=^TestACPFloodHelper$`)
	t.Setenv("SANDBOX_INSTRUCTIONS", "")
	const stall = 3 * time.Second
	start := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/events") {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(stall - time.Since(start)):
			}
		}
		cp.ServeHTTP(w, r)
	}))
	defer srv.Close()
	c := &client{base: srv.URL, http: srv.Client()}
	if code := runACP(t, c, &model.Run{ID: "run_flood", Task: "flood"}); code != 0 {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		t.Fatalf("exit %d; last lines: %q", code, cp.lines[max(0, len(cp.lines)-5):])
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	calls := 0
	for _, l := range cp.lines {
		if strings.Contains(l, `"type":"acp.tool_call"`) {
			calls++
		}
	}
	if calls != 2*floodNotifications || cp.turns() != 2 {
		t.Fatalf("tool calls delivered %d, want %d; turns %d", calls, 2*floodNotifications, cp.turns())
	}
}

const floodNotifications = 3000

type floodAgent struct{ *fakeAgent }

// Prompt reports a verbose turn: a tool call every 0.1 ms or so, 3000 in well under the stall,
// which the client takes as fast as the SDK delivers them unless it waits on the network.
func (f *floodAgent) Prompt(ctx context.Context, p acp.PromptRequest) (acp.PromptResponse, error) {
	for i := range floodNotifications {
		if i%10 == 0 {
			time.Sleep(time.Millisecond)
		}
		u := acp.StartToolCall(acp.ToolCallId(fmt.Sprintf("call_%d", i)), "Read file", acp.WithStartKind(acp.ToolKindRead))
		if err := f.conn().SessionUpdate(ctx, acp.SessionNotification{SessionId: p.SessionId, Update: u}); err != nil {
			return acp.PromptResponse{}, err
		}
	}
	return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
}

func TestACPFloodHelper(t *testing.T) {
	if os.Getenv("ACP_FLOOD_HELPER") != "agent" {
		t.Skip("subprocess helper")
	}
	log, err := os.OpenFile(os.Getenv("ACP_FAKE_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(3)
	}
	f := &floodAgent{fakeAgent: &fakeAgent{log: log}}
	c := acp.NewAgentSideConnection(f, os.Stdout, os.Stdin)
	f.connection.Store(c)
	<-c.Done()
	os.Exit(0) // no Go test footer on the ACP transport
}
