package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// Wiki item 3, the runner's side: every call about a run carries the attempt the run was handed
// out under, and an attempt the control plane says was handed out past (409) stops at once
// instead of running its harness to the end next to the attempt that replaced it.
func TestRound2RunnerSendsItsAttemptAndStopsWhenSuperseded(t *testing.T) {
	_, _, _ = setupACP(t, "")
	t.Setenv("HARNESS_INPUT", "")
	t.Setenv("ACP_FAKE_AGENT", "")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("HARNESS_CMD", "echo hello; sleep 30")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var mu sync.Mutex
	seen := map[string][]string{} // call → X-Run-Attempt values
	handed, finished := false, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		path := r.URL.Path
		if strings.HasPrefix(path, "/agent/runs/run_att/") {
			call := path[strings.LastIndex(path, "/")+1:]
			seen[call] = append(seen[call], r.Header.Get("X-Run-Attempt"))
		}
		switch {
		case strings.HasSuffix(path, "/runs/next"):
			if !handed {
				handed = true
				_ = json.NewEncoder(w).Encode(model.Run{ID: "run_att", Task: "x", Attempt: 3})
				return
			}
			if finished {
				cancel()
			}
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/input"):
			// The claim was handed out again meanwhile: this attempt is fenced off.
			http.Error(w, `{"error":"the run was handed out again since this attempt"}`, http.StatusConflict)
		case strings.HasSuffix(path, "/finish"):
			finished = true
			http.Error(w, `{"error":"stale attempt"}`, http.StatusConflict)
		case strings.HasSuffix(path, "/events"):
			_, _ = w.Write([]byte(`{"accepted":1,"skipped":0}`))
		default:
			_, _ = w.Write([]byte("[]"))
		}
	}))
	defer srv.Close()
	done := make(chan struct{})
	start := time.Now()
	go func() { serveRuns(ctx, &client{base: srv.URL, http: srv.Client()}); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the superseded attempt was not stopped")
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("the superseded attempt ran its harness to the end: %v", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen["input"]) == 0 || len(seen["finish"]) == 0 {
		t.Fatalf("calls about the run: %v", seen)
	}
	for call, vals := range seen {
		for _, v := range vals {
			if v != "3" {
				t.Fatalf("%s sent X-Run-Attempt %q, want 3 (all: %v)", call, v, seen)
			}
		}
	}
}
