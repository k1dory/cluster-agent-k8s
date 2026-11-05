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

// A result the control plane did not acknowledge within the budget stays pending: the runner
// takes no other run and goes on until the control plane is back and acknowledges it. (A run
// whose pod is healthy is settled by nothing else.)
func TestPendingFinishIsKeptUntilAcknowledged(t *testing.T) {
	_, _, _ = setupACP(t, "")
	t.Setenv("HARNESS_INPUT", "")
	t.Setenv("ACP_FAKE_AGENT", "")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("HARNESS_CMD", "echo done")
	old := finishBudget
	finishBudget = 300 * time.Millisecond
	defer func() { finishBudget = old }()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var mu sync.Mutex
	var log []string // "next", "finish 503", "finish ok"
	handed := false
	var down time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/runs/next"):
			log = append(log, "next")
			if !handed {
				handed = true
				_ = json.NewEncoder(w).Encode(model.Run{ID: "run_pending", Task: "x"})
				return
			}
			if strings.Contains(strings.Join(log, ","), "finish ok") {
				cancel() // acknowledged, and the runner is back to polling: the test is over
			}
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/finish"):
			if down.IsZero() {
				down = time.Now()
			}
			// Down for several budgets, then back.
			if time.Since(down) < 4*finishBudget+time.Second {
				log = append(log, "finish 503")
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			log = append(log, "finish ok")
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = w.Write([]byte("[]"))
		}
	}))
	defer srv.Close()
	done := make(chan struct{})
	go func() { serveRuns(ctx, &client{base: srv.URL, http: srv.Client()}); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the runner did not get the result acknowledged")
	}
	mu.Lock()
	defer mu.Unlock()
	got := strings.Join(log, ",")
	first, ok := strings.Index(got, "finish 503"), strings.Index(got, "finish ok")
	if first < 0 || ok < 0 || strings.Contains(got[first:ok], "next") {
		t.Fatalf("a new run was polled for while the result was pending, or it was never acknowledged: %s", got)
	}
}
