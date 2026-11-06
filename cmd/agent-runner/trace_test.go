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

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"agent-sandbox/internal/model"
)

// Every call the runner makes about a run carries the run's traceparent: one trace per run
// (events, input polls and finish of one run share it, the next run has its own), so the
// control plane's spans for the run join it. Calls that are about no run (the poll for the
// next one) carry none.
func TestRunnerSendsTheRunsTraceparent(t *testing.T) {
	_, _, _ = setupACP(t, "")
	t.Setenv("HARNESS_INPUT", "")
	t.Setenv("ACP_FAKE_AGENT", "")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("HARNESS_CMD", "echo hello")

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var mu sync.Mutex
	traces := map[string]map[trace.TraceID]bool{} // run → trace ids its calls carried
	var untraced, nextTraced int
	runs := []string{"run_trace_a", "run_trace_b"}
	finished := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		sc := trace.SpanContextFromContext(propagation.TraceContext{}.Extract(context.Background(), propagation.HeaderCarrier(r.Header)))
		path := r.URL.Path
		if rest, ok := strings.CutPrefix(path, "/agent/runs/"); ok && !strings.HasPrefix(rest, "next") {
			id, _, _ := strings.Cut(rest, "/")
			if !sc.IsValid() {
				untraced++
			} else {
				if traces[id] == nil {
					traces[id] = map[trace.TraceID]bool{}
				}
				traces[id][sc.TraceID()] = true
			}
		}
		switch {
		case strings.HasSuffix(path, "/runs/next"):
			if sc.IsValid() {
				nextTraced++
			}
			if len(runs) > 0 && finished == 2-len(runs) {
				_ = json.NewEncoder(w).Encode(model.Run{ID: runs[0], Task: "x"})
				runs = runs[1:]
				return
			}
			if finished == 2 {
				cancel()
			}
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(path, "/finish"):
			finished++
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(path, "/events"):
			_, _ = w.Write([]byte(`{"accepted":1,"skipped":0}`))
		case strings.HasSuffix(path, "/input"):
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = w.Write([]byte("[]"))
		}
	}))
	defer srv.Close()
	done := make(chan struct{})
	c := &client{base: srv.URL, http: srv.Client()}
	go func() { serveRuns(ctx, c); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the runs did not finish")
	}
	mu.Lock()
	defer mu.Unlock()
	if untraced != 0 || nextTraced != 0 {
		t.Fatalf("calls about a run without a traceparent: %d; polls for the next run with one: %d", untraced, nextTraced)
	}
	a, b := traces["run_trace_a"], traces["run_trace_b"]
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("one trace per run: a %v, b %v", a, b)
	}
	for id := range a {
		if b[id] {
			t.Fatal("two runs share a trace")
		}
	}
	if _, ok := c.traces.Load("run_trace_a"); ok {
		t.Fatal("a finished run's trace is kept")
	}
}
