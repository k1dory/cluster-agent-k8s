package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// A text-mode harness that reads stdin to its end before it starts, as `claude -p` does with a
// non-terminal stdin, must get EOF after the task: with the pipe left open the run never ended
// (seen on a live cluster, where kind's echo harness had hidden it).
func TestTextModeHarnessGetsEOFAfterTheTask(t *testing.T) {
	root := t.TempDir()
	got := filepath.Join(root, "stdin")
	t.Setenv("HOME", root)
	t.Setenv("PWD", root)
	t.Setenv("SANDBOX_REPO_DIR", root)
	t.Setenv("HARNESS_INPUT", "")
	t.Setenv("HARNESS_CMD", `cat > "`+got+`"; echo done`)
	// The control plane long-polls input: answer slowly with nothing, as an idle run does.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			select {
			case <-r.Context().Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	done := make(chan int, 1)
	go func() {
		done <- execute(ctx, &client{base: srv.URL, http: srv.Client()}, &model.Run{ID: "run_stdin", Task: "fixture task"})
	}()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("harness exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the harness never saw the end of stdin: the run would hang")
	}
	if b, err := os.ReadFile(got); err != nil || string(b) != "fixture task\n" {
		t.Fatalf("stdin of the harness: %q %v", b, err)
	}
}
