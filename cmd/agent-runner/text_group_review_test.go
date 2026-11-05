package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// A text-mode harness is a process group like an ACP agent: a compound HARNESS_CMD that starts a
// child (here one holding the output pipe) leaves nothing running after the run, cancelled or
// not, and the run still ends. (Background jobs of a non-interactive shell ignore SIGINT: only
// the group's SIGTERM reaches this one.)
func TestTextHarnessProcessGroupEndsWithTheRun(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
		tail   string
	}{
		{"cancelled", true, `trap 'echo got-int; exit 0' INT; echo ready; while :; do sleep 0.05; done`},
		{"exits on its own", false, `echo ready`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cp, c := setupACP(t, "")
			t.Setenv("HARNESS_INPUT", "")
			t.Setenv("ACP_FAKE_AGENT", "")
			t.Setenv("SANDBOX_MCP_SERVERS", "")
			old := groupKillDelay
			groupKillDelay = 300 * time.Millisecond
			defer func() { groupKillDelay = old }()
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			t.Setenv("HARNESS_CMD", `sleep 300 & echo $! > "`+pidFile+`"; `+tc.tail)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				go func() {
					for ctx.Err() == nil {
						cp.mu.Lock()
						ready := strings.Contains(strings.Join(cp.lines, "\n"), "ready")
						cp.mu.Unlock()
						if ready {
							cancel()
							return
						}
						time.Sleep(20 * time.Millisecond)
					}
				}()
			}
			done := make(chan struct{})
			go func() { execute(ctx, c, &model.Run{ID: "run_group_text", Task: "x"}); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("the run did not end")
			}
			b, err := os.ReadFile(pidFile)
			if err != nil {
				t.Fatal(err)
			}
			pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			for i := 0; ; i++ {
				if syscall.Kill(pid, 0) != nil {
					return // gone
				}
				if i == 100 {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("the harness's child %d outlived the run", pid)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}
