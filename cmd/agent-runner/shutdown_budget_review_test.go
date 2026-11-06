package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// shortShutdown scales the shutdown budget down for a test: the harness must end by 2.6 s after
// SIGTERM, its output is delivered until 3.4 s, the result until 4 s.
func shortShutdown(t *testing.T) {
	t.Helper()
	b, d, f := shutdownBudget, drainReserve, finishReserve
	shutdownBudget, drainReserve, finishReserve = 4*time.Second, 800*time.Millisecond, 600*time.Millisecond
	t.Cleanup(func() { shutdownBudget, drainReserve, finishReserve = b, d, f })
}

// What a harness says while it stops after SIGTERM is its result and is delivered, though it
// comes later than a fixed delivery grace from the signal would allow; a harness that does not
// stop is killed in time for its output and the result to go within the shutdown budget.
func TestOutputAfterSIGTERMIsDeliveredWithinTheBudget(t *testing.T) {
	for _, tc := range []struct {
		name, onInt, want string
	}{
		{"stops slowly", `sleep 1.6; echo final-result; exit 0`, "final-result"},
		{"never stops", `echo still-here`, "still-here"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shortShutdown(t)
			_, cp, c := setupACP(t, "")
			t.Setenv("HARNESS_INPUT", "")
			t.Setenv("ACP_FAKE_AGENT", "")
			t.Setenv("SANDBOX_MCP_SERVERS", "")
			t.Setenv("HARNESS_CMD", `trap '`+tc.onInt+`' INT; trap '' TERM; echo ready; while :; do sleep 0.05; done`)
			ctx, sigterm := context.WithCancel(t.Context())
			go func() {
				for ctx.Err() == nil {
					cp.mu.Lock()
					ready := strings.Contains(strings.Join(cp.lines, "\n"), "ready")
					cp.mu.Unlock()
					if ready {
						sigterm()
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			}()
			exit := execute(ctx, c, &model.Run{ID: "run_shutdown", Task: "x"})
			settled := c.finish(ctx, "run_shutdown", exit)
			stopped := shutdownDeadline(ctx, shutdownBudget) // the signal's time
			if d := time.Since(stopped); d > shutdownBudget+500*time.Millisecond || !settled {
				t.Fatalf("the way out took %s (budget %s), result settled %v", d, shutdownBudget, settled)
			}
			cp.mu.Lock()
			out := strings.Join(cp.lines, "\n")
			cp.mu.Unlock()
			if !strings.Contains(out, tc.want) {
				t.Fatalf("the output while stopping was lost:\n%s", out)
			}
		})
	}
}
