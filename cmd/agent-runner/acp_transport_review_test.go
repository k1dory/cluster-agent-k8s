package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// An agent that stops reading its input does not hold the run past its deadline: the prompt (a
// task larger than the pipe holds) blocks in the SDK's write, which no context bounds, and the
// runner ends the transport under it. (120 KiB: over a pipe's 64 KiB, under Linux's 128 KiB for
// one environment string, which carries the task too.)
func TestACPDeadlineEndsABlockedWrite(t *testing.T) {
	_, cp, c := setupACP(t, "")
	t.Setenv("ACP_FAKE_AGENT", "")
	t.Setenv("ACP_DEAF_HELPER", "agent")
	t.Setenv("HARNESS_CMD", `exec "`+os.Args[0]+`" -test.run=^TestACPDeafAgentHelper$`)
	t.Setenv("SANDBOX_INSTRUCTIONS", "")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("HARNESS_TURN_TIMEOUT", "1")
	old := abortGrace
	abortGrace = 300 * time.Millisecond
	defer func() { abortGrace = old }()
	done := make(chan int, 1)
	go func() {
		done <- execute(t.Context(), c, &model.Run{ID: "run_deaf", Task: strings.Repeat("x", 120<<10)})
	}()
	select {
	case code := <-done:
		cp.mu.Lock()
		out := notices(cp.lines)
		cp.mu.Unlock()
		if code != 1 || !strings.Contains(out, "HARNESS_TURN_TIMEOUT") {
			t.Fatalf("exit %d, notices:\n%s", code, out)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the run is stuck writing to an agent that does not read")
	}
}

// TestACPDeafAgentHelper is an ACP agent written by hand: it answers initialize and session/new,
// then never reads its input again.
func TestACPDeafAgentHelper(t *testing.T) {
	if os.Getenv("ACP_DEAF_HELPER") != "agent" {
		t.Skip("subprocess helper")
	}
	in := bufio.NewReader(os.Stdin)
	answer := func(id json.RawMessage, result string) {
		fmt.Fprintf(os.Stdout, `{"jsonrpc":"2.0","id":%s,"result":%s}`+"\n", id, result)
	}
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			os.Exit(0)
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(line, &m)
		switch m.Method {
		case "initialize":
			answer(m.ID, `{"protocolVersion":1,"agentCapabilities":{}}`)
		case "session/new":
			answer(m.ID, `{"sessionId":"sess_deaf"}`)
			time.Sleep(30 * time.Second) // deaf from here on
			os.Exit(0)
		}
	}
}

// A helper that left the agent's process group (setsid) and holds its stderr does not hold the
// run: the runner owns that pipe and stops waiting on it after the group's kill, instead of
// exec's copier waiting out WaitDelay (20 s) and, after SIGTERM, the whole shutdown budget.
func TestACPDetachedHelperHoldingStderrDoesNotHoldTheRun(t *testing.T) {
	_, _, c := setupACP(t, "")
	pidFile := filepath.Join(t.TempDir(), "helper.pid")
	t.Setenv("ACP_SETSID_PID", pidFile)
	t.Setenv("HARNESS_CMD", `ACP_FAKE_AGENT= ACP_SETSID_HELPER=1 "`+os.Args[0]+`" -test.run=^TestSetsidHelper$ </dev/null >/dev/null & exec "`+os.Args[0]+`"`)
	old := groupKillDelay
	groupKillDelay = 300 * time.Millisecond
	defer func() { groupKillDelay = old }()
	t.Cleanup(func() {
		if b, err := os.ReadFile(pidFile); err == nil {
			if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid > 0 {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})
	start := time.Now()
	if code := runACP(t, c, &model.Run{ID: "run_detached", Task: "x"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("the run took %s: it waited on a pipe a detached helper held", d)
	}
}

// TestSetsidHelper leaves its process group and session, keeps the stderr it was given, and
// sleeps (ACP_SETSID_HELPER).
func TestSetsidHelper(t *testing.T) {
	if os.Getenv("ACP_SETSID_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	_, _ = syscall.Setsid()
	_ = os.WriteFile(os.Getenv("ACP_SETSID_PID"), []byte(strconv.Itoa(os.Getpid())), 0o600)
	time.Sleep(60 * time.Second)
	os.Exit(0)
}
