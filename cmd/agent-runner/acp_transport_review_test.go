package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
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
