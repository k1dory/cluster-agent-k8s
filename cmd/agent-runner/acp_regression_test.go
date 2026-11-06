package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	acp "github.com/coder/acp-go-sdk"
)

// A queued follow-up must keep input polling alive for the entire next turn.
// The third message arrives after the previous turn's idle deadline. Channels
// control the ordering; advancing an already-running idle clock avoids a sleep.
func TestACPQueuedPromptKeepsInputOpen(t *testing.T) {
	t.Setenv("SANDBOX_INSTRUCTIONS", "")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	chat := newChat(harness.InputACP, time.Minute)
	secondQueued := make(chan struct{})
	secondStarted := make(chan struct{})
	inputDone := make(chan struct{})
	thirdDelivered := make(chan struct{})
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++ // forwardInput makes one request at a time
		var events []model.Event
		switch requests {
		case 1:
			events = []model.Event{{ID: 1, Type: model.EventInput, Data: "second"}}
		case 2:
			// The preceding Send and chat.sent have both completed.
			close(secondQueued)
			select {
			case <-secondStarted:
			case <-r.Context().Done():
				return
			}
		case 3:
			events = []model.Event{{ID: 2, Type: model.EventInput, Data: "third"}, {ID: 3, Type: model.EventRunClose}}
			defer close(thirdDelivered)
		default:
			// After the close the runner still listens for a cancel: a long poll that ends with the run.
			<-r.Context().Done()
			return
		}
		_ = json.NewEncoder(w).Encode(events)
	}))
	defer srv.Close()
	c := &client{base: srv.URL, http: srv.Client()}
	var prompts []string
	conn := &scriptedACPConn{prompt: func(_ context.Context, p acp.PromptRequest) (acp.PromptResponse, error) {
		prompts = append(prompts, p.Prompt[0].Text.Text)
		switch len(prompts) {
		case 1:
			select {
			case <-secondQueued:
			case <-ctx.Done():
				return acp.PromptResponse{}, ctx.Err()
			}
		case 2:
			chat.mu.Lock()
			if !chat.turnEnd.IsZero() {
				chat.turnEnd = time.Now().Add(-2 * chat.idle)
			}
			chat.mu.Unlock()
			close(secondStarted)
			select {
			case <-thirdDelivered:
			case <-ctx.Done():
				return acp.PromptResponse{}, ctx.Err()
			}
		}
		return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
	}}
	emit := chat.sawLine
	code := driveACP(ctx, conn, &acpClient{emit: emit}, &model.Run{Task: "first"}, emit, chat, func(sink inputSink) {
		go func() {
			defer close(inputDone)
			forwardInput(ctx, c, "queued", sink, cancel, chat)
		}()
	})
	cancel()
	<-inputDone
	if code != 0 {
		t.Fatalf("run failed: exit %d", code)
	}
	if want := []string{"first", "second", "third"}; !reflect.DeepEqual(prompts, want) {
		t.Fatalf("input closed during the queued turn: prompts = %q, want %q", prompts, want)
	}
}

type scriptedACPConn struct {
	prompt func(context.Context, acp.PromptRequest) (acp.PromptResponse, error)
}

func (*scriptedACPConn) Initialize(context.Context, acp.InitializeRequest) (acp.InitializeResponse, error) {
	return acp.InitializeResponse{ProtocolVersion: acp.ProtocolVersionNumber}, nil
}
func (*scriptedACPConn) NewSession(context.Context, acp.NewSessionRequest) (acp.NewSessionResponse, error) {
	return acp.NewSessionResponse{SessionId: "regression"}, nil
}
func (*scriptedACPConn) LoadSession(context.Context, acp.LoadSessionRequest) (acp.LoadSessionResponse, error) {
	return acp.LoadSessionResponse{}, nil
}
func (c *scriptedACPConn) Prompt(ctx context.Context, p acp.PromptRequest) (acp.PromptResponse, error) {
	return c.prompt(ctx, p)
}
func (*scriptedACPConn) Cancel(context.Context, acp.CancelNotification) error { return nil }

// Exercise execute itself, including its output bridge. Contain a possible
// deadlock in a subprocess and kill its process group, including the ACP agent,
// on timeout so the test suite never inherits blocked goroutines or processes.
func TestACPOversizedDiffDoesNotHangRunner(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestACPOutputRegressionHelper$")
	cmd.Env = append(os.Environ(), "ACP_FAKE_AGENT=", "ACP_OUTPUT_HELPER=runner")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("runner hung after an ACP diff exceeding 1 MiB; neither later output nor run.close completed")
	}
	if err != nil {
		if len(output) > 4096 {
			output = output[len(output)-4096:]
		}
		t.Fatalf("runner subprocess: %v\n%s", err, output)
	}
}

func TestACPOutputRegressionHelper(t *testing.T) {
	switch os.Getenv("ACP_OUTPUT_HELPER") {
	case "agent":
		log, err := os.OpenFile(os.Getenv("ACP_FAKE_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			os.Exit(3)
		}
		f := &oversizedDiffAgent{fakeAgent: &fakeAgent{log: log}}
		c := acp.NewAgentSideConnection(f, os.Stdout, os.Stdin)
		f.connection.Store(c)
		<-c.Done()
		_ = log.Close()
		os.Exit(0) // no Go test footer on the ACP transport
	case "runner":
		_, cp, c := setupACP(t, "")
		t.Setenv("ACP_FAKE_AGENT", "")
		t.Setenv("ACP_OUTPUT_HELPER", "agent")
		t.Setenv("HARNESS_CMD", `exec "`+os.Args[0]+`" -test.run=^TestACPOutputRegressionHelper$`)
		if code := execute(t.Context(), c, &model.Run{ID: "large-diff", Task: "edit"}); code != 0 {
			t.Fatalf("runner exit %d", code)
		}
		cp.mu.Lock()
		defer cp.mu.Unlock()
		found := false
		for _, line := range cp.lines {
			role, text := harness.ParseMessage(line)
			found = found || role == "assistant" && text == "after-large-diff"
		}
		if !found || cp.turns() != 2 {
			t.Fatalf("output after oversized diff was lost: marker=%v, completed turns=%d", found, cp.turns())
		}
	default:
		t.Skip("subprocess helper")
	}
}

type oversizedDiffAgent struct{ *fakeAgent }

func (f *oversizedDiffAgent) Prompt(ctx context.Context, p acp.PromptRequest) (acp.PromptResponse, error) {
	for _, update := range []acp.SessionUpdate{
		acp.StartToolCall("large", "Edit large.txt", acp.WithStartContent([]acp.ToolCallContent{
			acp.ToolDiffContent("large.txt", strings.Repeat("x", 1100*1024), "old"),
		})),
		acp.UpdateAgentMessageText("after-large-diff"),
	} {
		if err := f.conn().SessionUpdate(ctx, acp.SessionNotification{SessionId: p.SessionId, Update: update}); err != nil {
			return acp.PromptResponse{}, err
		}
	}
	return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
}
