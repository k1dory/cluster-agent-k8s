package main

import (
	"context"
	"strings"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/model"
)

// silentConn is a scripted agent that never answers the calls it is told to hang on.
type silentConn struct {
	*coreConn
	hangInit, hangLoad, hangPrompt bool
}

func (c *silentConn) Initialize(ctx context.Context, p acp.InitializeRequest) (acp.InitializeResponse, error) {
	if c.hangInit {
		<-ctx.Done()
		return acp.InitializeResponse{}, ctx.Err()
	}
	return c.coreConn.Initialize(ctx, p)
}

func (c *silentConn) LoadSession(ctx context.Context, p acp.LoadSessionRequest) (acp.LoadSessionResponse, error) {
	if c.hangLoad {
		c.call("load")
		<-ctx.Done()
		return acp.LoadSessionResponse{}, ctx.Err()
	}
	return c.coreConn.LoadSession(ctx, p)
}

func (c *silentConn) Prompt(ctx context.Context, p acp.PromptRequest) (acp.PromptResponse, error) {
	if c.hangPrompt {
		c.call("prompt")
		<-ctx.Done()
		return acp.PromptResponse{}, ctx.Err()
	}
	return c.coreConn.Prompt(ctx, p)
}

// driveWithin runs a conversation and fails the test if it outlives limit.
func driveWithin(t *testing.T, limit time.Duration, conn acpConn, run *model.Run) (int, []string) {
	t.Helper()
	type result struct {
		code  int
		lines []string
	}
	done := make(chan result, 1)
	go func() {
		code, lines := runCore(t, conn, nil, run)
		done <- result{code, lines}
	}()
	select {
	case r := <-done:
		return r.code, r.lines
	case <-time.After(limit):
		t.Fatalf("the conversation was still waiting on the agent after %s", limit)
		return 0, nil
	}
}

// An agent that never answers initialize ends the run after HARNESS_ACP_SETUP_TIMEOUT, saying so;
// a load that never answers leaves session/new its own deadline, and the conversation goes on.
func TestACPSetupCallsHaveADeadline(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("HARNESS_ACP_SETUP_TIMEOUT", "1")
	code, lines := driveWithin(t, 5*time.Second, &silentConn{coreConn: &coreConn{}, hangInit: true}, &model.Run{ID: "r", Task: "x"})
	if code != 1 || !strings.Contains(notices(lines), "acp initialize: no answer within 1s (HARNESS_ACP_SETUP_TIMEOUT)") {
		t.Fatalf("exit %d, notices:\n%s", code, notices(lines))
	}

	conn := &silentConn{coreConn: &coreConn{init: acp.InitializeResponse{AgentCapabilities: acp.AgentCapabilities{LoadSession: true}}}, hangLoad: true}
	code, lines = driveWithin(t, 5*time.Second, conn, &model.Run{ID: "r2", Task: "x", ResumeOf: "r1", Session: "sess_old", Mode: model.RunMessage})
	if code != 0 || !hasCall(conn.coreConn, "load") || !hasCall(conn.coreConn, "new") ||
		!strings.Contains(notices(lines), "session/load sess_old: no answer within 1s") {
		t.Fatalf("exit %d, calls %v, notices:\n%s", code, conn.calls, notices(lines))
	}
}

// A turn that runs past HARNESS_TURN_TIMEOUT is cancelled, and so is the run, with a notice.
func TestACPTurnHasAMaximum(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("HARNESS_TURN_TIMEOUT", "1")
	code, lines := driveWithin(t, 5*time.Second, &silentConn{coreConn: &coreConn{}, hangPrompt: true}, &model.Run{ID: "r", Task: "x"})
	if code != 1 || !strings.Contains(notices(lines), "the turn ran longer than 1s (HARNESS_TURN_TIMEOUT): the run is cancelled") {
		t.Fatalf("exit %d, notices:\n%s", code, notices(lines))
	}
}

// slowConfigConn answers each configuration change after delay, or fails it when its context
// ends first.
type slowConfigConn struct {
	*coreConn
	delay time.Duration
}

func (c *slowConfigConn) SetSessionConfigOption(ctx context.Context, p acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error) {
	select {
	case <-time.After(c.delay):
	case <-ctx.Done():
		return acp.SetSessionConfigOptionResponse{}, ctx.Err()
	}
	return c.coreConn.SetSessionConfigOption(ctx, p)
}

// Each setting has its own setup deadline: two that each answer in time are applied though
// together they take longer than one deadline.
func TestACPEachSettingHasItsOwnDeadline(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("HARNESS_ACP_SETUP_TIMEOUT", "1")
	t.Setenv("HARNESS_MODE", "plan")
	t.Setenv("SANDBOX_MODEL", "fast")
	conn := &slowConfigConn{delay: 700 * time.Millisecond, coreConn: &coreConn{newRes: acp.NewSessionResponse{ConfigOptions: []acp.SessionConfigOption{
		selectOption("mode", acp.SessionConfigOptionCategoryMode, "default", "default", "plan"),
		selectOption("model", acp.SessionConfigOptionCategoryModel, "slow", "slow", "fast")}}}}
	code, lines := runCore(t, conn, nil, &model.Run{ID: "r", Task: "x"})
	if code != 0 || !hasCall(conn.coreConn, "set_config mode=plan") || !hasCall(conn.coreConn, "set_config model=fast") || notices(lines) != "" {
		t.Fatalf("exit %d, calls %v, notices:\n%s", code, conn.calls, notices(lines))
	}
}
