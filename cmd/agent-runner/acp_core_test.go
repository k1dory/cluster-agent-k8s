package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	"github.com/k1dory/acpx"
)

// coreConn is a scripted ACP agent in process: it declares what a test gives it (modes,
// configuration options, resume, an agent name) and records every call the runner makes.
type coreConn struct {
	init   acp.InitializeResponse
	newRes acp.NewSessionResponse
	opened acpSessionState // returned by load and resume
	// loadErr, resumeErr fail those calls.
	loadErr, resumeErr error
	// prompt answers prompt n (0-based) with text; nil: end the turn with no usage.
	prompt func(n int, text string) (acp.PromptResponse, error)
	// onOpen runs inside load and resume, before they answer (a load replaying its history).
	onOpen func()
	// steer answers Steer; nil: the connection has no steering (the method still exists).
	steer func(text string) acpx.SteerOutcome
	// configAfter is the agent's options after any change (nil: it answers none).
	configAfter []acp.SessionConfigOption

	mu       sync.Mutex
	calls    []string
	prompts  []string
	blocks   [][]acp.ContentBlock
	newReq   *acp.NewSessionRequest
	loadReq  *acp.LoadSessionRequest
	resumReq *acp.ResumeSessionRequest
}

func (c *coreConn) call(s string) {
	c.mu.Lock()
	c.calls = append(c.calls, s)
	c.mu.Unlock()
}

func (c *coreConn) Initialize(context.Context, acp.InitializeRequest) (acp.InitializeResponse, error) {
	c.call("initialize")
	r := c.init
	r.ProtocolVersion = acp.ProtocolVersionNumber
	return r, nil
}

func (c *coreConn) NewSession(_ context.Context, p acp.NewSessionRequest) (acp.NewSessionResponse, error) {
	c.call("new")
	c.newReq = &p
	r := c.newRes
	if r.SessionId == "" {
		r.SessionId = "sess_new"
	}
	return r, nil
}

func (c *coreConn) LoadSession(_ context.Context, p acp.LoadSessionRequest) (acp.LoadSessionResponse, error) {
	c.call("load")
	c.loadReq = &p
	if c.onOpen != nil {
		c.onOpen()
	}
	return acp.LoadSessionResponse{Modes: c.opened.Modes, ConfigOptions: c.opened.Options}, c.loadErr
}

func (c *coreConn) ResumeSession(_ context.Context, p acp.ResumeSessionRequest) (acp.ResumeSessionResponse, error) {
	c.call("resume")
	c.resumReq = &p
	if c.onOpen != nil {
		c.onOpen()
	}
	return acp.ResumeSessionResponse{Modes: c.opened.Modes, ConfigOptions: c.opened.Options}, c.resumeErr
}

func (c *coreConn) SetSessionMode(_ context.Context, p acp.SetSessionModeRequest) (acp.SetSessionModeResponse, error) {
	c.call("set_mode " + string(p.ModeId))
	return acp.SetSessionModeResponse{}, nil
}

func (c *coreConn) SetSessionConfigOption(_ context.Context, p acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error) {
	c.call("set_config " + string(p.ValueId.ConfigId) + "=" + string(p.ValueId.Value))
	return acp.SetSessionConfigOptionResponse{ConfigOptions: c.configAfter}, nil
}

func (c *coreConn) Prompt(_ context.Context, p acp.PromptRequest) (acp.PromptResponse, error) {
	c.mu.Lock()
	n := len(c.prompts)
	text := p.Prompt[0].Text.Text
	c.prompts = append(c.prompts, text)
	c.blocks = append(c.blocks, p.Prompt)
	c.mu.Unlock()
	if c.prompt == nil {
		return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
	}
	return c.prompt(n, text)
}

func (c *coreConn) Cancel(context.Context, acp.CancelNotification) error { return nil }

func (c *coreConn) Steer(_ context.Context, _ acp.SessionId, text string) (acpx.SteerOutcome, error) {
	c.call("steer " + text)
	if c.steer == nil {
		return acpx.SteerPromptRequired, nil
	}
	return c.steer(text), nil
}

func (c *coreConn) CloseSession(_ context.Context, p acp.CloseSessionRequest) (acp.CloseSessionResponse, error) {
	c.call("close " + string(p.SessionId))
	return acp.CloseSessionResponse{}, nil
}

// runCore drives one conversation against conn: the task, then messages, then the end of input.
func runCore(t *testing.T, conn acpConn, cl *acpClient, run *model.Run, messages ...string) (code int, lines []string) {
	t.Helper()
	var mu sync.Mutex
	emit := func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }
	if cl == nil {
		cl = &acpClient{}
	}
	cl.emit = emit
	chat := newChat(harness.InputACP, chatIdle())
	code = driveACP(t.Context(), conn, cl, run, emit, chat, func(sink inputSink) {
		for _, m := range messages {
			_ = sink.Send(m)
		}
		_ = sink.Close()
	})
	return code, lines
}

func clearACPEnv(t *testing.T) {
	for _, k := range []string{"SANDBOX_INSTRUCTIONS", "SANDBOX_MCP_SERVERS", "SANDBOX_MODEL", "SANDBOX_RESUME_PROMPT",
		"HARNESS_MODE", "HARNESS_MCP", "HARNESS_AUTH_METHOD"} {
		t.Setenv(k, "")
	}
}

func category(c acp.SessionConfigOptionCategory) *acp.SessionConfigOptionCategory { return &c }

func selectOption(id string, cat acp.SessionConfigOptionCategory, current string, values ...string) acp.SessionConfigOption {
	opts := acp.SessionConfigSelectOptionsUngrouped{}
	for _, v := range values {
		opts = append(opts, acp.SessionConfigSelectOption{Value: acp.SessionConfigValueId(v), Name: v})
	}
	return acp.SessionConfigOption{Select: &acp.SessionConfigOptionSelect{Id: acp.SessionConfigId(id), Category: category(cat),
		CurrentValue: acp.SessionConfigValueId(current), Options: acp.SessionConfigSelectOptions{Ungrouped: &opts}, Type: "select"}}
}

func notices(lines []string) string {
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, "[agent-runner] ") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func hasCall(c *coreConn, call string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range c.calls {
		if x == call {
			return true
		}
	}
	return false
}

// harness.mode goes through the agent's configuration option of category mode when it has one
// (codex-acp declares both), else through session/set_mode (OpenCode); a mode the agent does not
// offer is reported with the ones it does, and the agent stays where it is.
func TestACPModeFromTheProfile(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("HARNESS_MODE", "agent-full-access")
	modes := &acp.SessionModeState{CurrentModeId: "agent", AvailableModes: []acp.SessionMode{{Id: "read-only"}, {Id: "agent"}, {Id: "agent-full-access"}}}

	both := &coreConn{newRes: acp.NewSessionResponse{Modes: modes,
		ConfigOptions: []acp.SessionConfigOption{selectOption("mode", acp.SessionConfigOptionCategoryMode, "agent", "read-only", "agent", "agent-full-access")}}}
	if code, _ := runCore(t, both, nil, &model.Run{Task: "go"}); code != 0 || !hasCall(both, "set_config mode=agent-full-access") || hasCall(both, "set_mode agent-full-access") {
		t.Fatalf("config option first: %v", both.calls)
	}

	onlyModes := &coreConn{newRes: acp.NewSessionResponse{Modes: modes}}
	if _, _ = runCore(t, onlyModes, nil, &model.Run{Task: "go"}); !hasCall(onlyModes, "set_mode agent-full-access") {
		t.Fatalf("session/set_mode: %v", onlyModes.calls)
	}
	// set_mode comes before the first prompt.
	if i := strings.Join(onlyModes.calls, ","); !strings.HasSuffix(i, "set_mode agent-full-access") || len(onlyModes.prompts) != 1 {
		t.Fatalf("order: %v", onlyModes.calls)
	}

	already := &coreConn{newRes: acp.NewSessionResponse{Modes: &acp.SessionModeState{CurrentModeId: "agent-full-access", AvailableModes: modes.AvailableModes}}}
	if _, _ = runCore(t, already, nil, &model.Run{Task: "go"}); hasCall(already, "set_mode agent-full-access") {
		t.Fatalf("the current mode is set again: %v", already.calls)
	}

	optAlready := &coreConn{newRes: acp.NewSessionResponse{ConfigOptions: []acp.SessionConfigOption{
		selectOption("mode", acp.SessionConfigOptionCategoryMode, "agent-full-access", "agent", "agent-full-access")}}}
	if _, _ = runCore(t, optAlready, nil, &model.Run{Task: "go"}); len(optAlready.calls) != 2 {
		t.Fatalf("the current mode option is set again: %v", optAlready.calls)
	}

	t.Setenv("HARNESS_MODE", "yolo")
	unknown := &coreConn{newRes: acp.NewSessionResponse{Modes: modes}}
	code, lines := runCore(t, unknown, nil, &model.Run{Task: "go"})
	if code != 0 || len(unknown.calls) != 2 || !strings.Contains(notices(lines), `harness.mode "yolo" is not a mode the agent offers [read-only agent agent-full-access]`) {
		t.Fatalf("unknown mode: exit %d calls %v\n%s", code, unknown.calls, notices(lines))
	}

	none := &coreConn{}
	if _, lines := runCore(t, none, nil, &model.Run{Task: "go"}); !strings.Contains(notices(lines), "declares no session modes") {
		t.Fatalf("no modes: %s", notices(lines))
	}
}

// The profile's model is selected through the agent's model option: the same value, a
// provider-qualified one, or an option named after it. An agent without one is told nothing
// and the run says so.
func TestACPModelFromTheProfile(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("SANDBOX_MODEL", "claude-sonnet-5-5")
	conn := &coreConn{newRes: acp.NewSessionResponse{ConfigOptions: []acp.SessionConfigOption{
		selectOption("model", acp.SessionConfigOptionCategoryModel, "anthropic/claude-opus-5-5", "anthropic/claude-opus-5-5", "anthropic/claude-sonnet-5-5")}}}
	if _, _ = runCore(t, conn, nil, &model.Run{Task: "go"}); !hasCall(conn, "set_config model=anthropic/claude-sonnet-5-5") {
		t.Fatalf("model: %v", conn.calls)
	}
	same := &coreConn{newRes: acp.NewSessionResponse{ConfigOptions: []acp.SessionConfigOption{
		selectOption("model", acp.SessionConfigOptionCategoryModel, "claude-sonnet-5-5", "claude-sonnet-5-5")}}}
	if _, _ = runCore(t, same, nil, &model.Run{Task: "go"}); len(same.calls) != 2 {
		t.Fatalf("the current model is set again: %v", same.calls)
	}
	other := &coreConn{newRes: acp.NewSessionResponse{ConfigOptions: []acp.SessionConfigOption{
		selectOption("model", acp.SessionConfigOptionCategoryModel, "gpt-6", "gpt-6")}}}
	if _, lines := runCore(t, other, nil, &model.Run{Task: "go"}); len(other.calls) != 2 || !strings.Contains(notices(lines), `model "claude-sonnet-5-5" is not one the agent offers [gpt-6]`) {
		t.Fatalf("unknown model: %v %s", other.calls, notices(lines))
	}
	if _, lines := runCore(t, &coreConn{}, nil, &model.Run{Task: "go"}); !strings.Contains(notices(lines), "offers no model option") {
		t.Fatalf("no model option: %s", notices(lines))
	}
}

// A run that continues a conversation resumes the session when the agent declares
// session/resume, loads it when it only loads, and starts a new one otherwise. The mode is
// applied to a continued session too: a new agent process starts in its default.
func TestACPContinuesTheSessionByResumeThenLoad(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("HARNESS_MODE", "build")
	run := &model.Run{Task: "next", Session: "sess_old", ResumeOf: "run_1", Mode: model.RunMessage}
	modes := &acp.SessionModeState{CurrentModeId: "plan", AvailableModes: []acp.SessionMode{{Id: "plan"}, {Id: "build"}}}
	both := acp.AgentCapabilities{LoadSession: true, SessionCapabilities: acp.SessionCapabilities{Resume: &acp.SessionResumeCapabilities{}}}

	resume := &coreConn{init: acp.InitializeResponse{AgentCapabilities: both}, opened: acpSessionState{Modes: modes}}
	_, lines := runCore(t, resume, nil, run)
	if want := []string{"initialize", "resume", "set_mode build"}; !reflect.DeepEqual(resume.calls, want) || resume.prompts[0] != "next" {
		t.Fatalf("resume: %v %q", resume.calls, resume.prompts)
	}
	if !strings.Contains(lines[0], `"session_id":"sess_old"`) {
		t.Fatalf("session line: %s", lines[0])
	}

	failed := &coreConn{init: acp.InitializeResponse{AgentCapabilities: both}, resumeErr: errors.New("gone")}
	if _, _ = runCore(t, failed, nil, run); !reflect.DeepEqual(failed.calls[:3], []string{"initialize", "resume", "load"}) {
		t.Fatalf("resume failed → load: %v", failed.calls)
	}

	load := &coreConn{init: acp.InitializeResponse{AgentCapabilities: acp.AgentCapabilities{LoadSession: true}}}
	if _, _ = runCore(t, load, nil, run); !reflect.DeepEqual(load.calls, []string{"initialize", "load"}) {
		t.Fatalf("load: %v", load.calls)
	}

	neither := &coreConn{}
	_, lines = runCore(t, neither, nil, run)
	if !reflect.DeepEqual(neither.calls, []string{"initialize", "new"}) || !strings.Contains(notices(lines), "cannot continue session sess_old") {
		t.Fatalf("new: %v %s", neither.calls, notices(lines))
	}
}

// An agent that takes the client's system prompt gets the instructions as one (in session/new
// and again in a load, which does not keep them), and the task alone; one that does not gets
// them ahead of the first prompt of a new session, as before.
func TestACPInstructionsAsTheSystemPrompt(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("SANDBOX_INSTRUCTIONS", "Be brief.")
	native := &coreConn{init: acp.InitializeResponse{AgentCapabilities: acp.AgentCapabilities{LoadSession: true}}}
	cl := &acpClient{systemPrompt: func() bool { return true }}
	runCore(t, native, cl, &model.Run{Task: "go"})
	if native.newReq.Meta[acpx.SystemPromptMetaKey] != "Be brief." || native.prompts[0] != "go" {
		t.Fatalf("system prompt: meta %v prompt %q", native.newReq.Meta, native.prompts[0])
	}
	runCore(t, native, cl, &model.Run{Task: "more", Session: "sess_new", ResumeOf: "r", Mode: model.RunMessage})
	if native.loadReq == nil || native.loadReq.Meta[acpx.SystemPromptMetaKey] != "Be brief." {
		t.Fatalf("load keeps the system prompt: %+v", native.loadReq)
	}

	prefixed := &coreConn{}
	runCore(t, prefixed, &acpClient{systemPrompt: func() bool { return false }}, &model.Run{Task: "go"})
	if prefixed.newReq.Meta != nil || !strings.HasPrefix(prefixed.prompts[0], "<instructions>\nBe brief.\n</instructions>") {
		t.Fatalf("prefix: meta %v prompt %q", prefixed.newReq.Meta, prefixed.prompts[0])
	}
}

// The diff of a change OpenCode and Hermes send only with the permission request is recorded
// there; the call's later lines leave the same diff out and mark a different one as replacing
// it (Claude's preview, then the real hunks). codex-acp's kind of change is kept.
func TestACPDiffsFromPermissionAndReplacement(t *testing.T) {
	var lines []string
	cl := &acpClient{emit: func(l string) { lines = append(lines, l) }}
	ctx := context.Background()
	diff := []acp.ToolCallContent{acp.ToolDiffContent("/w/a.txt", "new", "old")}
	_, _ = cl.RequestPermission(ctx, acp.RequestPermissionRequest{SessionId: "s",
		ToolCall: acp.ToolCallUpdate{ToolCallId: "c1", Content: diff},
		Options:  []acp.PermissionOption{{OptionId: "y", Kind: acp.PermissionOptionKindAllowOnce}}})
	_ = cl.SessionUpdate(ctx, acp.SessionNotification{SessionId: "s", Update: acp.UpdateToolCall("c1",
		acp.WithUpdateStatus(acp.ToolCallStatusInProgress), acp.WithUpdateContent(diff))})
	real := []acp.ToolCallContent{acp.ToolDiffContent("/w/a.txt", "newer", "old")}
	_ = cl.SessionUpdate(ctx, acp.SessionNotification{SessionId: "s", Update: acp.UpdateToolCall("c1", acp.WithUpdateContent(real))})
	del := acp.ToolDiffContent("/w/gone.txt", "")
	del.Diff.Meta = map[string]any{"kind": "delete"}
	mv := acp.ToolDiffContent("/w/new.go", "")
	mv.Diff.Meta = map[string]any{"kind": "update", "diff_git_patch": map[string]any{"oldPath": "/w/old.go", "text": "…"}}
	_ = cl.SessionUpdate(ctx, acp.SessionNotification{SessionId: "s", Update: acp.StartToolCall("c2", "patch",
		acp.WithStartContent([]acp.ToolCallContent{del, mv}))})

	var got []harness.ACPLine
	for _, l := range lines {
		var v harness.ACPLine
		_ = json.Unmarshal([]byte(l), &v)
		got = append(got, v)
	}
	switch {
	case len(got) != 4:
		t.Fatalf("lines: %q", lines)
	case got[0].Type != harness.ACPPermission || len(got[0].Diffs) != 1 || got[0].Diffs[0].NewText != "new" || got[0].DiffsReplace:
		t.Fatalf("permission diff: %+v", got[0])
	case len(got[1].Diffs) != 0 || got[1].Status != "in_progress":
		t.Fatalf("same diff repeated: %+v", got[1])
	case len(got[2].Diffs) != 1 || got[2].Diffs[0].NewText != "newer" || !got[2].DiffsReplace:
		t.Fatalf("replacing diff: %+v", got[2])
	case got[3].Diffs[0].Change != "delete" || got[3].Diffs[1].Change != "rename" || got[3].Diffs[1].OldPath != "/w/old.go" || got[3].DiffsReplace:
		t.Fatalf("kinds: %+v", got[3].Diffs)
	}
}

// One usage record per turn: Hermes's running total becomes the turn's share (kept across
// runs on the workspace), a cumulative cost becomes what it grew by, and reasoning tokens are
// added only when the agent counts them beside the output.
func TestACPUsagePerTurn(t *testing.T) {
	clearACPEnv(t)
	dir := t.TempDir()
	usageOf := func(l string) model.Usage {
		u, mode, ok := harness.ParseUsage(l)
		if !ok || mode != harness.Increment {
			t.Fatalf("not a usage line: %s", l)
		}
		return u
	}
	usages := func(lines []string) (out []model.Usage) {
		for _, l := range lines {
			if strings.Contains(l, `"type":"usage"`) {
				out = append(out, usageOf(l))
			}
		}
		return out
	}
	cached := func(n int) *int { return &n }

	totals := []acp.Usage{{InputTokens: 100, OutputTokens: 10, TotalTokens: 110, CachedReadTokens: cached(50)},
		{InputTokens: 250, OutputTokens: 30, TotalTokens: 280, CachedReadTokens: cached(120)}}
	hermes := func() *coreConn {
		return &coreConn{init: acp.InitializeResponse{AgentInfo: &acp.Implementation{Name: "hermes-agent"},
			AgentCapabilities: acp.AgentCapabilities{LoadSession: true}},
			prompt: func(n int, _ string) (acp.PromptResponse, error) {
				u := totals[n%2]
				return acp.PromptResponse{StopReason: acp.StopReasonEndTurn, Usage: &u}, nil
			}}
	}
	_, lines := runCore(t, hermes(), &acpClient{usageDir: dir}, &model.Run{Task: "a"}, "b")
	got := usages(lines)
	if len(got) != 2 || got[0].InputTokens != 100 || got[1].InputTokens != 150 || got[1].OutputTokens != 20 || got[1].CacheRead != 70 {
		t.Fatalf("hermes deltas: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "sess_new.json")); err != nil {
		t.Fatalf("running total not kept: %v", err)
	}
	// The next run loads the session: its first turn counts from the kept total.
	next := hermes()
	next.prompt = func(int, string) (acp.PromptResponse, error) {
		u := acp.Usage{InputTokens: 300, OutputTokens: 35, TotalTokens: 335, CachedReadTokens: cached(150)}
		return acp.PromptResponse{StopReason: acp.StopReasonEndTurn, Usage: &u}, nil
	}
	_, lines = runCore(t, next, &acpClient{usageDir: dir}, &model.Run{Task: "c", Session: "sess_new", ResumeOf: "r", Mode: model.RunMessage})
	if got := usages(lines); len(got) != 1 || got[0].InputTokens != 50 || got[0].OutputTokens != 5 {
		t.Fatalf("after load: %+v", got)
	}

	// Cost: the session's total from usage_update, per turn its growth; a turn without token
	// usage but with cost still gets a record.
	var cl *acpClient
	costs := []float64{0.5, 0.8}
	claude := &coreConn{prompt: func(n int, _ string) (acp.PromptResponse, error) {
		_ = cl.SessionUpdate(context.Background(), acp.SessionNotification{SessionId: "s", Update: acp.SessionUpdate{
			UsageUpdate: &acp.SessionUsageUpdate{Cost: &acp.Cost{Amount: costs[n], Currency: "USD"}, Used: 1, Size: 2}}})
		if n == 1 {
			return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
		}
		return acp.PromptResponse{StopReason: acp.StopReasonEndTurn, Usage: &acp.Usage{InputTokens: 1, OutputTokens: 1, TotalTokens: 2}}, nil
	}}
	cl = &acpClient{}
	_, lines = runCore(t, claude, cl, &model.Run{Task: "a"}, "b")
	if got := usages(lines); len(got) != 2 || got[0].CostUSD != 0.5 || got[1].CostUSD < 0.2999 || got[1].CostUSD > 0.3001 || got[1].InputTokens != 0 {
		t.Fatalf("cost deltas: %+v", got)
	}

	// Reasoning: inside the output (total = input + output) stays; beside it is added.
	thought := func(total int) []model.Usage {
		th := 40
		c := &coreConn{prompt: func(int, string) (acp.PromptResponse, error) {
			return acp.PromptResponse{StopReason: acp.StopReasonEndTurn, Usage: &acp.Usage{InputTokens: 100, OutputTokens: 60, ThoughtTokens: &th, TotalTokens: total}}, nil
		}}
		_, lines := runCore(t, c, nil, &model.Run{Task: "a"})
		return usages(lines)
	}
	if got := thought(160); got[0].OutputTokens != 60 {
		t.Fatalf("thought inside the output counted twice: %+v", got)
	}
	if got := thought(200); got[0].OutputTokens != 100 {
		t.Fatalf("thought beside the output lost: %+v", got)
	}
}

// Hermes refuses a prompt while a lost turn waits (unknown_execution): the runner discards the
// turns the refusal names and sends the prompt once more. Any other error ends the run.
func TestACPDiscardsALostTurnAndRetries(t *testing.T) {
	clearACPEnv(t)
	refusal := acp.NewInternalError(map[string]any{"details": "unknown_execution: do not resend accepted input; a turn in this session was lost " +
		"when the gateway restarted and its outcome is unknown (nothing was submitted). Send `/discard adm_7` here (or `hermes sessions discard s` in a terminal), then continue."})
	conn := &coreConn{prompt: func(n int, _ string) (acp.PromptResponse, error) {
		if n == 0 {
			return acp.PromptResponse{}, refusal
		}
		return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
	}}
	code, lines := runCore(t, conn, nil, &model.Run{Task: "go on"})
	if want := []string{"go on", "/discard adm_7", "go on"}; code != 0 || !reflect.DeepEqual(conn.prompts, want) {
		t.Fatalf("exit %d prompts %q\n%s", code, conn.prompts, notices(lines))
	}
	// The retry is refused again: the run ends, no second round of discards.
	again := &coreConn{prompt: func(_ int, text string) (acp.PromptResponse, error) {
		if strings.HasPrefix(text, "/discard") {
			return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
		}
		return acp.PromptResponse{}, refusal
	}}
	if code, _ := runCore(t, again, nil, &model.Run{Task: "go on"}); code != 1 || len(again.prompts) != 3 {
		t.Fatalf("retried more than once: exit %d prompts %q", code, again.prompts)
	}
	// A discard the agent refuses ends the run too.
	stuck := &coreConn{prompt: func(int, string) (acp.PromptResponse, error) { return acp.PromptResponse{}, refusal }}
	if code, _ := runCore(t, stuck, nil, &model.Run{Task: "go on"}); code != 1 || len(stuck.prompts) != 2 {
		t.Fatalf("refused discard: exit %d prompts %q", code, stuck.prompts)
	}
	other := &coreConn{prompt: func(int, string) (acp.PromptResponse, error) { return acp.PromptResponse{}, errors.New("boom") }}
	if code, _ := runCore(t, other, nil, &model.Run{Task: "go on"}); code != 1 || len(other.prompts) != 1 {
		t.Fatalf("other error: exit %d prompts %q", code, other.prompts)
	}
	if ids := lostTurns("session_busy"); ids != nil {
		t.Fatalf("not a lost turn: %v", ids)
	}
}

// A message that starts with "/" reaches the agent as text, not as one of its commands.
func TestACPEscapesALeadingSlash(t *testing.T) {
	clearACPEnv(t)
	conn := &coreConn{}
	runCore(t, conn, nil, &model.Run{Task: "/review the PR"}, "  /compact", "fix a/b")
	want := []string{"​/review the PR", "​  /compact", "fix a/b"}
	if !reflect.DeepEqual(conn.prompts, want) {
		t.Fatalf("prompts: %q", conn.prompts)
	}
}

// harness.mcp: always passes the MCP servers to an agent that does not declare MCP over HTTP.
func TestACPMCPAlways(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("SANDBOX_MCP_SERVERS", `[{"name":"git","url":"https://mcp.example/git"}]`)
	auto := &coreConn{}
	_, lines := runCore(t, auto, nil, &model.Run{Task: "go"})
	if len(auto.newReq.McpServers) != 0 || !strings.Contains(notices(lines), "spec.harness.mcp: always") {
		t.Fatalf("auto: %+v %s", auto.newReq.McpServers, notices(lines))
	}
	t.Setenv("HARNESS_MCP", "always")
	always := &coreConn{}
	runCore(t, always, nil, &model.Run{Task: "go"})
	if len(always.newReq.McpServers) != 1 || always.newReq.McpServers[0].Http == nil {
		t.Fatalf("always: %+v", always.newReq.McpServers)
	}
}

// OpenCode reports an approved edit it already made through fs/write_text_file: the runner
// answers success and writes nothing.
func TestACPWriteTextFileIsAcknowledged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.txt")
	if _, err := (&acpClient{}).WriteTextFile(context.Background(), acp.WriteTextFileRequest{Path: path, Content: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the runner wrote the file: %v", err)
	}
}

// A cancelled run interrupts the harness before it terminates it: `claude -p` completes its turn
// on SIGINT; SIGTERM comes only to one still running after interruptGrace.
func TestCancelledHarnessIsInterruptedFirst(t *testing.T) {
	for _, tc := range []struct {
		name, onInt string
		want        string
	}{
		{"exits on SIGINT", "echo got-int; exit 0", "got-int"},
		{"ignores SIGINT", "echo ignored-int", "got-term"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cp, c := setupACP(t, "")
			t.Setenv("HARNESS_INPUT", "")
			t.Setenv("ACP_FAKE_AGENT", "")
			t.Setenv("SANDBOX_MCP_SERVERS", "")
			t.Setenv("HARNESS_CMD", `trap '`+tc.onInt+`' INT; trap 'echo got-term; exit 0' TERM; echo ready; while :; do sleep 0.05; done`)
			old := interruptGrace
			interruptGrace = 300 * time.Millisecond
			defer func() { interruptGrace = old }()
			ctx, cancel := context.WithCancel(t.Context())
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
			execute(ctx, c, &model.Run{ID: "run_cancel", Task: "x"})
			cancel()
			cp.mu.Lock()
			out := strings.Join(cp.lines, "\n")
			cp.mu.Unlock()
			if !strings.Contains(out, tc.want) || tc.want == "got-int" && strings.Contains(out, "got-term") {
				t.Fatalf("output:\n%s", out)
			}
		})
	}
}

// The session's cost is a running total that outlives the run: the run that continues the
// session (a new agent process) counts from the total the previous run ended on, kept on the
// workspace, or from what the agent reports while the session opens; a total that drops counts
// whole. (OpenCode after session/resume reported the whole session's cost as the first turn's.)
func TestACPCostAcrossRuns(t *testing.T) {
	clearACPEnv(t)
	dir := t.TempDir()
	costOf := func(lines []string) (out []float64) {
		for _, l := range lines {
			if u, _, ok := harness.ParseUsage(l); ok {
				out = append(out, u.CostUSD)
			}
		}
		return out
	}
	near := func(a, b float64) bool { return a-b < 1e-9 && b-a < 1e-9 }
	report := func(cl **acpClient, total float64) {
		_ = (*cl).SessionUpdate(context.Background(), acp.SessionNotification{SessionId: "s", Update: acp.SessionUpdate{
			UsageUpdate: &acp.SessionUsageUpdate{Cost: &acp.Cost{Amount: total, Currency: "USD"}}}})
	}
	caps := acp.InitializeResponse{AgentCapabilities: acp.AgentCapabilities{LoadSession: true,
		SessionCapabilities: acp.SessionCapabilities{Resume: &acp.SessionResumeCapabilities{}}}}
	agent := func(cl **acpClient, totals ...float64) *coreConn {
		return &coreConn{init: caps, prompt: func(n int, _ string) (acp.PromptResponse, error) {
			report(cl, totals[n])
			return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
		}}
	}
	next := &model.Run{Task: "again", Session: "sess_new", ResumeOf: "r", Mode: model.RunMessage}

	// Two turns, then a resumed run whose agent reports the session's total.
	var cl *acpClient
	cl = &acpClient{usageDir: dir}
	_, lines := runCore(t, agent(&cl, 0.00004, 0.00008), cl, &model.Run{Task: "a"}, "b")
	if got := costOf(lines); len(got) != 2 || !near(got[0], 0.00004) || !near(got[1], 0.00004) {
		t.Fatalf("first run: %v", got)
	}
	cl = &acpClient{usageDir: dir}
	_, lines = runCore(t, agent(&cl, 0.00012), cl, next)
	if got := costOf(lines); len(got) != 1 || !near(got[0], 0.00004) {
		t.Fatalf("resumed run charged the old cost again: %v", got)
	}

	// Nothing kept, but the load replays the session's cost: that is the base.
	cl = &acpClient{usageDir: t.TempDir()}
	loaded := agent(&cl, 0.7)
	loaded.init = acp.InitializeResponse{AgentCapabilities: acp.AgentCapabilities{LoadSession: true}}
	loaded.onOpen = func() { report(&cl, 0.5) }
	_, lines = runCore(t, loaded, cl, next)
	if got := costOf(lines); len(got) != 1 || !near(got[0], 0.2) {
		t.Fatalf("cost reported on load: %v", got)
	}

	// A total lower than the kept one: the agent counts from zero, the turn's cost is all of it.
	cl = &acpClient{usageDir: dir}
	_, lines = runCore(t, agent(&cl, 0.00001), cl, next)
	if got := costOf(lines); len(got) != 1 || !near(got[0], 0.00001) {
		t.Fatalf("reset: %v", got)
	}
}

// A message that arrives while a turn runs joins it when the agent takes steering; one the agent
// does not take (no turn after all, no steering) waits and is the next prompt.
func TestACPSteeringJoinsTheTurnInProgress(t *testing.T) {
	clearACPEnv(t)
	for _, tc := range []struct {
		name    string
		outcome acpx.SteerOutcome
		prompts []string
	}{
		{"injected", acpx.SteerInjected, []string{"task"}},
		{"not taken", acpx.SteerPromptRequired, []string{"task", "more"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sink inputSink
			steered := make(chan struct{})
			conn := &coreConn{steer: func(string) acpx.SteerOutcome { close(steered); return tc.outcome }}
			conn.prompt = func(n int, _ string) (acp.PromptResponse, error) {
				if n == 0 {
					_ = sink.Send("more") // arrives during the turn
					<-steered             // the turn lasts until the agent has answered the steering
				}
				return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
			}
			code, lines := runSteering(t, conn, &sink, len(tc.prompts))
			if code != 0 || !reflect.DeepEqual(conn.prompts, tc.prompts) || !hasCall(conn, "steer more") {
				t.Fatalf("exit %d prompts %q calls %v\n%s", code, conn.prompts, conn.calls, notices(lines))
			}
			// The notice names the message it took by its fingerprint (a client tells its turn
			// apart by it).
			if joined := strings.Contains(notices(lines), "joined the turn in progress (steering) [input sha256:"+inputFingerprint("more")+"]"); joined != (tc.outcome == acpx.SteerInjected) {
				t.Fatalf("steering notice for %q: %s", tc.name, notices(lines))
			}
		})
	}
}

// runSteering drives a conversation whose messages the test sends through sink; the input closes
// once want prompts have been sent.
func runSteering(t *testing.T, conn *coreConn, sink *inputSink, want int) (int, []string) {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	emit := func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }
	chat := newChat(harness.InputACP, chatIdle())
	code := driveACP(t.Context(), conn, &acpClient{emit: emit}, &model.Run{Task: "task"}, emit, chat, func(s inputSink) {
		*sink = s
		go func() {
			for {
				conn.mu.Lock()
				done := len(conn.prompts) >= want
				conn.mu.Unlock()
				if done {
					_ = s.Close()
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	})
	mu.Lock()
	defer mu.Unlock()
	return code, lines
}

// The input never waits on steering: an agent that does not answer cannot hold up a cancel or a
// close behind the message (the sender returns at once); messages keep their order, and the
// conversation ends only once the steered ones are placed.
func TestPromptQueueSteeringDoesNotBlockTheInput(t *testing.T) {
	q := newPromptQueue()
	release, started := make(chan struct{}), make(chan struct{})
	var steered []string
	var mu sync.Mutex
	q.steer = func(text string) bool {
		mu.Lock()
		steered = append(steered, text)
		mu.Unlock()
		close(started)
		<-release // a silent agent
		return false
	}
	q.setTurn(true)
	start := time.Now()
	for _, m := range []string{"a", "b", "c"} {
		if err := q.Send(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Close(); err != nil || time.Since(start) > time.Second {
		t.Fatalf("the input waited on steering: %v", time.Since(start))
	}
	<-started
	q.setTurn(false)
	got := make(chan []string)
	go func() {
		var out []string
		for {
			m, ok := q.next(context.Background())
			if !ok {
				got <- out
				return
			}
			out = append(out, m)
		}
	}()
	select {
	case <-got:
		t.Fatal("the conversation ended before the steered message was placed")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if out := <-got; !reflect.DeepEqual(out, []string{"a", "b", "c"}) {
		t.Fatalf("order: %q", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(steered, []string{"a"}) {
		t.Fatalf("after a message the agent did not take, the rest wait without steering: %q", steered)
	}
}

// A command the agent advertised is never steered: the agent runs commands from a prompt, steered
// text would only be text.
func TestACPSlashCommandsAreNotSteered(t *testing.T) {
	clearACPEnv(t)
	var sink inputSink
	var cl *acpClient
	conn := &coreConn{steer: func(string) acpx.SteerOutcome { return acpx.SteerInjected }}
	conn.prompt = func(n int, _ string) (acp.PromptResponse, error) {
		if n == 0 {
			_ = cl.SessionUpdate(context.Background(), acp.SessionNotification{SessionId: "sess_new", Update: acp.SessionUpdate{
				AvailableCommandsUpdate: &acp.SessionAvailableCommandsUpdate{SessionUpdate: "available_commands_update",
					AvailableCommands: []acp.AvailableCommand{{Name: "compact"}}}}})
			_ = sink.Send("/compact")
			// The turn lasts while the worker decides: steered, the command would be gone from
			// the prompts.
			time.Sleep(200 * time.Millisecond)
		}
		return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
	}
	emit := func(string) {}
	cl = &acpClient{emit: emit}
	chat := newChat(harness.InputACP, chatIdle())
	code := driveACP(t.Context(), conn, cl, &model.Run{Task: "task"}, emit, chat, func(s inputSink) {
		sink = s
		go func() {
			for {
				conn.mu.Lock()
				done := len(conn.prompts) >= 2
				conn.mu.Unlock()
				if done {
					_ = s.Close()
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	})
	if code != 0 || hasCall(conn, "steer /compact") || !reflect.DeepEqual(conn.prompts, []string{"task", "/compact"}) {
		t.Fatalf("exit %d prompts %q calls %v", code, conn.prompts, conn.calls)
	}
}

// The control plane's messages do not restart an ACP conversation's idle clock: driveACP owns it
// (a message joined to a turn that has ended since must not keep the conversation open forever).
func TestACPInputLeavesTheIdleClockToTheConversation(t *testing.T) {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls++
		var evs []model.Event
		switch polls {
		case 1:
			evs = []model.Event{{ID: 1, Type: model.EventInput, Data: "late"}, {ID: 2, Type: model.EventRunClose}}
		case 2:
			evs = []model.Event{{ID: 3, Type: model.EventRunCancel}}
		}
		_ = json.NewEncoder(w).Encode(evs)
	}))
	defer srv.Close()
	chat := newChat(harness.InputACP, time.Minute)
	chat.turnEnded()
	q := newPromptQueue()
	forwardInput(t.Context(), &client{base: srv.URL, http: srv.Client()}, "r", q, func() {}, chat)
	chat.mu.Lock()
	defer chat.mu.Unlock()
	if chat.turnEnd.IsZero() {
		t.Fatal("an input event reset the ACP conversation's idle clock")
	}
}

// One selection can change the agent's other options (codex-acp offers other reasoning levels
// for another model): the reasoning level goes by the options after the model was set.
func TestACPThoughtLevelFollowsTheModel(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("SANDBOX_MODEL", "big")
	t.Setenv("HARNESS_THOUGHT_LEVEL", "xhigh")
	conn := &coreConn{newRes: acp.NewSessionResponse{ConfigOptions: []acp.SessionConfigOption{
		selectOption("model", acp.SessionConfigOptionCategoryModel, "small", "small", "big"),
		selectOption("effort", acp.SessionConfigOptionCategoryThoughtLevel, "low", "low")}},
		configAfter: []acp.SessionConfigOption{
			selectOption("model", acp.SessionConfigOptionCategoryModel, "big", "small", "big"),
			selectOption("effort", acp.SessionConfigOptionCategoryThoughtLevel, "low", "low", "xhigh")}}
	_, lines := runCore(t, conn, nil, &model.Run{Task: "go"})
	if !hasCall(conn, "set_config model=big") || !hasCall(conn, "set_config effort=xhigh") {
		t.Fatalf("calls %v\n%s", conn.calls, notices(lines))
	}
}

// Through the real SDK connection and the wire: a notice between two chunks of a message is
// written as a notice (not as a session title, which the SDK decodes it as), and the message
// stays one message.
func TestACPNoticeBetweenChunksKeepsTheMessageWhole(t *testing.T) {
	lines := strings.Join([]string{
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"Hel"}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"notice","severity":"warning","title":"Context 90% full"}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"lo"}}}}`,
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"!"}}}}`,
	}, "\n") + "\n"
	var mu sync.Mutex
	var out []string
	wire := acpx.NewWire(io.Discard, strings.NewReader(lines), acpx.WireOptions{Notices: true})
	cl := &acpClient{wire: wire, emit: func(l string) { mu.Lock(); out = append(out, l); mu.Unlock() }}
	wire.Connect(cl)
	for i := 0; ; i++ {
		cl.mu.Lock()
		n := cl.msg.Len()
		cl.mu.Unlock()
		if n == len("Hello!") {
			break
		}
		if i == 200 {
			t.Fatalf("message so far %d bytes", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cl.flush()
	mu.Lock()
	defer mu.Unlock()
	if len(out) != 2 || !strings.Contains(out[0], `"type":"acp.notice"`) || !strings.Contains(out[1], `"text":"Hello!"`) {
		t.Fatalf("lines: %q", out)
	}
	for _, l := range out {
		if strings.Contains(l, harness.ACPSessionInfo) {
			t.Fatalf("the notice was taken for a session title: %q", out)
		}
	}
}

// A conversation that ends closes its session on the agent's side when the agent declares
// session/close; one that does not is left alone.
func TestACPClosesTheSessionAtTheEnd(t *testing.T) {
	clearACPEnv(t)
	closing := &coreConn{init: acp.InitializeResponse{AgentCapabilities: acp.AgentCapabilities{SessionCapabilities: acp.SessionCapabilities{Close: &acp.SessionCloseCapabilities{}}}}}
	runCore(t, closing, nil, &model.Run{Task: "go"}, "more")
	if calls := strings.Join(closing.calls, ","); !strings.HasSuffix(calls, "close sess_new") {
		t.Fatalf("calls: %s", calls)
	}
	plain := &coreConn{}
	runCore(t, plain, nil, &model.Run{Task: "go"})
	if hasCall(plain, "close sess_new") {
		t.Fatalf("closed without the capability: %v", plain.calls)
	}
}

// The agent's reasoning, plan, session title, notices and compactions become lines of the run's
// output, in the order they came; a reasoning ends where the message begins.
func TestACPReportsReasoningPlanNoticesAndCompaction(t *testing.T) {
	var lines []string
	cl := &acpClient{emit: func(l string) { lines = append(lines, l) }}
	ctx := context.Background()
	up := func(u acp.SessionUpdate) {
		_ = cl.SessionUpdate(ctx, acp.SessionNotification{SessionId: "s", Update: u})
	}
	up(acp.SessionUpdate{AgentThoughtChunk: &acp.SessionUpdateAgentThoughtChunk{Content: acp.TextBlock("Let me "), SessionUpdate: "agent_thought_chunk"}})
	up(acp.SessionUpdate{AgentThoughtChunk: &acp.SessionUpdateAgentThoughtChunk{Content: acp.TextBlock("think."), SessionUpdate: "agent_thought_chunk"}})
	up(acp.UpdateAgentMessageText("Done."))
	up(acp.SessionUpdate{Plan: &acp.SessionUpdatePlan{SessionUpdate: "plan", Entries: []acp.PlanEntry{
		{Content: "read", Status: acp.PlanEntryStatusCompleted, Priority: acp.PlanEntryPriorityHigh},
		{Content: "fix", Status: acp.PlanEntryStatusInProgress, Priority: acp.PlanEntryPriorityMedium}}}})
	title := "Fix the parser"
	up(acp.SessionUpdate{SessionInfoUpdate: &acp.SessionSessionInfoUpdate{SessionUpdate: "session_info_update", Title: &title}})
	cl.extraUpdate(acpx.ExtraUpdate{SessionID: "s", Notice: &acpx.Notice{Severity: "warning", Title: "Context 90% full"}})
	cl.extraUpdate(acpx.ExtraUpdate{SessionID: "s", Compaction: &acpx.Compaction{ID: "c1", Status: "in_progress"}})
	cl.extraUpdate(acpx.ExtraUpdate{SessionID: "s", SummaryChunk: &acpx.CompactionSummaryChunk{ID: "c1", Text: "Earlier: "}})
	cl.extraUpdate(acpx.ExtraUpdate{SessionID: "s", SummaryChunk: &acpx.CompactionSummaryChunk{ID: "c1", Text: "parser read."}})
	cl.extraUpdate(acpx.ExtraUpdate{SessionID: "s", Compaction: &acpx.Compaction{ID: "c1", Status: "completed"}})
	cl.flush()

	var got []harness.ACPLine
	for _, l := range lines {
		var v harness.ACPLine
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatal(l)
		}
		got = append(got, v)
	}
	want := []string{harness.ACPThought, harness.ACPMessage, harness.ACPPlan, harness.ACPSessionInfo, harness.ACPNotice, harness.ACPCompaction, harness.ACPCompaction}
	var types []string
	for _, l := range got {
		types = append(types, l.Type)
	}
	switch {
	case !reflect.DeepEqual(types, want):
		t.Fatalf("lines: %q", lines)
	case got[0].Text != "Let me think." || got[1].Text != "Done.":
		t.Fatalf("thought/message: %+v %+v", got[0], got[1])
	case len(got[2].Entries) != 2 || got[2].Entries[1] != (harness.ACPPlanEntry{Content: "fix", Status: "in_progress", Priority: "medium"}):
		t.Fatalf("plan: %+v", got[2])
	case got[3].Title != title || got[4].Severity != "warning" || got[4].Title != "Context 90% full":
		t.Fatalf("title/notice: %+v %+v", got[3], got[4])
	case got[5].Status != "in_progress" || got[6].Status != "completed" || got[6].Text != "Earlier: parser read." || got[6].CompactionID != "c1":
		t.Fatalf("compaction: %+v %+v", got[5], got[6])
	}
	// During a load's replay none of it is written again.
	lines = nil
	cl.setReplaying(true)
	up(acp.UpdateAgentMessageText("old"))
	cl.extraUpdate(acpx.ExtraUpdate{Notice: &acpx.Notice{Severity: "info", Title: "old"}})
	cl.setReplaying(false)
	cl.flush()
	if len(lines) != 0 {
		t.Fatalf("replayed: %q", lines)
	}
}

// A slash command the agent advertised reaches it as a command; anything else that starts with
// "/" is escaped.
func TestACPAdvertisedCommandsPass(t *testing.T) {
	clearACPEnv(t)
	cl := &acpClient{emit: func(string) {}}
	_ = cl.SessionUpdate(context.Background(), acp.SessionNotification{SessionId: "s", Update: acp.SessionUpdate{
		AvailableCommandsUpdate: &acp.SessionAvailableCommandsUpdate{SessionUpdate: "available_commands_update",
			AvailableCommands: []acp.AvailableCommand{{Name: "compact"}, {Name: "review"}}}}})
	for in, want := range map[string]string{
		"/compact":            "/compact",
		"  /review the diff":  "  /review the diff",
		"/etc/hosts is wrong": "\u200b/etc/hosts is wrong",
		"/unknown":            "\u200b/unknown",
		"plain":               "plain",
	} {
		if got := escapeACPPrompt(in, cl.isCommand); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

// harness.instructions file|env:NAME: the instructions are in the agent's configuration before it
// starts, and neither a prefix nor a system prompt carries them again.
func TestACPInstructionsDeliveredNatively(t *testing.T) {
	home := t.TempDir()
	env, ok, err := deliverInstructions([]string{"A=1"}, "file", "Be brief.", home)
	b, _ := os.ReadFile(filepath.Join(home, ".sandbox", "instructions.md"))
	if err != nil || !ok || string(b) != "Be brief.\n" || env[len(env)-1] != "SANDBOX_INSTRUCTIONS_FILE="+filepath.Join(home, ".sandbox", "instructions.md") {
		t.Fatalf("file: %v %v %q %v", ok, err, b, env)
	}
	env, ok, err = deliverInstructions(nil, "env:HERMES_ENVIRONMENT_HINT", "Be brief.", home)
	if err != nil || !ok || env[0] != "HERMES_ENVIRONMENT_HINT=Be brief." {
		t.Fatalf("env: %v %v %v", ok, err, env)
	}
	for _, bad := range []string{"env:SANDBOX_TOKEN", "env:", "prompt", "env:HARNESS_CMD"} {
		if _, _, err := deliverInstructions(nil, bad, "x", home); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if env, ok, err := deliverInstructions([]string{"A=1"}, "", "x", home); ok || err != nil || len(env) != 1 {
		t.Fatalf("default: %v %v %v", ok, err, env)
	}

	clearACPEnv(t)
	t.Setenv("SANDBOX_INSTRUCTIONS", "Be brief.")
	conn := &coreConn{}
	runCore(t, conn, &acpClient{instructionsDelivered: true, systemPrompt: func() bool { return true }}, &model.Run{Task: "go"})
	if conn.prompts[0] != "go" || conn.newReq.Meta != nil {
		t.Fatalf("sent again: prompt %q meta %v", conn.prompts[0], conn.newReq.Meta)
	}
}

// harness.session_meta goes with every session request, beside the system prompt; the reasoning
// level is selected like the mode and the model.
func TestACPSessionMetaAndThoughtLevel(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("HARNESS_SESSION_META", `{"claudeCode":{"options":{"maxTurns":40,"promptSuggestions":false}}}`)
	t.Setenv("HARNESS_THOUGHT_LEVEL", "high")
	t.Setenv("SANDBOX_INSTRUCTIONS", "Be brief.")
	conn := &coreConn{init: acp.InitializeResponse{AgentCapabilities: acp.AgentCapabilities{LoadSession: true}},
		newRes: acp.NewSessionResponse{ConfigOptions: []acp.SessionConfigOption{
			selectOption("effort", acp.SessionConfigOptionCategoryThoughtLevel, "medium", "low", "medium", "high")}}}
	cl := &acpClient{systemPrompt: func() bool { return true }}
	runCore(t, conn, cl, &model.Run{Task: "go"})
	opts, _ := conn.newReq.Meta["claudeCode"].(map[string]any)["options"].(map[string]any)
	if opts["maxTurns"] != float64(40) || conn.newReq.Meta[acpx.SystemPromptMetaKey] != "Be brief." || !hasCall(conn, "set_config effort=high") {
		t.Fatalf("new: meta %v calls %v", conn.newReq.Meta, conn.calls)
	}
	runCore(t, conn, cl, &model.Run{Task: "more", Session: "sess_new", ResumeOf: "r", Mode: model.RunMessage})
	if conn.loadReq == nil || conn.loadReq.Meta["claudeCode"] == nil {
		t.Fatalf("load: %+v", conn.loadReq)
	}
	t.Setenv("HARNESS_SESSION_META", "not json")
	bad := &coreConn{}
	_, lines := runCore(t, bad, nil, &model.Run{Task: "go"})
	if bad.newReq.Meta != nil || !strings.Contains(notices(lines), "HARNESS_SESSION_META") {
		t.Fatalf("bad meta: %v %s", bad.newReq.Meta, notices(lines))
	}
}

// What an agent leaves running in its process group (Hermes's gateway daemon) is stopped when the
// run ends.
func TestACPAgentProcessGroupEndsWithTheRun(t *testing.T) {
	_, _, c := setupACP(t, "")
	pidFile := filepath.Join(t.TempDir(), "daemon.pid")
	t.Setenv("HARNESS_CMD", `sleep 300 </dev/null >/dev/null 2>&1 & echo $! > "`+pidFile+`"; exec "`+os.Args[0]+`"`)
	old := groupKillDelay
	groupKillDelay = 200 * time.Millisecond
	defer func() { groupKillDelay = old }()
	if code := runACP(t, c, &model.Run{ID: "run_group", Task: "x"}); code != 0 {
		t.Fatalf("exit %d", code)
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
			t.Fatalf("the agent's background process %d outlived the run", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
