package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
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

	mu       sync.Mutex
	calls    []string
	prompts  []string
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
	return acp.LoadSessionResponse{Modes: c.opened.modes, ConfigOptions: c.opened.options}, c.loadErr
}

func (c *coreConn) ResumeSession(_ context.Context, p acp.ResumeSessionRequest) (acp.ResumeSessionResponse, error) {
	c.call("resume")
	c.resumReq = &p
	return acp.ResumeSessionResponse{Modes: c.opened.modes, ConfigOptions: c.opened.options}, c.resumeErr
}

func (c *coreConn) SetSessionMode(_ context.Context, p acp.SetSessionModeRequest) (acp.SetSessionModeResponse, error) {
	c.call("set_mode " + string(p.ModeId))
	return acp.SetSessionModeResponse{}, nil
}

func (c *coreConn) SetSessionConfigOption(_ context.Context, p acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error) {
	c.call("set_config " + string(p.ValueId.ConfigId) + "=" + string(p.ValueId.Value))
	return acp.SetSessionConfigOptionResponse{}, nil
}

func (c *coreConn) Prompt(_ context.Context, p acp.PromptRequest) (acp.PromptResponse, error) {
	c.mu.Lock()
	n := len(c.prompts)
	text := p.Prompt[0].Text.Text
	c.prompts = append(c.prompts, text)
	c.mu.Unlock()
	if c.prompt == nil {
		return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
	}
	return c.prompt(n, text)
}

func (c *coreConn) Cancel(context.Context, acp.CancelNotification) error { return nil }

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

	resume := &coreConn{init: acp.InitializeResponse{AgentCapabilities: both}, opened: acpSessionState{modes: modes}}
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
	if native.newReq.Meta[systemPromptMetaKey] != "Be brief." || native.prompts[0] != "go" {
		t.Fatalf("system prompt: meta %v prompt %q", native.newReq.Meta, native.prompts[0])
	}
	runCore(t, native, cl, &model.Run{Task: "more", Session: "sess_new", ResumeOf: "r", Mode: model.RunMessage})
	if native.loadReq == nil || native.loadReq.Meta[systemPromptMetaKey] != "Be brief." {
		t.Fatalf("load keeps the system prompt: %+v", native.loadReq)
	}

	prefixed := &coreConn{}
	runCore(t, prefixed, &acpClient{systemPrompt: func() bool { return false }}, &model.Run{Task: "go"})
	if prefixed.newReq.Meta != nil || !strings.HasPrefix(prefixed.prompts[0], "<instructions>\nBe brief.\n</instructions>") {
		t.Fatalf("prefix: meta %v prompt %q", prefixed.newReq.Meta, prefixed.prompts[0])
	}
}

// acpWire reads the capability off the initialize response and turns the marker into the
// request's systemPrompt; the rest of the request and every other message pass unchanged.
func TestACPWireSystemPrompt(t *testing.T) {
	var sent bytes.Buffer
	init := `{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":1,"agentCapabilities":{"sessionCapabilities":{"resume":{},"systemPrompt":{"mode":{"override":{}}}}}}}` + "\n"
	w := newACPWire(&sent, strings.NewReader(`{"jsonrpc":"2.0","method":"session/update","params":{}}`+"\n"+init[:40]))
	buf := make([]byte, 7) // lines arrive in pieces
	for {
		if _, err := w.Read(buf); err != nil {
			break
		}
	}
	if w.SystemPrompt() {
		t.Fatal("capability before the initialize response")
	}
	w.r = strings.NewReader(init[40:])
	for {
		if _, err := w.Read(buf); err != nil {
			break
		}
	}
	if !w.SystemPrompt() {
		t.Fatal("capability not seen")
	}
	none := newACPWire(&sent, strings.NewReader(`{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":1,"agentCapabilities":{"loadSession":true}}}`+"\n"))
	_, _ = none.Read(make([]byte, 4096))
	if none.SystemPrompt() {
		t.Fatal("capability without systemPrompt")
	}

	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "session/new",
		"params": map[string]any{"cwd": "/w", "mcpServers": []any{}, "_meta": map[string]any{systemPromptMetaKey: "Be brief.", "other": 1}}})
	if n, err := w.Write(append(req, '\n')); err != nil || n != len(req)+1 {
		t.Fatalf("write: %d %v", n, err)
	}
	var got struct {
		Params map[string]json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(sent.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Params["systemPrompt"]) != `{"content":[{"text":"Be brief.","type":"text"}],"mode":"append"}` ||
		string(got.Params["_meta"]) != `{"other":1}` || string(got.Params["cwd"]) != `"/w"` {
		t.Fatalf("rewritten: %s", sent.String())
	}
	sent.Reset()
	plain := `{"jsonrpc":"2.0","id":2,"method":"session/prompt","params":{}}` + "\n"
	_, _ = w.Write([]byte(plain))
	if sent.String() != plain {
		t.Fatalf("passthrough: %q", sent.String())
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
