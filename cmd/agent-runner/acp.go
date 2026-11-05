package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
)

// executeACP runs one run of an Agent Client Protocol harness: the command is an ACP agent
// (claude-agent-acp, codex-acp, gemini --experimental-acp…) and the runner is its client over
// the agent's stdio. The run's task is the first prompt of a session, every later message of the
// conversation the next prompt of the same session; a run that continues a conversation loads
// the session the previous one reported (session/load) instead of starting a new one.
//
// What the agent reports becomes the ACP lines of internal/harness (acp.session, acp.message,
// acp.tool_call with its diffs, acp.permission, acp.turn_end) on the run's output, so the
// control plane reads the transcript, the session id and the turn ends like any harness's.
func executeACP(ctx context.Context, c *client, run *model.Run, cmdline string, env []string) int {
	fmt.Printf("agent-runner: run %s (acp): %q\n", run.ID, truncate(run.Task, 80))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The agent is stopped by the runner (stdin closed, then SIGTERM), not by runCtx: a cancelled
	// run still gets its session/cancel first.
	procCtx, stopProc := context.WithCancel(context.Background())
	defer stopProc()
	cmd := exec.CommandContext(procCtx, "/bin/sh", "-lc", cmdline)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 20 * time.Second
	cmd.Env = env
	cmd.Dir = os.Getenv("PWD")
	if _, err := os.Stat(filepath.Join(repoDir(), ".git")); err == nil {
		cmd.Dir = repoDir()
	}
	if cmd.Dir == "" {
		cmd.Dir, _ = os.Getwd()
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 1
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 1
	}
	// The run's output is what the runner writes (ACP lines, notices) and the agent's stderr.
	outR, outW := io.Pipe()
	cmd.Stderr = outW
	if err := cmd.Start(); err != nil {
		c.post(run.ID, []string{"[agent-runner] cannot start harness: " + err.Error()})
		return 127
	}
	chat := newChat(harness.InputACP, chatIdle())
	var outputDone sync.WaitGroup
	outputDone.Add(1)
	// The conversation's idle clock is driven by driveACP itself (turn ended, next prompt sent),
	// not by the output, which reaches streamOutput later than the next prompt may start. Once
	// the reading ends the pipe is closed, so no write can wait on a reader that is gone.
	go func() {
		defer outputDone.Done()
		streamOutput(c, run.ID, outR, nil)
		_ = outR.CloseWithError(io.ErrClosedPipe)
	}()
	emit := func(line string) { _, _ = io.WriteString(outW, line+"\n") }

	wire := newACPWire(stdin, stdout)
	cl := &acpClient{emit: emit, permissions: os.Getenv("HARNESS_PERMISSIONS"), systemPrompt: wire.SystemPrompt,
		usageDir: filepath.Join(os.Getenv("HOME"), ".sandbox-acp-usage")}
	conn := acp.NewClientSideConnection(cl, wire, wire)
	exit := driveACP(runCtx, conn, cl, run, emit, chat, func(inputs inputSink) {
		go forwardInput(runCtx, c, run.ID, inputs, cancel, chat)
	})

	// The conversation is over: end of input, a grace period for the agent to exit on its own,
	// then SIGTERM (and SIGKILL after WaitDelay).
	_ = stdin.Close()
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		stopProc()
		<-exited
	}
	_ = outW.Close()
	outputDone.Wait()
	return exit
}

// acpConn is what driveACP needs of the client-side connection (an interface, so the conversation
// logic is tested against a scripted agent).
type acpConn interface {
	Initialize(ctx context.Context, params acp.InitializeRequest) (acp.InitializeResponse, error)
	NewSession(ctx context.Context, params acp.NewSessionRequest) (acp.NewSessionResponse, error)
	LoadSession(ctx context.Context, params acp.LoadSessionRequest) (acp.LoadSessionResponse, error)
	Prompt(ctx context.Context, params acp.PromptRequest) (acp.PromptResponse, error)
	Cancel(ctx context.Context, params acp.CancelNotification) error
}

// acpAuthenticator is the authenticate method of a connection (the client-side connection has
// it; a scripted one in a test need not).
type acpAuthenticator interface {
	Authenticate(ctx context.Context, params acp.AuthenticateRequest) (acp.AuthenticateResponse, error)
}

// acpOpened is the session a conversation runs in: its id, whether it is new (fresh), whether the
// agent took the instructions as its system prompt, and who the agent is.
type acpOpened struct {
	id           acp.SessionId
	fresh        bool
	instructions bool   // given as the session's system prompt: no prefix on the first prompt
	agent        string // initialize agentInfo.name
}

// openACPSession initializes the agent, authenticates it when the profile names a method, and
// continues the run's session (session/resume when the agent declares it, else session/load) or
// starts a new one. The session is then put in the profile's mode and on its model. Nothing is
// prompted here: a failure has been reported through emit when ok is false.
func openACPSession(ctx context.Context, conn acpConn, cl *acpClient, run *model.Run, emit func(string)) (s acpOpened, ok bool) {
	notice := noticeFunc(emit)
	init, err := conn.Initialize(ctx, acp.InitializeRequest{
		ProtocolVersion: acp.ProtocolVersionNumber,
		// The agent works in its own pod with its own tools: the runner offers no file system
		// or terminal of its own.
		ClientCapabilities: acp.ClientCapabilities{},
	})
	if err != nil {
		notice("acp initialize: %v", err)
		return s, false
	}
	if init.AgentInfo != nil {
		s.agent = init.AgentInfo.Name
	}
	// The profile names the agent's authentication method (spec.harness.auth_method): an API key
	// in the environment, say. Without one the agent is not asked, and one that needs it refuses
	// the session (authNeeded says which methods it offers).
	if method := os.Getenv("HARNESS_AUTH_METHOD"); method != "" {
		if ids := authMethodIDs(init.AuthMethods); !slices.Contains(ids, method) {
			notice("acp authenticate: the agent offers %v, not %q (spec.harness.auth_method)", ids, method)
			return s, false
		}
		auth, ok := conn.(acpAuthenticator)
		if !ok {
			notice("acp authenticate: the connection cannot authenticate")
			return s, false
		}
		if _, err := auth.Authenticate(ctx, acp.AuthenticateRequest{MethodId: method}); err != nil {
			notice("acp authenticate %s: %v", method, err)
			return s, false
		}
	}
	authNeeded := func(op string, err error) {
		var re *acp.RequestError
		if errors.As(err, &re) && re.Code == acp.NewAuthRequired(nil).Code {
			notice("acp %s: the agent requires authentication: set spec.harness.auth_method to one of %v", op, authMethodIDs(init.AuthMethods))
			return
		}
		notice("acp %s: %v", op, err)
	}
	cwd := os.Getenv("PWD")
	if _, err := os.Stat(filepath.Join(repoDir(), ".git")); err == nil {
		cwd = repoDir()
	}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	// harness.mcp: always passes the servers to an agent that takes them without declaring MCP
	// over HTTP (Hermes); auto (the default) only to one that declares it.
	httpMCP := init.AgentCapabilities.McpCapabilities.Http || os.Getenv("HARNESS_MCP") == harness.MCPAlways
	servers, skipped := acpMCPServers(os.Getenv("SANDBOX_MCP_SERVERS"), httpMCP)
	if skipped > 0 {
		notice("%d mcp server(s) not passed: the agent does not declare MCP servers over HTTP (spec.harness.mcp: always passes them anyway)", skipped)
	}
	// The instructions are the session's system prompt when the agent takes one: they then
	// survive the agent compacting its context, which a prefix of the first prompt may not.
	// A system prompt is not part of the session's history, so a loaded or resumed session gets
	// it again.
	instructions := strings.TrimSpace(os.Getenv("SANDBOX_INSTRUCTIONS"))
	if instructions != "" && cl.systemPrompt != nil && cl.systemPrompt() {
		s.instructions = true
	} else {
		instructions = ""
	}
	meta := sessionMeta(instructions)

	var st acpSessionState
	if run.Session != "" && run.ResumeOf != "" {
		prev := acp.SessionId(run.Session)
		caps := init.AgentCapabilities
		resumer, canResume := conn.(acpResumer)
		if caps.SessionCapabilities.Resume != nil && canResume {
			// session/resume continues without replaying the history.
			r, err := resumer.ResumeSession(ctx, acp.ResumeSessionRequest{Meta: meta, SessionId: prev, Cwd: cwd, McpServers: servers})
			if err == nil {
				s.id, st = prev, acpSessionState{modes: r.Modes, options: r.ConfigOptions}
			} else {
				authNeeded("session/resume "+run.Session, err)
			}
		}
		if s.id == "" && caps.LoadSession {
			// session/load replays the conversation as updates: the transcript already has it.
			cl.setReplaying(true)
			r, err := conn.LoadSession(ctx, acp.LoadSessionRequest{Meta: meta, SessionId: prev, Cwd: cwd, McpServers: servers})
			cl.setReplaying(false)
			if err == nil {
				s.id, st = prev, acpSessionState{modes: r.Modes, options: r.ConfigOptions}
			} else {
				authNeeded("session/load "+run.Session, err)
			}
		}
		switch {
		case s.id != "":
		case caps.SessionCapabilities.Resume == nil && !caps.LoadSession:
			notice("the agent cannot continue session %s (neither resume nor loadSession): starting a new session", run.Session)
		default:
			notice("starting a new session")
		}
	}
	if s.id == "" {
		ns, err := conn.NewSession(ctx, acp.NewSessionRequest{Meta: meta, Cwd: cwd, McpServers: servers})
		if err != nil {
			authNeeded("session/new", err)
			return s, false
		}
		s.id, s.fresh, st = ns.SessionId, true, acpSessionState{modes: ns.Modes, options: ns.ConfigOptions}
	}
	configureACPSession(ctx, conn, s.id, st, os.Getenv("HARNESS_MODE"), os.Getenv("SANDBOX_MODEL"), notice)
	return s, true
}

// driveACP holds the conversation: the session (openACPSession), then one prompt per message
// until the input is closed (run.close, the idle period) or the run is cancelled. startInput
// starts delivering the user's messages into the sink it is given. The result is the run's exit
// code.
func driveACP(ctx context.Context, conn acpConn, cl *acpClient, run *model.Run, emit func(string), chat *chatState, startInput func(inputSink)) int {
	sess, ok := openACPSession(ctx, conn, cl, run, emit)
	if !ok {
		return 1
	}
	sessionID := sess.id
	emit(harness.ACPLine{Type: harness.ACPSession, SessionID: string(sessionID)}.String())
	notice := noticeFunc(emit)
	usage := newACPUsage(sess.agent, string(sessionID), cl)

	inputs := newPromptQueue()
	startInput(inputs)
	instructions := os.Getenv("SANDBOX_INSTRUCTIONS")
	if sess.instructions {
		instructions = "" // the session's system prompt has them
	}
	prompt := firstPrompt(run, sess.fresh, instructions, os.Getenv("SANDBOX_RESUME_PROMPT"))
	for {
		resp, err := promptACP(ctx, conn, cl, sessionID, prompt, notice)
		cl.flush()
		if err != nil {
			if ctx.Err() != nil {
				// Cancelled: tell the agent, which ends the turn it is in.
				cctx, done := context.WithTimeout(context.Background(), 2*time.Second)
				_ = conn.Cancel(cctx, acp.CancelNotification{SessionId: sessionID})
				done()
				return 1
			}
			notice("acp session/prompt: %v", err)
			return 1
		}
		if line, ok := usage.turn(resp.Usage); ok {
			emit(line)
		}
		emit(harness.ACPLine{Type: harness.ACPTurnEnd, StopReason: string(resp.StopReason)}.String())
		if resp.StopReason == acp.StopReasonCancelled {
			return 1
		}
		chat.turnEnded()
		next, ok := inputs.next(ctx)
		if !ok {
			return 0
		}
		// A message that waited for this turn is a new turn: the idle clock stops until it ends.
		chat.sent()
		prompt = escapeACPPrompt(next)
	}
}

// promptACP sends one prompt. Hermes refuses every prompt of a session whose previous turn was
// lost when its gateway restarted (unknown_execution) until the lost turn is discarded with
// `/discard <id>`: the runner discards the turns it names and sends the prompt once more.
func promptACP(ctx context.Context, conn acpConn, cl *acpClient, sid acp.SessionId, text string, notice func(string, ...any)) (acp.PromptResponse, error) {
	resp, err := conn.Prompt(ctx, acp.PromptRequest{SessionId: sid, Prompt: []acp.ContentBlock{acp.TextBlock(text)}})
	if err == nil || ctx.Err() != nil {
		return resp, err
	}
	lost := lostTurns(err.Error())
	if len(lost) == 0 {
		return resp, err
	}
	cl.flush()
	for _, id := range lost {
		notice("the agent lost a turn (unknown_execution): discarding %s and sending the prompt again", id)
		if _, derr := conn.Prompt(ctx, acp.PromptRequest{SessionId: sid, Prompt: []acp.ContentBlock{acp.TextBlock("/discard " + id)}}); derr != nil {
			notice("/discard %s: %v", id, derr)
			return resp, err
		}
		cl.flush()
	}
	return conn.Prompt(ctx, acp.PromptRequest{SessionId: sid, Prompt: []acp.ContentBlock{acp.TextBlock(text)}})
}

// lostTurnRe finds the turns Hermes's unknown_execution refusal names: "Send `/discard <id>`".
var lostTurnRe = regexp.MustCompile("`/discard ([^`\\s]+)`")

func lostTurns(msg string) []string {
	if !strings.Contains(msg, "unknown_execution") {
		return nil
	}
	var ids []string
	for _, m := range lostTurnRe.FindAllStringSubmatch(msg, 4) {
		if !slices.Contains(ids, m[1]) {
			ids = append(ids, m[1])
		}
	}
	return ids
}

// escapeACPPrompt keeps a message that starts with "/" from being taken for one of the agent's
// slash commands (OpenCode runs a known command and ends the turn empty on an unknown one;
// claude-agent-acp has its own). The agents trim whitespace before they look, so the escape is
// a zero-width space, which they do not trim and the model reads past.
func escapeACPPrompt(text string) string {
	if strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "/") {
		return "\u200b" + text
	}
	return text
}

// firstPrompt is the text of the run's first prompt. For an agent that takes no system prompt
// (sessionCapabilities.systemPrompt), a new session starts with the agent definition's
// instructions ahead of the task; a loaded one already has them. A run that resumes an interrupted one (a rollout) continues it.
func firstPrompt(run *model.Run, fresh bool, instructions, resumePrompt string) string {
	task := run.Task
	if run.ResumeOf != "" && run.Mode != model.RunMessage {
		task = resumePrompt
		if task == "" {
			task = "The sandbox was restarted to update the agent. Continue the task where you left off."
		}
		if fresh {
			task = run.Task // nothing to continue: do the task again
		}
	}
	task = escapeACPPrompt(task)
	if fresh && strings.TrimSpace(instructions) != "" {
		return "<instructions>\n" + strings.TrimSpace(instructions) + "\n</instructions>\n\n" + task
	}
	return task
}

// authMethodIDs lists the ids of the authentication methods an agent advertises.
func authMethodIDs(methods []acp.AuthMethod) []string {
	ids := []string{}
	for _, m := range methods {
		switch {
		case m.Agent != nil:
			ids = append(ids, m.Agent.Id)
		case m.EnvVar != nil:
			ids = append(ids, m.EnvVar.Id)
		case m.Terminal != nil:
			ids = append(ids, m.Terminal.Id)
		}
	}
	return ids
}

// acpMCPServers turns SANDBOX_MCP_SERVERS ([{name, url}]) into the session's MCP servers. They
// are HTTP servers behind the gateway, given as their gateway bridge URLs; an agent without the
// http MCP capability gets none (skipped counts them).
func acpMCPServers(raw string, http bool) (servers []acp.McpServer, skipped int) {
	servers = []acp.McpServer{}
	if strings.TrimSpace(raw) == "" {
		return servers, 0
	}
	var list []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if json.Unmarshal([]byte(raw), &list) != nil {
		return servers, 0
	}
	for _, s := range list {
		if s.Name == "" || s.URL == "" {
			continue
		}
		if !http {
			skipped++
			continue
		}
		// Through the gateway bridge: an ACP agent's MCP client need not present the pod's
		// client certificate itself (bridge.go).
		servers = append(servers, acp.McpServer{Http: &acp.McpServerHttpInline{Name: s.Name, Url: gatewayBridgeURL(s.URL), Headers: []acp.HttpHeader{}, Type: "http"}})
	}
	return servers, skipped
}

// promptQueue is the inputSink of an ACP conversation: messages wait for the turn in progress
// to end and become the next prompts, in order.
type promptQueue struct {
	mu     sync.Mutex
	queue  []string
	closed bool
	wake   chan struct{}
}

func newPromptQueue() *promptQueue { return &promptQueue{wake: make(chan struct{}, 1)} }

func (q *promptQueue) Send(text string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return errors.New("conversation closed")
	}
	q.queue = append(q.queue, text)
	q.signal()
	return nil
}

func (q *promptQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.signal()
	return nil
}

func (q *promptQueue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// next waits for the next message; ok is false once the input is closed and drained, or the
// run is cancelled.
func (q *promptQueue) next(ctx context.Context) (string, bool) {
	for {
		q.mu.Lock()
		if len(q.queue) > 0 {
			t := q.queue[0]
			q.queue = q.queue[1:]
			q.mu.Unlock()
			return t, true
		}
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return "", false
		}
		select {
		case <-q.wake:
		case <-ctx.Done():
			return "", false
		}
	}
}

// acpClient is the runner's side of ACP: it turns the agent's session updates into ACP lines and
// answers its permission requests by the profile's policy. It offers no file system or terminal
// (the client capabilities say so), so those methods are never called by a conforming agent.
type acpClient struct {
	emit        func(string)
	permissions string // harness.PermissionsAllow (default) or PermissionsDeny
	// systemPrompt reports whether the agent takes the client's system prompt (acpWire); nil:
	// it does not.
	systemPrompt func() bool
	// usageDir keeps the last cumulative usage of the sessions of an agent that reports one
	// (acpUsage); "" keeps it in memory only.
	usageDir string

	mu        sync.Mutex
	msg       strings.Builder // the agent message being streamed in chunks
	replaying bool            // session/load: history the transcript already has
	// diffs are the diffs last written for each tool call: a later line with the same ones
	// leaves them out, one with others replaces them (harness.ACPLine.DiffsReplace).
	diffs map[string][]harness.ACPDiff
	// cost is the session's cost as the agent last reported it (usage_update, cumulative).
	cost     float64
	costSeen bool
}

var _ acp.Client = (*acpClient)(nil)

func (a *acpClient) setReplaying(v bool) {
	a.mu.Lock()
	a.replaying = v
	a.mu.Unlock()
}

// flush writes the agent message gathered so far as one acp.message line.
func (a *acpClient) flush() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flushLocked()
}

func (a *acpClient) flushLocked() {
	if strings.TrimSpace(a.msg.String()) != "" {
		a.emit(harness.ACPLine{Type: harness.ACPMessage, Text: a.msg.String()}.String())
	}
	a.msg.Reset()
}

func (a *acpClient) SessionUpdate(_ context.Context, n acp.SessionNotification) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.replaying {
		return nil
	}
	u := n.Update
	switch {
	case u.AgentMessageChunk != nil:
		if t := u.AgentMessageChunk.Content.Text; t != nil {
			a.msg.WriteString(t.Text)
		}
	case u.ToolCall != nil:
		a.flushLocked()
		tc := u.ToolCall
		l := harness.ACPLine{Type: harness.ACPToolCall, ToolCallID: string(tc.ToolCallId), Title: tc.Title,
			Kind: string(tc.Kind), Status: string(tc.Status)}
		a.withDiffsLocked(&l, acpDiffs(tc.Content))
		a.emit(l.String())
	case u.ToolCallUpdate != nil:
		tu := u.ToolCallUpdate
		l := harness.ACPLine{Type: harness.ACPToolUpdate, ToolCallID: string(tu.ToolCallId)}
		a.withDiffsLocked(&l, acpDiffs(tu.Content))
		if tu.Status != nil {
			l.Status = string(*tu.Status)
		}
		if tu.Title != nil {
			l.Title = *tu.Title
		}
		if l.Status != "" || len(l.Diffs) > 0 {
			a.flushLocked()
			a.emit(l.String())
		}
	case u.UsageUpdate != nil:
		if c := u.UsageUpdate.Cost; c != nil && (c.Currency == "" || strings.EqualFold(c.Currency, "USD")) {
			a.cost, a.costSeen = c.Amount, true
		}
	}
	return nil
}

// withDiffsLocked puts diffs on a tool call's line unless the call's last line already carried
// the same ones; diffs that differ from earlier ones replace them. Called with a.mu held.
func (a *acpClient) withDiffsLocked(l *harness.ACPLine, diffs []harness.ACPDiff) {
	if len(diffs) == 0 {
		return
	}
	if a.diffs == nil {
		a.diffs = map[string][]harness.ACPDiff{}
	}
	prev, seen := a.diffs[l.ToolCallID]
	if seen && reflect.DeepEqual(prev, diffs) {
		return
	}
	a.diffs[l.ToolCallID] = diffs
	l.Diffs, l.DiffsReplace = diffs, seen
}

// sessionCost is the cost the agent reported last (ok false: none).
func (a *acpClient) sessionCost() (float64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cost, a.costSeen
}

// maxACPDiffText caps the text of one diff on an ACP line: a larger change keeps its path and
// sizes and is marked truncated (the file itself is in the workspace). The whole line stays
// well under maxOutputLine and the control plane's batch limit.
const maxACPDiffText = 128 << 10

func acpDiffs(content []acp.ToolCallContent) []harness.ACPDiff {
	var out []harness.ACPDiff
	for _, c := range content {
		d := c.Diff
		if d == nil {
			continue
		}
		diff := harness.ACPDiff{Path: d.Path, OldText: d.OldText, NewText: d.NewText, NewSize: len(d.NewText)}
		diff.Change, diff.OldPath = diffChange(d.Meta, d.Path)
		if d.OldText != nil {
			diff.OldSize = len(*d.OldText)
		}
		if diff.OldSize+diff.NewSize > maxACPDiffText {
			diff.OldText, diff.NewText, diff.Truncated = nil, "", true
		}
		out = append(out, diff)
	}
	return out
}

// diffChange reads what kind of change a diff is from its _meta, where codex-acp says it (kind:
// add, update, delete) and keeps the patch it came from (diff_git_patch.oldPath: a different
// path is a rename). Other agents say nothing: "".
func diffChange(meta map[string]any, path string) (change, oldPath string) {
	if meta == nil {
		return "", ""
	}
	change, _ = meta["kind"].(string)
	switch change {
	case "add", "update", "delete", "rename":
	default:
		change = ""
	}
	if patch, ok := meta["diff_git_patch"].(map[string]any); ok {
		if old, _ := patch["oldPath"].(string); old != "" && old != path {
			oldPath = old
			if change == "" || change == "update" {
				change = "rename"
			}
		}
	}
	return change, oldPath
}

// RequestPermission picks the agent's own option that matches the profile's policy (allow:
// allow_once, else allow_always; deny: reject_once, else reject_always) and records it. With no
// matching option the request is cancelled, which the agent treats as a refusal.
func (a *acpClient) RequestPermission(_ context.Context, p acp.RequestPermissionRequest) (acp.RequestPermissionResponse, error) {
	want := []acp.PermissionOptionKind{acp.PermissionOptionKindAllowOnce, acp.PermissionOptionKindAllowAlways}
	if a.permissions == harness.PermissionsDeny {
		want = []acp.PermissionOptionKind{acp.PermissionOptionKindRejectOnce, acp.PermissionOptionKindRejectAlways}
	}
	l := harness.ACPLine{Type: harness.ACPPermission, ToolCallID: string(p.ToolCall.ToolCallId), Decision: "cancelled"}
	if p.ToolCall.Title != nil {
		l.Title = *p.ToolCall.Title
	}
	out := acp.RequestPermissionResponse{Outcome: acp.RequestPermissionOutcome{Cancelled: &acp.RequestPermissionOutcomeCancelled{}}}
pick:
	for _, kind := range want {
		for _, o := range p.Options {
			if o.Kind == kind {
				out = acp.RequestPermissionResponse{Outcome: acp.RequestPermissionOutcome{Selected: &acp.RequestPermissionOutcomeSelected{OptionId: o.OptionId}}}
				l.Decision = string(kind)
				break pick
			}
		}
	}
	a.mu.Lock()
	// OpenCode and Hermes send the change's full diff only here, in the tool call the request is
	// about; the call's own updates may refine it (withDiffsLocked).
	a.withDiffsLocked(&l, acpDiffs(p.ToolCall.Content))
	// Requests are dispatched independently of ordered session notifications.
	// A permission callback may overtake text chunks, so only the notification
	// stream and the prompt response may flush the pending assistant message.
	a.emit(l.String())
	a.mu.Unlock()
	return out, nil
}

var errNoClientCapability = errors.New("agent-runner offers no client file system or terminal")

func (a *acpClient) ReadTextFile(context.Context, acp.ReadTextFileRequest) (acp.ReadTextFileResponse, error) {
	return acp.ReadTextFileResponse{}, errNoClientCapability
}

// WriteTextFile answers success without writing. The runner declares no file system, yet
// OpenCode tells the client about an approved edit it has already made on disk (and leaves an
// error unhandled): the file is in the workspace, there is nothing for the runner to do.
func (a *acpClient) WriteTextFile(context.Context, acp.WriteTextFileRequest) (acp.WriteTextFileResponse, error) {
	return acp.WriteTextFileResponse{}, nil
}

func (a *acpClient) CreateTerminal(context.Context, acp.CreateTerminalRequest) (acp.CreateTerminalResponse, error) {
	return acp.CreateTerminalResponse{}, errNoClientCapability
}

func (a *acpClient) KillTerminal(context.Context, acp.KillTerminalRequest) (acp.KillTerminalResponse, error) {
	return acp.KillTerminalResponse{}, errNoClientCapability
}

func (a *acpClient) TerminalOutput(context.Context, acp.TerminalOutputRequest) (acp.TerminalOutputResponse, error) {
	return acp.TerminalOutputResponse{}, errNoClientCapability
}

func (a *acpClient) ReleaseTerminal(context.Context, acp.ReleaseTerminalRequest) (acp.ReleaseTerminalResponse, error) {
	return acp.ReleaseTerminalResponse{}, errNoClientCapability
}

func (a *acpClient) WaitForTerminalExit(context.Context, acp.WaitForTerminalExitRequest) (acp.WaitForTerminalExitResponse, error) {
	return acp.WaitForTerminalExitResponse{}, errNoClientCapability
}
