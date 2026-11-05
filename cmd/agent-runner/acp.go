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

	cl := &acpClient{emit: emit, permissions: os.Getenv("HARNESS_PERMISSIONS")}
	conn := acp.NewClientSideConnection(cl, stdin, stdout)
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

// openACPSession initializes the agent, authenticates it when the profile names a method, and
// loads the run's session (a continuing conversation) or starts a new one; fresh says which.
// Nothing is prompted here: a failure has been reported through emit when ok is false.
func openACPSession(ctx context.Context, conn acpConn, cl *acpClient, run *model.Run, emit func(string)) (sessionID acp.SessionId, fresh, ok bool) {
	notice := func(format string, a ...any) { emit("[agent-runner] " + fmt.Sprintf(format, a...)) }
	init, err := conn.Initialize(ctx, acp.InitializeRequest{
		ProtocolVersion: acp.ProtocolVersionNumber,
		// The agent works in its own pod with its own tools: the runner offers no file system
		// or terminal of its own.
		ClientCapabilities: acp.ClientCapabilities{},
	})
	if err != nil {
		notice("acp initialize: %v", err)
		return "", false, false
	}
	// The profile names the agent's authentication method (spec.harness.auth_method): an API key
	// in the environment, say. Without one the agent is not asked, and one that needs it refuses
	// the session (authNeeded says which methods it offers).
	if method := os.Getenv("HARNESS_AUTH_METHOD"); method != "" {
		if ids := authMethodIDs(init.AuthMethods); !slices.Contains(ids, method) {
			notice("acp authenticate: the agent offers %v, not %q (spec.harness.auth_method)", ids, method)
			return "", false, false
		}
		auth, ok := conn.(acpAuthenticator)
		if !ok {
			notice("acp authenticate: the connection cannot authenticate")
			return "", false, false
		}
		if _, err := auth.Authenticate(ctx, acp.AuthenticateRequest{MethodId: method}); err != nil {
			notice("acp authenticate %s: %v", method, err)
			return "", false, false
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
	servers, skipped := acpMCPServers(os.Getenv("SANDBOX_MCP_SERVERS"), init.AgentCapabilities.McpCapabilities.Http)
	if skipped > 0 {
		notice("%d mcp server(s) not passed: the agent does not take MCP servers over HTTP", skipped)
	}

	if run.Session != "" && run.ResumeOf != "" {
		if init.AgentCapabilities.LoadSession {
			// session/load replays the conversation as updates: the transcript already has it.
			cl.setReplaying(true)
			_, err := conn.LoadSession(ctx, acp.LoadSessionRequest{SessionId: acp.SessionId(run.Session), Cwd: cwd, McpServers: servers})
			cl.setReplaying(false)
			if err == nil {
				sessionID = acp.SessionId(run.Session)
			} else {
				authNeeded("session/load "+run.Session, err)
				notice("starting a new session")
			}
		} else {
			notice("the agent cannot load session %s (no loadSession capability): starting a new session", run.Session)
		}
	}
	if sessionID == "" {
		ns, err := conn.NewSession(ctx, acp.NewSessionRequest{Cwd: cwd, McpServers: servers})
		if err != nil {
			authNeeded("session/new", err)
			return "", false, false
		}
		sessionID, fresh = ns.SessionId, true
	}
	return sessionID, fresh, true
}

// driveACP holds the conversation: the session (openACPSession), then one prompt per message
// until the input is closed (run.close, the idle period) or the run is cancelled. startInput
// starts delivering the user's messages into the sink it is given. The result is the run's exit
// code.
func driveACP(ctx context.Context, conn acpConn, cl *acpClient, run *model.Run, emit func(string), chat *chatState, startInput func(inputSink)) int {
	sessionID, fresh, ok := openACPSession(ctx, conn, cl, run, emit)
	if !ok {
		return 1
	}
	emit(harness.ACPLine{Type: harness.ACPSession, SessionID: string(sessionID)}.String())
	notice := func(format string, a ...any) { emit("[agent-runner] " + fmt.Sprintf(format, a...)) }

	inputs := newPromptQueue()
	startInput(inputs)
	prompt := firstPrompt(run, fresh, os.Getenv("SANDBOX_INSTRUCTIONS"), os.Getenv("SANDBOX_RESUME_PROMPT"))
	for {
		resp, err := conn.Prompt(ctx, acp.PromptRequest{SessionId: sessionID, Prompt: []acp.ContentBlock{acp.TextBlock(prompt)}})
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
		if u := resp.Usage; u != nil {
			emit(usageLine(*u))
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
		prompt = next
	}
}

// firstPrompt is the text of the run's first prompt. ACP has no system prompt of its own, so a
// new session starts with the agent definition's instructions ahead of the task; a loaded one
// already has them. A run that resumes an interrupted one (a rollout) continues it.
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
// are HTTP servers behind the gateway; an agent without the http MCP capability gets none
// (skipped counts them).
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
		servers = append(servers, acp.McpServer{Http: &acp.McpServerHttpInline{Name: s.Name, Url: s.URL, Headers: []acp.HttpHeader{}, Type: "http"}})
	}
	return servers, skipped
}

// usageLine renders a prompt turn's usage as the generic usage record the control plane adds up.
func usageLine(u acp.Usage) string {
	rec := model.Usage{InputTokens: int64(u.InputTokens), OutputTokens: int64(u.OutputTokens), Turns: 1}
	if u.CachedReadTokens != nil {
		rec.CacheRead = int64(*u.CachedReadTokens)
	}
	if u.CachedWriteTokens != nil {
		rec.CacheWrite = int64(*u.CachedWriteTokens)
	}
	b, _ := json.Marshal(struct {
		Type string `json:"type"`
		model.Usage
	}{"usage", rec})
	return string(b)
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

	mu        sync.Mutex
	msg       strings.Builder // the agent message being streamed in chunks
	replaying bool            // session/load: history the transcript already has
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
		a.emit(harness.ACPLine{Type: harness.ACPToolCall, ToolCallID: string(tc.ToolCallId), Title: tc.Title,
			Kind: string(tc.Kind), Status: string(tc.Status), Diffs: acpDiffs(tc.Content)}.String())
	case u.ToolCallUpdate != nil:
		tu := u.ToolCallUpdate
		l := harness.ACPLine{Type: harness.ACPToolUpdate, ToolCallID: string(tu.ToolCallId), Diffs: acpDiffs(tu.Content)}
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
	}
	return nil
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

func (a *acpClient) WriteTextFile(context.Context, acp.WriteTextFileRequest) (acp.WriteTextFileResponse, error) {
	return acp.WriteTextFileResponse{}, errNoClientCapability
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
