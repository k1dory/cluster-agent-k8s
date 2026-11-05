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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
	"github.com/k1dory/acpx"
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
	// The instructions an agent reads from its own configuration (harness.instructions: file or
	// env:NAME) are in place before it starts.
	env, delivered, err := deliverInstructions(env, os.Getenv("HARNESS_INSTRUCTIONS"), os.Getenv("SANDBOX_INSTRUCTIONS"), os.Getenv("HOME"))
	if err != nil {
		c.post(run.ID, []string{"[agent-runner] instructions: " + err.Error()})
		return 1
	}
	cmd := exec.CommandContext(procCtx, "/bin/sh", "-lc", cmdline)
	// The agent and everything it starts are one process group, ended as a whole: an agent may
	// leave helpers running after it exits (Hermes's gateway daemon, a server of its own), which
	// would outlive the run with the run's configuration and keep writing into the workspace.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return signalGroup(cmd, syscall.SIGTERM) }
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

	// The agent's notices and compaction updates are asked for by the wire (the SDK cannot) and
	// told apart from the SDK's own updates in their place in the stream (Classify): the client
	// has the wire before the connection delivers anything.
	wire := acpx.NewWire(stdin, stdout, acpx.WireOptions{Notices: true, Compaction: true})
	cl := &acpClient{emit: emit, permissions: os.Getenv("HARNESS_PERMISSIONS"), instructionsDelivered: delivered,
		usageDir: filepath.Join(os.Getenv("HOME"), ".sandbox-acp-usage"), wire: wire, systemPrompt: wire.SystemPrompt,
		pending: acpx.NewPending(), askTimeout: askTimeout(os.Getenv("HARNESS_ASK_TIMEOUT"))}
	conn := wire.Connect(cl)
	exit := driveACP(runCtx, conn, cl, run, emit, chat, func(inputs inputSink) {
		go forwardInput(runCtx, c, run.ID, inputs, cancel, chat)
	})

	// The conversation is over: end of input, a grace period for the agent to exit on its own,
	// then SIGTERM to its process group (and SIGKILL after WaitDelay).
	_ = stdin.Close()
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		stopProc()
		<-exited
	}
	// What the agent left running in its group is stopped too: SIGTERM (a daemon drains on it),
	// SIGKILL a moment later for what did not exit.
	endGroup(cmd)
	_ = outW.Close()
	outputDone.Wait()
	return exit
}

// askTimeout is how long a request waits for a person (HARNESS_ASK_TIMEOUT seconds; 0 or unset: 15 minutes).
func askTimeout(v string) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 15 * time.Minute
}

// signalGroup sends sig to the process group the command leads.
func signalGroup(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd.Process == nil {
		return nil
	}
	return syscall.Kill(-cmd.Process.Pid, sig)
}

// groupKillDelay is how long what is left of an agent's process group has between SIGTERM and SIGKILL.
var groupKillDelay = 10 * time.Second

// endGroup stops whatever is left of the agent's process group once the agent has exited.
func endGroup(cmd *exec.Cmd) {
	if signalGroup(cmd, syscall.SIGTERM) != nil {
		return // nothing left
	}
	delay := groupKillDelay
	go func() {
		time.Sleep(delay)
		_ = signalGroup(cmd, syscall.SIGKILL)
	}()
}

// deliverInstructions puts the agent definition's instructions where the profile says the agent
// reads them (harness.instructions): "file" writes them to $HOME/.sandbox/instructions.md
// (SANDBOX_INSTRUCTIONS_FILE; OpenCode's `instructions` names it), "env:NAME" exports them as NAME
// (Hermes's HERMES_ENVIRONMENT_HINT). delivered is true when they were: the first prompt then
// carries no copy. Empty (the default): the session's system prompt when the agent takes one,
// else a prefix of the first prompt.
func deliverInstructions(env []string, mode, instructions, home string) (out []string, delivered bool, err error) {
	instructions = strings.TrimSpace(instructions)
	switch {
	case mode == "":
		return env, false, nil
	case mode == "file":
		dir := filepath.Join(home, ".sandbox")
		path := filepath.Join(dir, "instructions.md")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return env, false, err
		}
		// Written even when empty: a configuration that names the file must find it.
		if err := os.WriteFile(path, []byte(instructions+"\n"), 0o600); err != nil {
			return env, false, err
		}
		return append(env, "SANDBOX_INSTRUCTIONS_FILE="+path), true, nil
	case strings.HasPrefix(mode, "env:"):
		name := strings.TrimPrefix(mode, "env:")
		if name == "" || model.PlatformEnv(name) {
			return env, false, fmt.Errorf("harness.instructions %q: not a variable the profile may set", mode)
		}
		return append(env, name+"="+instructions), true, nil
	}
	return env, false, fmt.Errorf("harness.instructions %q: file or env:NAME", mode)
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

// acpSteerer sends a message into the turn in progress (acpx.Conn.Steer).
type acpSteerer interface {
	Steer(ctx context.Context, sessionID acp.SessionId, text string) (acpx.SteerOutcome, error)
}

// acpCloser ends a session on the agent's side (session/close).
type acpCloser interface {
	CloseSession(ctx context.Context, params acp.CloseSessionRequest) (acp.CloseSessionResponse, error)
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
	instructions bool   // given natively (system prompt, file, env): no prefix on the first prompt
	agent        string // initialize agentInfo.name
	canClose     bool   // the agent declares sessionCapabilities.close
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
		// or terminal of its own. With permissions ask a person is there: the agent may ask them
		// questions (a form, a sign-in link).
		ClientCapabilities: clientCapabilities(cl.permissions),
	})
	if err != nil {
		notice("acp initialize: %v", err)
		return s, false
	}
	if init.AgentInfo != nil {
		s.agent = init.AgentInfo.Name
	}
	s.canClose = init.AgentCapabilities.SessionCapabilities.Close != nil
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
	// The instructions reach the agent natively when they can: already in its configuration
	// (harness.instructions), else as the session's system prompt when the agent takes one. They
	// then survive the agent compacting its context, which a prefix of the first prompt may not. A
	// system prompt is not part of the session's history, so a loaded or resumed session gets it
	// again.
	instructions := strings.TrimSpace(os.Getenv("SANDBOX_INSTRUCTIONS"))
	switch {
	case instructions == "":
	case cl.instructionsDelivered:
		s.instructions, instructions = true, ""
	case cl.systemPrompt != nil && cl.systemPrompt():
		s.instructions = true
	default:
		instructions = ""
	}
	// harness.session_meta goes with every session request (claude-agent-acp: claudeCode.options).
	profileMeta, err := profileSessionMeta(os.Getenv("HARNESS_SESSION_META"))
	if err != nil {
		notice("%v: not passed", err)
	}
	meta := acpx.SessionMeta(profileMeta, instructions)

	var st acpSessionState
	if run.Session != "" && run.ResumeOf != "" {
		prev := acp.SessionId(run.Session)
		caps := init.AgentCapabilities
		resumer, canResume := conn.(acpResumer)
		if caps.SessionCapabilities.Resume != nil && canResume {
			// session/resume continues without replaying the history.
			r, err := resumer.ResumeSession(ctx, acp.ResumeSessionRequest{Meta: meta, SessionId: prev, Cwd: cwd, McpServers: servers})
			if err == nil {
				s.id, st = prev, acpSessionState{Modes: r.Modes, Options: r.ConfigOptions}
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
				s.id, st = prev, acpSessionState{Modes: r.Modes, Options: r.ConfigOptions}
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
		s.id, s.fresh, st = ns.SessionId, true, acpSessionState{Modes: ns.Modes, Options: ns.ConfigOptions}
	}
	configureACPSession(ctx, conn, s.id, st, acpSettings{mode: os.Getenv("HARNESS_MODE"), model: os.Getenv("SANDBOX_MODEL"),
		thoughtLevel: os.Getenv("HARNESS_THOUGHT_LEVEL")}, notice)
	return s, true
}

// driveACP holds the conversation: the session (openACPSession), then one prompt per message
// until the input is closed (run.close, the idle period) or the run is cancelled. startInput
// starts delivering the user's messages into the sink it is given. The result is the run's exit
// code.
func driveACP(ctx context.Context, conn acpConn, cl *acpClient, run *model.Run, emit func(string), chat *chatState, startInput func(inputSink)) int {
	// The input runs from the start: what the agent asks a person while the session opens (a
	// sign-in link during authentication) is answered, and a cancel reaches it; messages wait in
	// the queue for the first turn to end.
	inputs := newPromptQueue()
	inputs.onReply = cl.reply
	if cl.pending != nil {
		inputs.onClose = cl.pending.Close
	}
	startInput(inputs)
	sess, ok := openACPSession(ctx, conn, cl, run, emit)
	if !ok {
		return 1
	}
	sessionID := sess.id
	emit(harness.ACPLine{Type: harness.ACPSession, SessionID: string(sessionID)}.String())
	notice := noticeFunc(emit)
	usage := newACPUsage(sess.agent, string(sessionID), cl)

	// A message sent while a turn runs joins it when the agent takes steering; otherwise, or when
	// no turn is running after all, it waits for the turn to end and is the next prompt. A slash
	// command always waits: an agent runs its commands from a prompt, steered text is only text.
	// Steering runs beside the input (promptQueue), bounded, so a silent agent cannot hold up a
	// cancel or a close behind it.
	if st, ok := conn.(acpSteerer); ok {
		inputs.setSteer(func(text string) bool {
			if escapeACPPrompt(text, cl.isCommand) == text && strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "/") {
				return false // an advertised command
			}
			if _, files := harness.SplitAttachments(text); len(files) > 0 {
				return false // steering carries text only: files go with a prompt
			}
			sctx, done := context.WithTimeout(ctx, steerTimeout)
			defer done()
			out, err := st.Steer(sctx, sessionID, escapeACPPrompt(text, cl.isCommand))
			switch {
			case err != nil:
				notice("steering: %v: the message waits for the turn to end", err)
				return false
			case out == acpx.SteerInjected:
				notice("the message joined the turn in progress (steering)")
				return true
			case out == acpx.SteerStartedNewTurn:
				notice("the agent started a turn with the message itself (steering)")
				return true
			}
			return false
		})
	}
	instructions := os.Getenv("SANDBOX_INSTRUCTIONS")
	if sess.instructions {
		instructions = "" // the session's system prompt has them
	}
	prompt := firstPrompt(run, sess.fresh, instructions, os.Getenv("SANDBOX_RESUME_PROMPT"), cl.isCommand)
	for {
		inputs.setTurn(true)
		resp, err := promptACP(ctx, conn, cl, sessionID, prompt, notice)
		inputs.setTurn(false)
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
			closeACPSession(conn, sess, notice)
			return 0
		}
		// A message that waited for this turn is a new turn: the idle clock stops until it ends.
		chat.sent()
		prompt = escapeACPPrompt(next, cl.isCommand)
	}
}

// closeACPSession ends the conversation's session on the agent's side when it declares
// session/close: the agent frees what it holds for it and writes its state before the process
// ends. The session stays continuable (resume, load).
func closeACPSession(conn acpConn, sess acpOpened, notice func(string, ...any)) {
	cl, ok := conn.(acpCloser)
	if !sess.canClose || !ok {
		return
	}
	ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if _, err := cl.CloseSession(ctx, acp.CloseSessionRequest{SessionId: sess.id}); err != nil {
		notice("acp session/close: %v", err)
	}
}

// steerTimeout bounds how long the agent has to answer a steering request; a message it did not
// take in that time waits for the turn to end.
var steerTimeout = 30 * time.Second

// promptACP sends one prompt. Hermes refuses every prompt of a session whose previous turn was
// lost when its gateway restarted (unknown_execution) until the lost turn is discarded with
// `/discard <id>`: the runner discards the turns it names and sends the prompt once more.
func promptACP(ctx context.Context, conn acpConn, cl *acpClient, sid acp.SessionId, text string, notice func(string, ...any)) (acp.PromptResponse, error) {
	// The files a message attached (listed after its text by the control plane) go as resource
	// links: the agent sees them as files.
	body, files := harness.SplitAttachments(text)
	resp, err := conn.Prompt(ctx, acp.PromptRequest{SessionId: sid, Prompt: acpx.PromptBlocks(body, files)})
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
	return conn.Prompt(ctx, acp.PromptRequest{SessionId: sid, Prompt: acpx.PromptBlocks(body, files)})
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

// escapeACPPrompt keeps a message that starts with "/" from being taken for a slash command the
// agent does not have (OpenCode ends the turn empty on an unknown one). A command the agent
// advertised (available_commands_update: /compact, /review…) passes as it is. The agents trim
// whitespace before they look, so the escape is a zero-width space, which they do not trim and
// the model reads past.
func escapeACPPrompt(text string, isCommand func(string) bool) string {
	// The command is the text's, not the attached files' list after it.
	if body, files := harness.SplitAttachments(text); len(files) > 0 {
		return harness.WithAttachments(escapeACPPrompt(body, isCommand), files)
	}
	t := strings.TrimLeft(text, " \t\r\n")
	if !strings.HasPrefix(t, "/") {
		return text
	}
	if name, _, _ := strings.Cut(strings.TrimPrefix(t, "/"), " "); isCommand != nil && name != "" && isCommand(strings.TrimSpace(name)) {
		return text
	}
	return "\u200b" + text
}

// firstPrompt is the text of the run's first prompt. For an agent that takes no system prompt
// (sessionCapabilities.systemPrompt), a new session starts with the agent definition's
// instructions ahead of the task; a loaded one already has them. A run that resumes an interrupted one (a rollout) continues it.
func firstPrompt(run *model.Run, fresh bool, instructions, resumePrompt string, isCommand func(string) bool) string {
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
	task = escapeACPPrompt(task, isCommand)
	if fresh && strings.TrimSpace(instructions) != "" {
		return "<instructions>\n" + strings.TrimSpace(instructions) + "\n</instructions>\n\n" + task
	}
	return task
}

// clientCapabilities is what the runner offers the agent: elicitation when a person answers.
func clientCapabilities(permissions string) acp.ClientCapabilities {
	if permissions != harness.PermissionsAsk {
		return acp.ClientCapabilities{}
	}
	return acp.ClientCapabilities{Elicitation: &acp.ElicitationCapabilities{
		Form: &acp.ElicitationFormCapabilities{}, Url: &acp.ElicitationUrlCapabilities{}}}
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
	inTurn bool // a prompt is in flight
	// steer, when set, offers a message that arrives during a turn to that turn; true: it was
	// taken and does not wait. It runs on a worker of its own, never on the sender's goroutine:
	// the sender (forwardInput) must stay free to take a cancel or a close.
	steer     func(text string) bool
	steering  []string // messages waiting for the worker, in order
	steerBusy bool     // the worker is running
	// onReply takes a person's answer to a request of the agent (a reply input event).
	onReply func(data string)
	// onClose runs when the input closes: what waits on a person is given up.
	onClose func()
}

// setSteer sets the steering function (once the session is open).
func (q *promptQueue) setSteer(f func(text string) bool) {
	q.mu.Lock()
	q.steer = f
	q.mu.Unlock()
}

// Reply hands a reply input event to the conversation (forwardInput).
func (q *promptQueue) Reply(data string) error {
	if q.onReply != nil {
		q.onReply(data)
	}
	return nil
}

func newPromptQueue() *promptQueue { return &promptQueue{wake: make(chan struct{}, 1)} }

// setTurn records whether a prompt is in flight.
func (q *promptQueue) setTurn(v bool) {
	q.mu.Lock()
	q.inTurn = v
	q.mu.Unlock()
}

// Send takes a message and returns at once. During a turn (and behind messages still being
// steered) it goes to the steering worker; otherwise, or when the worker cannot place it in the
// turn, it waits for the next prompt. Order is kept either way.
func (q *promptQueue) Send(text string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return errors.New("conversation closed")
	}
	if q.steer != nil && (q.steerBusy || q.inTurn && len(q.queue) == 0) {
		q.steering = append(q.steering, text)
		if !q.steerBusy {
			q.steerBusy = true
			go q.steerAll()
		}
		return nil
	}
	q.queue = append(q.queue, text)
	q.signal()
	return nil
}

// steerAll offers the waiting messages to the turn in progress, one by one; one not taken (no
// turn any more, the agent declined or did not answer) goes to the prompt queue, and so does every
// one after it, so they keep their order.
func (q *promptQueue) steerAll() {
	failed := false
	for {
		q.mu.Lock()
		if len(q.steering) == 0 {
			q.steerBusy = false
			q.signal()
			q.mu.Unlock()
			return
		}
		text := q.steering[0]
		q.steering = q.steering[1:]
		inTurn := q.inTurn
		q.mu.Unlock()
		if !failed && inTurn && q.steer(text) {
			continue
		}
		failed = true
		q.mu.Lock()
		q.queue = append(q.queue, text)
		q.signal()
		q.mu.Unlock()
	}
}

func (q *promptQueue) Close() error {
	q.mu.Lock()
	q.closed = true
	q.signal()
	onClose := q.onClose
	q.mu.Unlock()
	if onClose != nil {
		onClose()
	}
	return nil
}

func (q *promptQueue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// next waits for the next message; ok is false once the input is closed and drained (nothing
// queued, nothing still being steered), or the run is cancelled.
func (q *promptQueue) next(ctx context.Context) (string, bool) {
	for {
		q.mu.Lock()
		if len(q.queue) > 0 {
			t := q.queue[0]
			q.queue = q.queue[1:]
			q.mu.Unlock()
			return t, true
		}
		done := q.closed && !q.steerBusy
		q.mu.Unlock()
		if done {
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
	// systemPrompt reports whether the agent takes the client's system prompt (acpx.Wire); nil:
	// it does not.
	systemPrompt func() bool
	// instructionsDelivered: the instructions are in the agent's own configuration
	// (harness.instructions), not to be sent again.
	instructionsDelivered bool
	// wire tells the SDK's updates from those it does not know (notices, compactions); nil: every
	// update is the SDK's.
	wire *acpx.Wire
	// pending holds the requests waiting for a person (permissions ask), askTimeout how long.
	pending    *acpx.Pending
	askTimeout time.Duration
	// lastCommands is the list of commands last written (acp.commands is written when it changes).
	lastCommands string
	// usageDir keeps the last cumulative usage of the sessions of an agent that reports one
	// (acpUsage); "" keeps it in memory only.
	usageDir string

	mu        sync.Mutex
	msg       strings.Builder             // the agent message being streamed in chunks
	thought   strings.Builder             // the agent's reasoning being streamed in chunks
	replaying bool                        // session/load: history the transcript already has
	commands  map[string]bool             // the slash commands the agent advertised
	summaries map[string]*strings.Builder // compaction summaries being streamed, by compaction id
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
	if strings.TrimSpace(a.thought.String()) != "" {
		a.emit(harness.ACPLine{Type: harness.ACPThought, Text: a.thought.String()}.String())
	}
	a.thought.Reset()
	if strings.TrimSpace(a.msg.String()) != "" {
		a.emit(harness.ACPLine{Type: harness.ACPMessage, Text: a.msg.String()}.String())
	}
	a.msg.Reset()
}

// isCommand reports whether the agent advertised the slash command name.
func (a *acpClient) isCommand(name string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.commands[name]
}

// extraUpdate writes the updates the SDK cannot decode (acpx.Wire): notices and compactions.
func (a *acpClient) extraUpdate(u acpx.ExtraUpdate) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.extraUpdateLocked(u)
}

func (a *acpClient) extraUpdateLocked(u acpx.ExtraUpdate) {
	if a.replaying {
		return
	}
	switch {
	case u.Notice != nil:
		// Not a break in the agent's message: one being streamed goes on and is written whole.
		a.emit(harness.ACPLine{Type: harness.ACPNotice, Severity: u.Notice.Severity, Title: u.Notice.Title, Text: u.Notice.Description}.String())
	case u.SummaryChunk != nil:
		if a.summaries == nil {
			a.summaries = map[string]*strings.Builder{}
		}
		b := a.summaries[u.SummaryChunk.ID]
		if b == nil {
			b = &strings.Builder{}
			a.summaries[u.SummaryChunk.ID] = b
		}
		if b.Len() < maxACPDiffText {
			b.WriteString(u.SummaryChunk.Text)
		}
	case u.Compaction != nil:
		c := u.Compaction
		l := harness.ACPLine{Type: harness.ACPCompaction, CompactionID: c.ID, Status: c.Status, Error: c.Error, Text: c.Summary}
		if c.Status != "in_progress" {
			if b := a.summaries[c.ID]; b != nil && l.Text == "" {
				l.Text = b.String()
			}
			delete(a.summaries, c.ID)
		}
		a.emit(l.String())
	}
}

func (a *acpClient) SessionUpdate(_ context.Context, n acp.SessionNotification) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u := n.Update
	// An update the SDK does not know reaches here as another kind's (a notice as a
	// session_info_update): what it really is, the wire knows, in this same order.
	if a.wire != nil {
		if extra, sdk := a.wire.Classify(u); !sdk {
			if extra != nil {
				a.extraUpdateLocked(*extra)
			}
			return nil
		}
	}
	// A cost reported while a load replays the history is the session's total so far: kept (the
	// run's usage counts from it), not written.
	if u.UsageUpdate != nil {
		if c := u.UsageUpdate.Cost; c != nil && (c.Currency == "" || strings.EqualFold(c.Currency, "USD")) {
			a.cost, a.costSeen = c.Amount, true
		}
		return nil
	}
	// The agent's commands are state, whenever they come (a load announces them too).
	if u.AvailableCommandsUpdate != nil {
		a.commands = map[string]bool{}
		l := harness.ACPLine{Type: harness.ACPCommands, Commands: []harness.ACPCommand{}}
		for _, c := range u.AvailableCommandsUpdate.AvailableCommands {
			a.commands[c.Name] = true
			cmd := harness.ACPCommand{Name: c.Name, Description: c.Description}
			if c.Input != nil && c.Input.Unstructured != nil {
				cmd.Hint = c.Input.Unstructured.Hint
			}
			l.Commands = append(l.Commands, cmd)
		}
		// A client lists them for its user (role commands); written when the list changes.
		if line := l.String(); line != a.lastCommands {
			a.lastCommands = line
			a.emit(line)
		}
		return nil
	}
	if a.replaying {
		return nil
	}
	switch {
	case u.AgentMessageChunk != nil:
		if a.thought.Len() > 0 {
			a.flushLocked() // the reasoning before this message is complete
		}
		if t := u.AgentMessageChunk.Content.Text; t != nil {
			a.msg.WriteString(t.Text)
		}
	case u.AgentThoughtChunk != nil:
		if a.msg.Len() > 0 {
			a.flushLocked()
		}
		if t := u.AgentThoughtChunk.Content.Text; t != nil {
			a.thought.WriteString(t.Text)
		}
	case u.Plan != nil:
		a.flushLocked()
		l := harness.ACPLine{Type: harness.ACPPlan, Entries: []harness.ACPPlanEntry{}}
		for _, e := range u.Plan.Entries {
			l.Entries = append(l.Entries, harness.ACPPlanEntry{Content: e.Content, Status: string(e.Status), Priority: string(e.Priority)})
		}
		a.emit(l.String())
	case u.SessionInfoUpdate != nil:
		if t := u.SessionInfoUpdate.Title; t != nil && *t != "" {
			a.emit(harness.ACPLine{Type: harness.ACPSessionInfo, Title: *t}.String())
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

// RequestPermission answers the agent's permission request by the profile's policy: allow picks
// the agent's allow_once (else allow_always) option, deny its reject_once (else reject_always);
// with no matching option the request is cancelled, which the agent treats as a refusal. With
// ask a person answers (askPerson). Every request and its decision are recorded.
func (a *acpClient) RequestPermission(ctx context.Context, p acp.RequestPermissionRequest) (acp.RequestPermissionResponse, error) {
	l := harness.ACPLine{Type: harness.ACPPermission, ToolCallID: string(p.ToolCall.ToolCallId), Decision: "cancelled"}
	if p.ToolCall.Title != nil {
		l.Title = *p.ToolCall.Title
	}
	diffs := acpDiffs(p.ToolCall.Content)
	if a.permissions == harness.PermissionsAsk {
		return a.askPermission(ctx, p, l, diffs)
	}
	want := []acp.PermissionOptionKind{acp.PermissionOptionKindAllowOnce, acp.PermissionOptionKindAllowAlways}
	if a.permissions == harness.PermissionsDeny {
		want = []acp.PermissionOptionKind{acp.PermissionOptionKindRejectOnce, acp.PermissionOptionKindRejectAlways}
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
	a.withDiffsLocked(&l, diffs)
	// Requests are dispatched independently of ordered session notifications.
	// A permission callback may overtake text chunks, so only the notification
	// stream and the prompt response may flush the pending assistant message.
	a.emit(l.String())
	a.mu.Unlock()
	return out, nil
}

// askPermission puts the request to a person: an acp.request line (the agent's options and the
// change's diff) the control plane shows, then the answer the person sends
// (POST /requests/{id} → a reply input event → reply), within the ask timeout. Unanswered, or
// answered with something the request did not offer, it is refused (cancelled outcome). The
// decision is recorded as an acp.permission line and the resolution as acp.request_resolved.
func (a *acpClient) askPermission(ctx context.Context, p acp.RequestPermissionRequest, l harness.ACPLine, diffs []harness.ACPDiff) (acp.RequestPermissionResponse, error) {
	req := a.pending.Open(acpx.PermissionRequest(p))
	rl := harness.ACPLine{Type: harness.ACPRequest, Request: &req, ToolCallID: req.ToolCallID}
	a.mu.Lock()
	// The request shows the whole change it is about: its own diffs, else the ones the tool
	// call carried before (Codex sends them with the call). The diff lines keep their own rules.
	snapshot := diffs
	if len(snapshot) == 0 {
		snapshot = a.diffs[req.ToolCallID]
	}
	a.withDiffsLocked(&harness.ACPLine{ToolCallID: req.ToolCallID}, diffs)
	rl.Diffs = snapshot
	a.emit(boundRequestLine(rl))
	a.mu.Unlock()

	reply, by := a.awaitReply(ctx, req.ID)
	resp := acp.RequestPermissionResponse{Outcome: acp.RequestPermissionOutcome{Cancelled: &acp.RequestPermissionOutcomeCancelled{}}}
	outcome := "cancelled"
	if by == "user" {
		var err error
		if resp, outcome, err = acpx.PermissionResponse(req, reply); err != nil {
			by = "invalid"
			a.notice("request %s: %v: refused", req.ID, err)
		}
	}
	l.Decision = outcome
	a.mu.Lock()
	a.emit(l.String())
	a.emit(harness.ACPLine{Type: harness.ACPResolved, RequestID: req.ID, Outcome: outcome, By: by}.String())
	a.mu.Unlock()
	return resp, nil
}

// maxRequestLine bounds an acp.request line well under the output's line limit: a request a
// person cannot see cannot be answered. Larger details are cut (diff texts first, then the
// tool's input and text), never the request itself.
const maxRequestLine = 512 << 10

func boundRequestLine(l harness.ACPLine) string {
	line := l.String()
	if len(line) <= maxRequestLine {
		return line
	}
	diffs := make([]harness.ACPDiff, len(l.Diffs))
	for i, d := range l.Diffs {
		d.OldText, d.NewText, d.Truncated = nil, "", true
		diffs[i] = d
	}
	l.Diffs = diffs
	if line = l.String(); len(line) <= maxRequestLine {
		return line
	}
	r := *l.Request
	r.RawInput, r.Text = nil, truncate(r.Text, 4<<10)
	l.Request = &r
	if line = l.String(); len(line) <= maxRequestLine {
		return line
	}
	l.Diffs = nil
	return l.String()
}

// awaitReply waits for a person's reply to an open request; by is "user", or "timeout" / "cancelled"
// when none came.
func (a *acpClient) awaitReply(ctx context.Context, id string) (acpx.Reply, string) {
	reply, ok := a.pending.Wait(ctx, id, a.askTimeout)
	switch {
	case ok:
		return reply, "user"
	case ctx.Err() != nil:
		return reply, "cancelled"
	case a.pending.Closed():
		return reply, "closed" // the conversation was closed while it waited
	}
	return reply, "timeout"
}

// UnstableCreateElicitation puts the agent's question to a person (permissions ask, which is when
// the runner advertises elicitation): a form (AskUserQuestion, an MCP server's form) or a link
// (an MCP server's OAuth sign-in). The answer is checked against the form; unanswered, or not
// fitting, the question is cancelled.
func (a *acpClient) UnstableCreateElicitation(ctx context.Context, p acp.UnstableCreateElicitationRequest) (acp.UnstableCreateElicitationResponse, error) {
	if a.permissions != harness.PermissionsAsk || a.pending == nil {
		return acpx.CancelledElicitation(), nil // nobody to ask (not advertised either)
	}
	r, err := acpx.ElicitationRequest(p)
	if err != nil {
		return acpx.CancelledElicitation(), nil
	}
	req := a.pending.Open(r)
	a.mu.Lock()
	// Requests come apart from the ordered notifications: a message being streamed is not cut here.
	a.emit(boundRequestLine(harness.ACPLine{Type: harness.ACPRequest, Request: &req}))
	a.mu.Unlock()

	reply, by := a.awaitReply(ctx, req.ID)
	resp, outcome := acpx.CancelledElicitation(), "cancelled"
	if by == "user" {
		if resp, err = acpx.ElicitationResponse(req, reply); err != nil {
			by = "invalid"
			a.notice("request %s: %v: cancelled", req.ID, err)
		} else {
			outcome = reply.Action
		}
	}
	a.mu.Lock()
	a.emit(harness.ACPLine{Type: harness.ACPResolved, RequestID: req.ID, Outcome: outcome, By: by}.String())
	a.mu.Unlock()
	return resp, nil
}

// UnstableCompleteElicitation: the agent says a link question was completed on its side (the
// sign-in finished). A question still waiting for the person's consent is answered by it.
func (a *acpClient) UnstableCompleteElicitation(_ context.Context, n acp.UnstableCompleteElicitationNotification) error {
	if a.pending == nil {
		return nil
	}
	if id, ok := a.pending.ResolveElicitation(string(n.ElicitationId)); ok {
		a.notice("request %s: the agent reports the interaction complete", id)
	}
	return nil
}

// reply hands a person's answer (a reply input event: acpx.Reply JSON) to the request it names.
// One that names no request waiting (answered already, timed out) is recorded and dropped.
func (a *acpClient) reply(data string) {
	var r acpx.Reply
	if err := json.Unmarshal([]byte(data), &r); err != nil {
		a.notice("reply: %v", err)
		return
	}
	if a.pending == nil {
		return
	}
	if err := a.pending.Resolve(r); err != nil {
		a.mu.Lock()
		a.emit(harness.ACPLine{Type: harness.ACPResolved, RequestID: r.RequestID, Outcome: "not_waiting", By: "user"}.String())
		a.mu.Unlock()
	}
}

func (a *acpClient) notice(format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.emit("[agent-runner] " + fmt.Sprintf(format, args...))
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
