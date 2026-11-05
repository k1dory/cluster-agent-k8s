package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
)

// The test binary doubles as a scripted ACP agent: run with ACP_FAKE_AGENT=1 it speaks ACP on
// its stdio instead of running tests, and logs what it was asked to ACP_FAKE_LOG.
func TestMain(m *testing.M) {
	if os.Getenv("ACP_FAKE_AGENT") == "1" {
		runFakeAgent()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type fakeAgent struct {
	conn *acp.AgentSideConnection
	log  *os.File
	mu   sync.Mutex
}

func (f *fakeAgent) record(kind string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"kind": kind, "v": v})
	_, _ = f.log.Write(append(b, '\n'))
}

func runFakeAgent() {
	log, err := os.OpenFile(os.Getenv("ACP_FAKE_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(3)
	}
	f := &fakeAgent{log: log}
	f.conn = acp.NewAgentSideConnection(f, os.Stdout, os.Stdin)
	<-f.conn.Done()
}

func (f *fakeAgent) Initialize(context.Context, acp.InitializeRequest) (acp.InitializeResponse, error) {
	return acp.InitializeResponse{ProtocolVersion: acp.ProtocolVersionNumber, AgentCapabilities: acp.AgentCapabilities{
		LoadSession: true, McpCapabilities: acp.McpCapabilities{Http: true}}}, nil
}

func (f *fakeAgent) NewSession(_ context.Context, p acp.NewSessionRequest) (acp.NewSessionResponse, error) {
	f.record("new", p)
	return acp.NewSessionResponse{SessionId: "sess_new"}, nil
}

func (f *fakeAgent) LoadSession(ctx context.Context, p acp.LoadSessionRequest) (acp.LoadSessionResponse, error) {
	f.record("load", p)
	// History is replayed as updates before the response.
	_ = f.conn.SessionUpdate(ctx, acp.SessionNotification{SessionId: p.SessionId, Update: acp.UpdateAgentMessageText("OLD HISTORY")})
	return acp.LoadSessionResponse{}, nil
}

func (f *fakeAgent) Prompt(ctx context.Context, p acp.PromptRequest) (acp.PromptResponse, error) {
	text := ""
	for _, b := range p.Prompt {
		if b.Text != nil {
			text += b.Text.Text
		}
	}
	f.record("prompt", map[string]string{"session": string(p.SessionId), "text": text})
	send := func(u acp.SessionUpdate) {
		_ = f.conn.SessionUpdate(ctx, acp.SessionNotification{SessionId: p.SessionId, Update: u})
	}
	send(acp.UpdateAgentMessageText("Hel"))
	send(acp.UpdateAgentMessageText("lo"))
	send(acp.StartToolCall("call_1", "Edit a.txt", acp.WithStartKind(acp.ToolKindEdit), acp.WithStartStatus(acp.ToolCallStatusPending),
		acp.WithStartContent([]acp.ToolCallContent{acp.ToolDiffContent("/workspace/a.txt", "new line", "old line")})))
	title := "Edit a.txt"
	resp, err := f.conn.RequestPermission(ctx, acp.RequestPermissionRequest{SessionId: p.SessionId,
		ToolCall: acp.ToolCallUpdate{ToolCallId: "call_1", Title: &title},
		Options: []acp.PermissionOption{
			{OptionId: "yes", Name: "Allow", Kind: acp.PermissionOptionKindAllowOnce},
			{OptionId: "no", Name: "Reject", Kind: acp.PermissionOptionKindRejectOnce},
		}})
	chosen := "error"
	if err == nil && resp.Outcome.Selected != nil {
		chosen = string(resp.Outcome.Selected.OptionId)
	} else if err == nil && resp.Outcome.Cancelled != nil {
		chosen = "cancelled"
	}
	f.record("permission", chosen)
	send(acp.UpdateToolCall("call_1", acp.WithUpdateStatus(acp.ToolCallStatusCompleted)))
	send(acp.UpdateAgentMessageText("done: " + text))
	return acp.PromptResponse{StopReason: acp.StopReasonEndTurn, Usage: &acp.Usage{InputTokens: 10, OutputTokens: 5, TotalTokens: 15}}, nil
}

func (f *fakeAgent) Cancel(context.Context, acp.CancelNotification) error { return nil }
func (f *fakeAgent) Authenticate(context.Context, acp.AuthenticateRequest) (acp.AuthenticateResponse, error) {
	return acp.AuthenticateResponse{}, nil
}
func (f *fakeAgent) Logout(context.Context, acp.LogoutRequest) (acp.LogoutResponse, error) {
	return acp.LogoutResponse{}, nil
}
func (f *fakeAgent) CloseSession(context.Context, acp.CloseSessionRequest) (acp.CloseSessionResponse, error) {
	return acp.CloseSessionResponse{}, nil
}
func (f *fakeAgent) ListSessions(context.Context, acp.ListSessionsRequest) (acp.ListSessionsResponse, error) {
	return acp.ListSessionsResponse{}, nil
}
func (f *fakeAgent) ResumeSession(context.Context, acp.ResumeSessionRequest) (acp.ResumeSessionResponse, error) {
	return acp.ResumeSessionResponse{}, nil
}
func (f *fakeAgent) SetSessionConfigOption(context.Context, acp.SetSessionConfigOptionRequest) (acp.SetSessionConfigOptionResponse, error) {
	return acp.SetSessionConfigOptionResponse{}, nil
}
func (f *fakeAgent) SetSessionMode(context.Context, acp.SetSessionModeRequest) (acp.SetSessionModeResponse, error) {
	return acp.SetSessionModeResponse{}, nil
}

// fakeControlPlane records the run's output and plays the user: after the first turn it sends
// one message, after the second it closes the conversation.
type fakeControlPlane struct {
	mu    sync.Mutex
	lines []string
	sent  int
}

func (cp *fakeControlPlane) turns() int {
	n := 0
	for _, l := range cp.lines {
		if harness.IsTurnEnd(l) {
			n++
		}
	}
	return n
}

func (cp *fakeControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/events"):
		b, _ := io.ReadAll(r.Body)
		cp.mu.Lock()
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			cp.lines = append(cp.lines, l)
		}
		cp.mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/input"):
		cp.mu.Lock()
		turns, sent := cp.turns(), cp.sent
		var evs []model.Event
		switch {
		case turns >= 1 && sent == 0:
			evs = []model.Event{{ID: 1, Type: model.EventInput, Data: "second message"}}
			cp.sent = 1
		case turns >= 2 && sent == 1:
			evs = []model.Event{{ID: 2, Type: model.EventRunClose}}
			cp.sent = 2
		}
		cp.mu.Unlock()
		if evs == nil {
			select {
			case <-r.Context().Done():
			case <-time.After(50 * time.Millisecond):
			}
			evs = []model.Event{}
		}
		_ = json.NewEncoder(w).Encode(evs)
	default:
		_, _ = w.Write([]byte("[]"))
	}
}

func setupACP(t *testing.T, permissions string) (agentLog string, cp *fakeControlPlane, cl *client) {
	t.Helper()
	root := t.TempDir()
	agentLog = root + "/agent.log"
	t.Setenv("HOME", root)
	t.Setenv("PWD", root)
	t.Setenv("SANDBOX_REPO_DIR", root+"/no-repo")
	t.Setenv("HARNESS_INPUT", harness.InputACP)
	t.Setenv("HARNESS_PERMISSIONS", permissions)
	t.Setenv("HARNESS_CMD", `exec "`+os.Args[0]+`"`)
	t.Setenv("ACP_FAKE_AGENT", "1")
	t.Setenv("ACP_FAKE_LOG", agentLog)
	t.Setenv("SANDBOX_INSTRUCTIONS", "Triage by the book.")
	t.Setenv("SANDBOX_MCP_SERVERS", `[{"name":"argus","url":"https://argus-mcp.asb.internal/"}]`)
	t.Setenv("SANDBOX_HARNESS_FILES", "")
	cp = &fakeControlPlane{}
	srv := httptest.NewServer(cp)
	t.Cleanup(srv.Close)
	return agentLog, cp, &client{base: srv.URL, http: srv.Client()}
}

type agentRecord struct {
	Kind string          `json:"kind"`
	V    json.RawMessage `json:"v"`
}

func readAgentLog(t *testing.T, path string) []agentRecord {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []agentRecord
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r agentRecord
		if json.Unmarshal([]byte(l), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

func runACP(t *testing.T, cl *client, run *model.Run) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- execute(ctx, cl, run) }()
	select {
	case code := <-done:
		return code
	case <-time.After(15 * time.Second):
		t.Fatal("the ACP run did not finish")
		return -1
	}
}

// A conversation over ACP: a new session gets the instructions and the sandbox's MCP servers,
// the agent's chunks become one message, its tool call keeps its diff, its permission request is
// answered by the profile's policy and recorded, a follow-up message is the next prompt of the
// same session, and the transcript, session and usage read from the output.
func TestACPConversation(t *testing.T) {
	agentLog, cp, cl := setupACP(t, "")
	if code := runACP(t, cl, &model.Run{ID: "run_acp", Task: "triage INC-1"}); code != 0 {
		t.Fatalf("exit %d; output:\n%s", code, strings.Join(cp.lines, "\n"))
	}

	recs := readAgentLog(t, agentLog)
	var prompts []map[string]string
	var newSession acp.NewSessionRequest
	var permissions []string
	for _, r := range recs {
		switch r.Kind {
		case "new":
			_ = json.Unmarshal(r.V, &newSession)
		case "prompt":
			var p map[string]string
			_ = json.Unmarshal(r.V, &p)
			prompts = append(prompts, p)
		case "permission":
			var s string
			_ = json.Unmarshal(r.V, &s)
			permissions = append(permissions, s)
		case "load":
			t.Fatal("a new conversation must not load a session")
		}
	}
	if len(newSession.McpServers) != 1 || newSession.McpServers[0].Http == nil || newSession.McpServers[0].Http.Url != "https://argus-mcp.asb.internal/" {
		t.Fatalf("session/new MCP servers: %+v", newSession.McpServers)
	}
	if len(prompts) != 2 {
		t.Fatalf("prompts: %+v", prompts)
	}
	if !strings.Contains(prompts[0]["text"], "Triage by the book.") || !strings.HasSuffix(prompts[0]["text"], "triage INC-1") {
		t.Fatalf("first prompt must carry the instructions, then the task: %q", prompts[0]["text"])
	}
	if prompts[1]["text"] != "second message" || prompts[1]["session"] != "sess_new" {
		t.Fatalf("the follow-up must be the next prompt of the same session: %+v", prompts[1])
	}
	if strings.Join(permissions, ",") != "yes,yes" {
		t.Fatalf("permissions answered: %v (want the allow option by default)", permissions)
	}

	var roles []string
	var session string
	var usage model.Usage
	var sawDiff, sawDecision bool
	for _, l := range cp.lines {
		if role, text := harness.ParseMessage(l); role != "" {
			roles = append(roles, role+":"+text)
		}
		if s, ok := harness.ParseSession(l); ok {
			session = s
		}
		if u, _, ok := harness.ParseUsage(l); ok {
			usage.Add(u)
		}
		if strings.Contains(l, `"acp.tool_call"`) && strings.Contains(l, `"path":"/workspace/a.txt"`) && strings.Contains(l, `"old_text":"old line"`) {
			sawDiff = true
		}
		if strings.Contains(l, `"acp.permission"`) && strings.Contains(l, `"decision":"allow_once"`) {
			sawDecision = true
		}
	}
	want := []string{"assistant:Hello", "tool:Edit a.txt", "assistant:done: ", "assistant:Hello", "tool:Edit a.txt", "assistant:done: second message"}
	if len(roles) != len(want) || roles[0] != want[0] || roles[1] != want[1] || !strings.HasPrefix(roles[2], want[2]) || roles[5] != want[5] {
		t.Fatalf("transcript: %q", roles)
	}
	if session != "sess_new" {
		t.Fatalf("session id from the output: %q", session)
	}
	if usage.InputTokens != 20 || usage.OutputTokens != 10 || usage.Turns != 2 {
		t.Fatalf("usage over two turns: %+v", usage)
	}
	if !sawDiff || !sawDecision {
		t.Fatalf("diff recorded %v, permission decision recorded %v; output:\n%s", sawDiff, sawDecision, strings.Join(cp.lines, "\n"))
	}
}

// The next message of a finished conversation loads its session: the replayed history is not
// output again and the message is the prompt, without the instructions the session already has.
func TestACPResumeLoadsTheSession(t *testing.T) {
	agentLog, cp, cl := setupACP(t, "")
	run := &model.Run{ID: "run_acp2", Task: "and the next one?", ResumeOf: "run_acp", Session: "sess_old", Mode: model.RunMessage}
	if code := runACP(t, cl, run); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var loaded acp.LoadSessionRequest
	var first map[string]string
	for _, r := range readAgentLog(t, agentLog) {
		switch r.Kind {
		case "load":
			_ = json.Unmarshal(r.V, &loaded)
		case "new":
			t.Fatal("a resumed conversation must load its session, not start a new one")
		case "prompt":
			if first == nil {
				_ = json.Unmarshal(r.V, &first)
			}
		}
	}
	if loaded.SessionId != "sess_old" || len(loaded.McpServers) != 1 {
		t.Fatalf("session/load: %+v", loaded)
	}
	if first["text"] != "and the next one?" || first["session"] != "sess_old" {
		t.Fatalf("first prompt of the resumed run: %+v", first)
	}
	for _, l := range cp.lines {
		if strings.Contains(l, "OLD HISTORY") {
			t.Fatal("the history session/load replays must not reach the transcript again")
		}
	}
}

// permissions: deny answers with the agent's reject option.
func TestACPPermissionsDeny(t *testing.T) {
	agentLog, cp, cl := setupACP(t, harness.PermissionsDeny)
	if code := runACP(t, cl, &model.Run{ID: "run_acp3", Task: "edit"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, r := range readAgentLog(t, agentLog) {
		if r.Kind == "permission" && string(r.V) != `"no"` {
			t.Fatalf("deny policy chose %s", r.V)
		}
	}
	found := false
	for _, l := range cp.lines {
		found = found || strings.Contains(l, `"decision":"reject_once"`)
	}
	if !found {
		t.Fatal("the refusal must be recorded in the output")
	}
}

func TestFirstPrompt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		run   model.Run
		fresh bool
		want  string
	}{
		{"new", model.Run{Task: "t"}, true, "<instructions>\nI\n</instructions>\n\nt"},
		{"message, loaded", model.Run{Task: "m", ResumeOf: "r", Mode: model.RunMessage}, false, "m"},
		{"rollout, loaded", model.Run{Task: "t", ResumeOf: "r", Mode: model.RunResume}, false, "carry on"},
		{"rollout, session lost", model.Run{Task: "t", ResumeOf: "r", Mode: model.RunResume}, true, "<instructions>\nI\n</instructions>\n\nt"},
	} {
		if got := firstPrompt(&tc.run, tc.fresh, "I", "carry on"); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A real ACP adapter (ACP_REAL_AGENT=<command>, e.g. the codex-acp of the agent image) opens a
// session through the runner with the profile's authentication method (ACP_REAL_AUTH_METHOD,
// sent as ACP authenticate). The run is stopped as soon as the session is reported; the model
// endpoint points at a closed local port, so nothing leaves the machine. Skipped unless asked for.
func TestACPRealAdapterOpensASession(t *testing.T) {
	agent := os.Getenv("ACP_REAL_AGENT")
	if agent == "" {
		t.Skip("ACP_REAL_AGENT not set")
	}
	_, cp, cl := setupACP(t, "")
	t.Setenv("ACP_FAKE_AGENT", "")
	t.Setenv("HARNESS_CMD", agent)
	t.Setenv("HARNESS_AUTH_METHOD", os.Getenv("ACP_REAL_AUTH_METHOD"))
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("OPENAI_BASE_URL", "http://127.0.0.1:9/v1")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- execute(ctx, cl, &model.Run{ID: "run_real", Task: "reply with the word ok"}) }()
	deadline := time.After(30 * time.Second)
	for {
		cp.mu.Lock()
		var session string
		for _, l := range cp.lines {
			if s, ok := harness.ParseSession(l); ok {
				session = s
			}
		}
		out := strings.Join(cp.lines, "\n")
		cp.mu.Unlock()
		if session != "" {
			cancel()
			<-done
			return
		}
		select {
		case <-done:
			t.Fatalf("the run ended without a session; output:\n%s", out)
		case <-deadline:
			t.Fatalf("no session in 30s; output:\n%s", out)
		case <-time.After(100 * time.Millisecond):
		}
	}
}
