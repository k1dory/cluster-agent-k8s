package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	acp "github.com/coder/acp-go-sdk"
	"github.com/k1dory/acpx"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
)

// askClient is a runner client with permissions ask whose output the test reads line by line.
func askClient(timeout time.Duration) (*acpClient, func() []harness.ACPLine) {
	var mu sync.Mutex
	var lines []string
	cl := &acpClient{permissions: harness.PermissionsAsk, pending: acpx.NewPending(), askTimeout: timeout,
		emit: func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() }}
	return cl, func() []harness.ACPLine {
		mu.Lock()
		defer mu.Unlock()
		var out []harness.ACPLine
		for _, l := range lines {
			var v harness.ACPLine
			if json.Unmarshal([]byte(l), &v) == nil && v.Type != "" {
				out = append(out, v)
			} else {
				out = append(out, harness.ACPLine{Type: "notice", Text: l})
			}
		}
		return out
	}
}

// waitRequest waits for the acp.request line and returns it.
func waitRequest(t *testing.T, lines func() []harness.ACPLine) harness.ACPLine {
	t.Helper()
	for i := 0; i < 200; i++ {
		for _, l := range lines() {
			if l.Type == harness.ACPRequest {
				return l
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no acp.request: %+v", lines())
	return harness.ACPLine{}
}

func editRequest() acp.RequestPermissionRequest {
	title := "Edit main.go"
	return acp.RequestPermissionRequest{SessionId: "s", ToolCall: acp.ToolCallUpdate{ToolCallId: "call_1", Title: &title,
		Content: []acp.ToolCallContent{acp.ToolDiffContent("/w/main.go", "new", "old")}},
		Options: []acp.PermissionOption{
			{OptionId: "yes", Name: "Allow", Kind: acp.PermissionOptionKindAllowOnce},
			{OptionId: "no", Name: "Reject", Kind: acp.PermissionOptionKindRejectOnce}}}
}

// With permissions ask, the agent's permission request is put to a person with its options and
// the change's diff, and the person's choice is the agent's answer; the decision and the
// resolution are recorded.
func TestACPAskPermissionPersonAnswers(t *testing.T) {
	cl, lines := askClient(time.Minute)
	type result struct {
		resp acp.RequestPermissionResponse
		err  error
	}
	done := make(chan result)
	go func() {
		resp, err := cl.RequestPermission(context.Background(), editRequest())
		done <- result{resp, err}
	}()
	req := waitRequest(t, lines)
	if req.Request == nil || req.Request.Kind != acpx.RequestPermission || len(req.Request.Options) != 2 || len(req.Diffs) != 1 || req.Diffs[0].NewText != "new" {
		t.Fatalf("request line: %+v", req)
	}
	b, _ := json.Marshal(acpx.Reply{RequestID: req.Request.ID, OptionID: "no"})
	cl.reply(string(b))
	r := <-done
	if r.err != nil || r.resp.Outcome.Selected == nil || r.resp.Outcome.Selected.OptionId != "no" {
		t.Fatalf("answer: %+v %v", r.resp, r.err)
	}
	all := lines()
	last, perm := all[len(all)-1], all[len(all)-2]
	if perm.Type != harness.ACPPermission || perm.Decision != "reject_once" || last.Type != harness.ACPResolved || last.Outcome != "reject_once" || last.By != "user" || last.RequestID != req.Request.ID {
		t.Fatalf("recorded: %+v", all)
	}
	// A second answer to the same request finds nothing waiting, and says so.
	cl.reply(string(b))
	if l := lines()[len(lines())-1]; l.Type != harness.ACPResolved || l.Outcome != "not_waiting" {
		t.Fatalf("late answer: %+v", l)
	}
}

// Nobody answers within the ask timeout, or the answer is not one of the options: refused.
func TestACPAskPermissionTimeoutAndInvalid(t *testing.T) {
	cl, lines := askClient(30 * time.Millisecond)
	resp, err := cl.RequestPermission(context.Background(), editRequest())
	if err != nil || resp.Outcome.Cancelled == nil {
		t.Fatalf("timeout: %+v %v", resp, err)
	}
	if l := lines()[len(lines())-1]; l.Outcome != "cancelled" || l.By != "timeout" {
		t.Fatalf("timeout recorded: %+v", l)
	}

	cl, lines = askClient(time.Minute)
	done := make(chan acp.RequestPermissionResponse)
	go func() { r, _ := cl.RequestPermission(context.Background(), editRequest()); done <- r }()
	req := waitRequest(t, lines)
	b, _ := json.Marshal(acpx.Reply{RequestID: req.Request.ID, OptionID: "maybe"})
	cl.reply(string(b))
	if r := <-done; r.Outcome.Cancelled == nil {
		t.Fatalf("invalid answer: %+v", r)
	}
	if l := lines()[len(lines())-1]; l.By != "invalid" {
		t.Fatalf("invalid recorded: %+v", lines())
	}
	// allow still answers by itself, no request.
	auto := &acpClient{permissions: harness.PermissionsAllow, emit: func(string) {}}
	if r, _ := auto.RequestPermission(context.Background(), editRequest()); r.Outcome.Selected == nil || r.Outcome.Selected.OptionId != "yes" {
		t.Fatalf("allow: %+v", r)
	}
}

// A question the agent asks (a form) is put to the person; the answer, checked against the form,
// is the agent's; one that does not fit cancels the question. Without ask nobody is asked.
func TestACPAskQuestion(t *testing.T) {
	cl, lines := askClient(time.Minute)
	form := acp.UnstableCreateElicitationRequest{Form: &acp.UnstableCreateElicitationForm{Mode: "form", Message: "Which database?",
		RequestedSchema: acp.UnstableElicitationSchema{Type: "object", Required: []string{"db"},
			Properties: map[string]any{"db": map[string]any{"type": "string", "oneOf": []any{map[string]any{"const": "pg"}}}}}}}
	done := make(chan acp.UnstableCreateElicitationResponse)
	go func() { r, _ := cl.UnstableCreateElicitation(context.Background(), form); done <- r }()
	req := waitRequest(t, lines)
	if req.Request.Kind != acpx.RequestForm || req.Request.Message != "Which database?" || !strings.Contains(string(req.Request.Schema), `"db"`) {
		t.Fatalf("question: %+v", req.Request)
	}
	b, _ := json.Marshal(acpx.Reply{RequestID: req.Request.ID, Action: acpx.ActionAccept, Content: map[string]any{"db": "pg"}})
	cl.reply(string(b))
	if r := <-done; r.Accept == nil || r.Accept.Content["db"] != "pg" {
		t.Fatalf("answer: %+v", r)
	}
	if l := lines()[len(lines())-1]; l.Outcome != "accept" || l.By != "user" {
		t.Fatalf("resolved: %+v", l)
	}

	go func() { r, _ := cl.UnstableCreateElicitation(context.Background(), form); done <- r }()
	time.Sleep(20 * time.Millisecond)
	var second harness.ACPLine
	for _, l := range lines() {
		if l.Type == harness.ACPRequest && l.Request.ID != req.Request.ID {
			second = l
		}
	}
	b, _ = json.Marshal(acpx.Reply{RequestID: second.Request.ID, Action: acpx.ActionAccept, Content: map[string]any{}})
	cl.reply(string(b))
	if r := <-done; r.Cancel == nil {
		t.Fatalf("missing required field: %+v", r)
	}

	nobody := &acpClient{permissions: harness.PermissionsAllow, emit: func(string) {}}
	if r, _ := nobody.UnstableCreateElicitation(context.Background(), form); r.Cancel == nil {
		t.Fatalf("without ask: %+v", r)
	}
	if c := clientCapabilities(harness.PermissionsAsk); c.Elicitation == nil || c.Elicitation.Form == nil || c.Elicitation.Url == nil {
		t.Fatalf("ask advertises elicitation: %+v", c)
	}
	if c := clientCapabilities(harness.PermissionsAllow); c.Elicitation != nil {
		t.Fatalf("allow advertises elicitation: %+v", c)
	}
}

// The agent's commands are written for clients when the list changes (not again when it does not).
func TestACPCommandsLine(t *testing.T) {
	var lines []string
	cl := &acpClient{emit: func(l string) { lines = append(lines, l) }}
	up := acp.SessionUpdate{AvailableCommandsUpdate: &acp.SessionAvailableCommandsUpdate{SessionUpdate: "available_commands_update",
		AvailableCommands: []acp.AvailableCommand{{Name: "review", Description: "Review the diff", Input: &acp.AvailableCommandInput{Unstructured: &acp.UnstructuredCommandInput{Hint: "branch"}}}}}}
	for i := 0; i < 2; i++ {
		_ = cl.SessionUpdate(context.Background(), acp.SessionNotification{SessionId: "s", Update: up})
	}
	var l harness.ACPLine
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &l) != nil || l.Type != harness.ACPCommands ||
		len(l.Commands) != 1 || l.Commands[0] != (harness.ACPCommand{Name: "review", Description: "Review the diff", Hint: "branch"}) {
		t.Fatalf("lines: %q", lines)
	}
}

// Files a message attached reach the agent as resource links, the text without the list.
func TestACPAttachmentsAreResourceLinks(t *testing.T) {
	clearACPEnv(t)
	conn := &coreConn{}
	runCore(t, conn, nil, &model.Run{Task: harness.WithAttachments("review this", []string{"/workspace/uploads/spec.md"})})
	b := conn.blocks[0]
	if len(b) != 2 || b[0].Text == nil || b[0].Text.Text != "review this" || b[1].ResourceLink == nil || b[1].ResourceLink.Uri != "file:///workspace/uploads/spec.md" {
		t.Fatalf("blocks: %+v", b)
	}
}

// A reply input event goes to the conversation, not into a prompt.
func TestForwardInputRoutesReplies(t *testing.T) {
	polls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls++
		var evs []model.Event
		switch polls {
		case 1:
			evs = []model.Event{{ID: 1, Type: model.EventReply, Data: `{"request_id":"req_0123456789abcdef","option_id":"yes"}`}, {ID: 2, Type: model.EventRunClose}}
		case 2:
			evs = []model.Event{{ID: 3, Type: model.EventRunCancel}} // after the close only a cancel ends the polling
		}
		_ = json.NewEncoder(w).Encode(evs)
	}))
	defer srv.Close()
	q := newPromptQueue()
	var got string
	q.onReply = func(d string) { got = d }
	forwardInput(t.Context(), &client{base: srv.URL, http: srv.Client()}, "r", q, func() {}, newChat(harness.InputACP, time.Minute))
	if !strings.Contains(got, "req_0123456789abcdef") || len(q.queue) != 0 {
		t.Fatalf("reply %q, queue %q", got, q.queue)
	}
}

// Closing the conversation gives up what waits on a person (it does not hold the run until the
// ask timeout), and polling goes on for a cancel.
func TestACPCloseGivesUpWaitingRequests(t *testing.T) {
	cl, lines := askClient(time.Hour)
	q := newPromptQueue()
	q.onClose = cl.pending.Close
	done := make(chan acp.RequestPermissionResponse)
	go func() { r, _ := cl.RequestPermission(context.Background(), editRequest()); done <- r }()
	waitRequest(t, lines)
	_ = q.Close()
	select {
	case r := <-done:
		if r.Outcome.Cancelled == nil {
			t.Fatalf("answered: %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request still waits after the close")
	}
	if l := lines()[len(lines())-1]; l.By != "closed" {
		t.Fatalf("resolution: %+v", l)
	}

	// After run.close, forwardInput still takes a cancel.
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		var evs []model.Event
		switch n {
		case 1:
			evs = []model.Event{{ID: 1, Type: model.EventRunClose}}
		case 2:
			evs = []model.Event{{ID: 2, Type: model.EventInput, Data: "ignored"}, {ID: 3, Type: model.EventRunCancel}}
		}
		_ = json.NewEncoder(w).Encode(evs)
	}))
	defer srv.Close()
	cancelled := false
	q2 := newPromptQueue()
	forwardInput(t.Context(), &client{base: srv.URL, http: srv.Client()}, "r", q2, func() { cancelled = true }, newChat(harness.InputACP, time.Minute))
	if !cancelled || !q2.closed || len(q2.queue) != 0 {
		t.Fatalf("cancel after close: %v closed %v queue %q", cancelled, q2.closed, q2.queue)
	}
}

// A link question the agent asks while it authenticates (before the session opens) is
// answered: the input runs from the start.
type authAsking struct {
	coreConn
	cl *acpClient
}

func (a *authAsking) Authenticate(ctx context.Context, _ acp.AuthenticateRequest) (acp.AuthenticateResponse, error) {
	r, _ := a.cl.UnstableCreateElicitation(ctx, acp.UnstableCreateElicitationRequest{Url: &acp.UnstableCreateElicitationUrl{
		Mode: "url", Message: "Sign in", Url: "https://auth.example/device", ElicitationId: "e1"}})
	if r.Decline != nil {
		return acp.AuthenticateResponse{}, errors.New("declined")
	}
	return acp.AuthenticateResponse{}, nil
}

func TestACPAnswersDuringAuthentication(t *testing.T) {
	clearACPEnv(t)
	t.Setenv("HARNESS_AUTH_METHOD", "chat-gpt-device-code")
	cl, lines := askClient(time.Minute)
	conn := &authAsking{cl: cl}
	conn.init = acp.InitializeResponse{AuthMethods: []acp.AuthMethod{{Agent: &acp.AuthMethodAgent{Id: "chat-gpt-device-code", Name: "ChatGPT"}}}}
	chat := newChat(harness.InputACP, chatIdle())
	emit := cl.emit
	code := make(chan int)
	go func() {
		code <- driveACP(t.Context(), conn, cl, &model.Run{Task: "go"}, emit, chat, func(s inputSink) {
			go func() {
				req := waitRequest(t, lines)
				b, _ := json.Marshal(acpx.Reply{RequestID: req.Request.ID, Action: acpx.ActionDecline})
				_ = s.(interface{ Reply(string) error }).Reply(string(b))
				_ = s.Close()
			}()
		})
	}()
	select {
	case c := <-code:
		if c != 1 || !strings.Contains(strings.Join(func() (o []string) {
			for _, l := range lines() {
				o = append(o, l.Text)
			}
			return
		}(), "\n"), "declined") {
			t.Fatalf("exit %d, lines %+v", c, lines())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the answer did not reach the agent while it authenticated")
	}
}

// A command sent with files is still a command; the files go with it.
func TestACPCommandWithAttachments(t *testing.T) {
	cl := &acpClient{emit: func(string) {}}
	_ = cl.SessionUpdate(context.Background(), acp.SessionNotification{SessionId: "s", Update: acp.SessionUpdate{
		AvailableCommandsUpdate: &acp.SessionAvailableCommandsUpdate{SessionUpdate: "available_commands_update", AvailableCommands: []acp.AvailableCommand{{Name: "review"}}}}})
	in := harness.WithAttachments("/review", []string{"/workspace/uploads/a.diff"})
	if got := escapeACPPrompt(in, cl.isCommand); got != in {
		t.Fatalf("escaped: %q", got)
	}
	body, files := harness.SplitAttachments(escapeACPPrompt(harness.WithAttachments("/etc is wrong", []string{"/workspace/a"}), cl.isCommand))
	if body != "​/etc is wrong" || len(files) != 1 {
		t.Fatalf("plain text: %q %q", body, files)
	}
}

// The person sees what they approve: the tool's input and text, and the diff the call carried
// before the request when the request has none; a request too large for a line is cut, never lost.
func TestACPPermissionRequestContextAndSize(t *testing.T) {
	cl, lines := askClient(50 * time.Millisecond)
	_ = cl.SessionUpdate(context.Background(), acp.SessionNotification{SessionId: "s", Update: acp.StartToolCall("call_1", "Apply patch",
		acp.WithStartContent([]acp.ToolCallContent{acp.ToolDiffContent("/w/a.go", "new a", "old a")}))})
	kind := acp.ToolKindExecute
	p := editRequest()
	p.ToolCall.Content = nil
	p.ToolCall.Kind = &kind
	p.ToolCall.RawInput = map[string]any{"command": "go generate"}
	_, _ = cl.RequestPermission(context.Background(), p)
	req := waitRequest(t, lines)
	if len(req.Diffs) != 1 || req.Diffs[0].NewText != "new a" || req.Request.ToolKind != "execute" || !strings.Contains(string(req.Request.RawInput), "go generate") {
		t.Fatalf("context: %+v %+v", req, req.Request)
	}

	big, _ := askClient(50 * time.Millisecond)
	var raw []string
	big.emit = func(l string) { raw = append(raw, l) }
	huge := strings.Repeat("x", 100<<10)
	p = editRequest()
	p.ToolCall.Content = nil
	for i := 0; i < 16; i++ {
		p.ToolCall.Content = append(p.ToolCall.Content, acp.ToolDiffContent(fmt.Sprintf("/w/f%d", i), huge[:70<<10], huge[:50<<10]))
	}
	_, _ = big.RequestPermission(context.Background(), p)
	var found bool
	for _, l := range raw {
		if strings.Contains(l, `"type":"acp.request"`) {
			found = true
			if len(l) > maxRequestLine || !strings.Contains(l, `"request_id":"req_`) || !strings.Contains(l, `"truncated":true`) {
				t.Fatalf("request line: %d bytes", len(l))
			}
		}
	}
	if !found {
		t.Fatal("the large request was not written")
	}
}

// The agent's elicitation/complete answers the link question still waiting for the person.
func TestACPElicitationCompleteResolvesTheLink(t *testing.T) {
	cl, lines := askClient(time.Minute)
	done := make(chan acp.UnstableCreateElicitationResponse)
	go func() {
		r, _ := cl.UnstableCreateElicitation(context.Background(), acp.UnstableCreateElicitationRequest{Url: &acp.UnstableCreateElicitationUrl{
			Mode: "url", Message: "Sign in to GitHub", Url: "https://github.com/login", ElicitationId: "e7"}})
		done <- r
	}()
	waitRequest(t, lines)
	_ = cl.UnstableCompleteElicitation(context.Background(), acp.UnstableCompleteElicitationNotification{ElicitationId: "e7"})
	select {
	case r := <-done:
		if r.Accept == nil {
			t.Fatalf("answer: %+v", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the completed link question still waits")
	}
}

// A question does not cut a message being streamed.
func TestACPQuestionDoesNotSplitAMessage(t *testing.T) {
	cl, lines := askClient(30 * time.Millisecond)
	_ = cl.SessionUpdate(context.Background(), acp.SessionNotification{SessionId: "s", Update: acp.UpdateAgentMessageText("Hel")})
	_, _ = cl.UnstableCreateElicitation(context.Background(), acp.UnstableCreateElicitationRequest{Form: &acp.UnstableCreateElicitationForm{Mode: "form", Message: "?",
		RequestedSchema: acp.UnstableElicitationSchema{Type: "object", Properties: map[string]any{}}}})
	_ = cl.SessionUpdate(context.Background(), acp.SessionNotification{SessionId: "s", Update: acp.UpdateAgentMessageText("lo")})
	cl.flush()
	var msgs []string
	for _, l := range lines() {
		if l.Type == harness.ACPMessage {
			msgs = append(msgs, l.Text)
		}
	}
	if len(msgs) != 1 || msgs[0] != "Hello" {
		t.Fatalf("messages: %q", msgs)
	}
}

// Through the conversation itself: the input closes while the agent's request waits, and the
// request is given up at once (driveACP wires the queue's close to the pending requests).
func TestACPConversationCloseReleasesTheAgent(t *testing.T) {
	clearACPEnv(t)
	cl, lines := askClient(time.Hour)
	var sink inputSink
	conn := &coreConn{}
	conn.prompt = func(n int, _ string) (acp.PromptResponse, error) {
		go func() { waitRequest(t, lines); _ = sink.Close() }()
		r, _ := cl.RequestPermission(context.Background(), editRequest()) // the agent waits on the person
		if r.Outcome.Cancelled == nil {
			t.Errorf("answered: %+v", r)
		}
		return acp.PromptResponse{StopReason: acp.StopReasonEndTurn}, nil
	}
	done := make(chan int)
	go func() {
		done <- driveACP(t.Context(), conn, cl, &model.Run{Task: "go"}, cl.emit, newChat(harness.InputACP, chatIdle()), func(s inputSink) { sink = s })
	}()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the close did not release the waiting agent")
	}
	var by string
	for _, l := range lines() {
		if l.Type == harness.ACPResolved {
			by = l.By
		}
	}
	if by != "closed" {
		t.Fatalf("resolution: %q", by)
	}
}
