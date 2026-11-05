package main

import (
	"context"
	"encoding/json"
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
	sent := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var evs []model.Event
		if !sent {
			evs, sent = []model.Event{{ID: 1, Type: model.EventReply, Data: `{"request_id":"req_0123456789abcdef","option_id":"yes"}`}, {ID: 2, Type: model.EventRunClose}}, true
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
