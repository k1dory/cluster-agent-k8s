package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/k1dory/acpx"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
)

// What the agent asks a person reaches the conversation (role request, with the runner's line
// as data), the person's answer reaches the run that waits for it (a reply input event), and the
// agent's commands are listed (role commands). A sandbox without a harness of its own runs the
// deployment's default (ACP here): it takes input during a run.
func TestAgentRequestsReachThePersonAndBack(t *testing.T) {
	s := newStack(t)
	s.orch.Cfg.DefaultHarnessInput = harness.InputACP
	api, gw := s.platform.URL, s.gateway.URL
	sb, hdr := agentOf(t, s, "ask")

	resp, body := call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", MessageRequest{Text: "refactor checkout"}, nil)
	var mr MessageResponse
	_ = json.Unmarshal(body, &mr)
	if resp.StatusCode != 202 || mr.Delivery != "new" {
		t.Fatalf("first message: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", gw+"/agent/runs/next?wait=2s", "", nil, hdr)
	var run model.Run
	_ = json.Unmarshal(body, &run)
	if resp.StatusCode != 200 || run.ID != mr.Run.ID {
		t.Fatalf("next run: %d %s", resp.StatusCode, body)
	}
	// The default harness is ACP: a message during the run is input, not a new run.
	resp, body = call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", MessageRequest{Text: "also the tests"}, nil)
	_ = json.Unmarshal(body, &mr)
	if resp.StatusCode != 202 || mr.Delivery != "input" || mr.Run.ID != run.ID {
		t.Fatalf("message during the run: %d %s", resp.StatusCode, body)
	}

	title := "Run go test ./..."
	req := acpx.Request{ID: "req_0123456789abcdef", Kind: acpx.RequestPermission, ToolCallID: "call_1", Title: title,
		Options: []acpx.Option{{ID: "yes", Name: "Allow", Kind: "allow_once"}, {ID: "no", Name: "Reject", Kind: "reject_once"}}}
	lines := []string{
		harness.ACPLine{Type: harness.ACPCommands, Commands: []harness.ACPCommand{{Name: "compact", Description: "Compact the context"}}}.String(),
		harness.ACPLine{Type: harness.ACPRequest, Request: &req, ToolCallID: "call_1"}.String(),
	}
	if resp, body := call(t, "POST", gw+"/agent/runs/"+run.ID+"/events", "", strings.Join(lines, "\n")+"\n", hdr); resp.StatusCode != 200 {
		t.Fatalf("output: %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, "GET", api+"/v1/sandboxes/"+sb.ID+"/messages", "alice-tok", nil, nil)
	var msgs []model.Message
	_ = json.Unmarshal(body, &msgs)
	var gotReq, gotCmds *model.Message
	for i := range msgs {
		switch msgs[i].Role {
		case model.RoleRequest:
			gotReq = &msgs[i]
		case model.RoleCommands:
			gotCmds = &msgs[i]
		}
	}
	if gotReq == nil || gotReq.Text != title || !strings.Contains(string(gotReq.Data), `"request_id":"req_0123456789abcdef"`) ||
		gotCmds == nil || gotCmds.Text != "/compact" || !strings.Contains(string(gotCmds.Data), `"Compact the context"`) {
		t.Fatalf("conversation: %s", body)
	}

	// The person answers; another tenant cannot; a malformed answer is refused.
	reqURL := api + "/v1/sandboxes/" + sb.ID + "/requests/" + req.ID
	if resp, _ := call(t, "POST", reqURL, "bob-tok", map[string]string{"option_id": "yes"}, nil); resp.StatusCode != 403 {
		t.Fatalf("bob answers alice's agent: %d", resp.StatusCode)
	}
	for _, bad := range []any{map[string]string{}, map[string]string{"option_id": "yes", "action": "accept"}, map[string]string{"action": "maybe"}} {
		if resp, body := call(t, "POST", reqURL, "alice-tok", bad, nil); resp.StatusCode != 400 {
			t.Fatalf("%v: %d %s", bad, resp.StatusCode, body)
		}
	}
	if resp, _ := call(t, "POST", api+"/v1/sandboxes/"+sb.ID+"/requests/not-a-request", "alice-tok", map[string]string{"option_id": "yes"}, nil); resp.StatusCode != 400 {
		t.Fatalf("bad id: %d", resp.StatusCode)
	}
	resp, body = call(t, "POST", reqURL, "alice-tok", map[string]string{"option_id": "yes"}, nil)
	if resp.StatusCode != 202 || !strings.Contains(string(body), run.ID) {
		t.Fatalf("reply: %d %s", resp.StatusCode, body)
	}
	// The runner gets it with the run's input.
	resp, body = call(t, "GET", gw+"/agent/runs/"+run.ID+"/input?wait=2s", "", nil, hdr)
	var inputs []model.Event
	_ = json.Unmarshal(body, &inputs)
	var reply acpx.Reply
	for _, e := range inputs {
		if e.Type == model.EventReply {
			_ = json.Unmarshal([]byte(e.Data), &reply)
		}
	}
	if reply.RequestID != req.ID || reply.OptionID != "yes" {
		t.Fatalf("reply event: %s", body)
	}
	// With no run waiting, there is nothing to answer.
	if resp, _ := call(t, "POST", gw+"/agent/runs/"+run.ID+"/finish", "", map[string]int{"exit_code": 0}, hdr); resp.StatusCode != 204 {
		t.Fatal("finish")
	}
	if resp, _ := call(t, "POST", reqURL, "alice-tok", map[string]string{"option_id": "yes"}, nil); resp.StatusCode != 409 {
		t.Fatalf("after the run: %d", resp.StatusCode)
	}
	// A text-mode harness asks nothing.
	sbx, _ := s.orch.Store.GetSandbox(context.Background(), sb.ID)
	sbx.Launch = &model.Launch{HarnessCommand: "claude -p", HarnessInput: harness.InputText}
	_ = s.orch.Store.UpdateSandbox(context.Background(), sbx)
	if resp, _ := call(t, "POST", reqURL, "alice-tok", map[string]string{"option_id": "yes"}, nil); resp.StatusCode != 409 {
		t.Fatalf("text harness: %d", resp.StatusCode)
	}
}
