package main

import (
	"context"
	"reflect"
	"testing"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/harness"
)

// The SDK dispatches requests separately from ordered session notifications.
// A permission callback can therefore run between two already-received text
// chunks. It must answer and record the request without splitting the message.
func TestACPPermissionDoesNotSplitMessageChunks(t *testing.T) {
	var lines []string
	cl := &acpClient{emit: func(line string) { lines = append(lines, line) }}
	ctx := context.Background()
	send := func(update acp.SessionUpdate) {
		t.Helper()
		if err := cl.SessionUpdate(ctx, acp.SessionNotification{SessionId: "s", Update: update}); err != nil {
			t.Fatal(err)
		}
	}
	send(acp.UpdateAgentMessageText("Hel"))
	response, err := cl.RequestPermission(ctx, acp.RequestPermissionRequest{
		SessionId: "s",
		ToolCall:  acp.ToolCallUpdate{ToolCallId: "edit"},
		Options:   []acp.PermissionOption{{OptionId: "yes", Name: "Allow", Kind: acp.PermissionOptionKindAllowOnce}},
	})
	if err != nil || response.Outcome.Selected == nil || response.Outcome.Selected.OptionId != "yes" {
		t.Fatalf("permission response: %+v, error: %v", response, err)
	}
	send(acp.UpdateAgentMessageText("lo"))
	send(acp.StartToolCall("edit", "Edit a.txt"))
	cl.flush()
	var turns []string
	for _, line := range lines {
		if role, text := harness.ParseMessage(line); role != "" {
			turns = append(turns, role+":"+text)
		}
	}
	if want := []string{"assistant:Hello", "tool:Edit a.txt"}; !reflect.DeepEqual(turns, want) {
		t.Fatalf("permission callback split the transcript: %q, want %q", turns, want)
	}
	if len(lines) != 3 {
		t.Fatalf("want one permission record, one message and one tool call; got %q", lines)
	}
}
