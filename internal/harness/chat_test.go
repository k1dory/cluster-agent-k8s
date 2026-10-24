package harness

import (
	"strings"
	"testing"
)

func TestChatParsing(t *testing.T) {
	claudeText := `{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"I will add the tests now."}]},"session_id":"s1"}`
	claudeTool := `{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","name":"Bash","input":{"command":"go test"}}]},"session_id":"s1"}`
	codex := `{"type":"item.completed","item":{"type":"agent_message","text":"Done."},"thread_id":"t1"}`
	for _, tc := range []struct{ line, role, text string }{
		{claudeText, "assistant", "I will add the tests now."},
		{claudeTool, "tool", "Bash"},
		{codex, "assistant", "Done."},
		{`{"type":"system","subtype":"init","session_id":"s1"}`, "", ""},
		{`{"type":"result","subtype":"success","result":"all good"}`, "", ""},
		{`plain log line`, "", ""},
		{`{"type":"user","message":{"role":"user","content":[{"type":"text","text":"echo"}]}}`, "", ""},
	} {
		role, text := ParseMessage(tc.line)
		if role != tc.role || text != tc.text {
			t.Errorf("%s → %q %q, want %q %q", tc.line, role, text, tc.role, tc.text)
		}
	}
	if !IsTurnEnd(`{"type":"result","subtype":"success"}`) || !IsTurnEnd(`{"type":"turn.completed","usage":{}}`) || IsTurnEnd(claudeText) || IsTurnEnd("x") {
		t.Fatal("turn end detection")
	}
	if got := FormatInput(InputText, "hello"); got != "hello\n" {
		t.Fatalf("text input: %q", got)
	}
	got := FormatInput(InputStreamJSON, `say "hi"`)
	if !strings.HasPrefix(got, `{"message":{"content":[{"text":"say \"hi\"","type":"text"}],"role":"user"},"type":"user"}`) || !strings.HasSuffix(got, "\n") || strings.Count(got, "\n") != 1 {
		t.Fatalf("stream-json input: %q", got)
	}
}
