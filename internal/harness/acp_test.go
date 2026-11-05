package harness

import "testing"

// The ACP lines the runner writes read like any harness's output: messages and tool calls are
// turns, acp.turn_end ends a turn, acp.session carries the session id. Updates, permission
// decisions and notices are not turns.
func TestACPLines(t *testing.T) {
	msg := ACPLine{Type: ACPMessage, Text: "  Hello\n"}.String()
	if role, text := ParseMessage(msg); role != "assistant" || text != "Hello" {
		t.Fatalf("message: %q %q", role, text)
	}
	call := ACPLine{Type: ACPToolCall, Title: "Edit a.txt", Diffs: []ACPDiff{{Path: "/w/a.txt", NewText: "x"}}}.String()
	if role, text := ParseMessage(call); role != "tool" || text != "Edit a.txt" {
		t.Fatalf("tool call: %q %q", role, text)
	}
	for _, l := range []string{
		ACPLine{Type: ACPToolUpdate, Status: "completed"}.String(),
		ACPLine{Type: ACPPermission, Title: "Edit a.txt", Decision: "allow_once"}.String(),
		ACPLine{Type: ACPMessage, Text: "   "}.String(),
		`{"type":"acp.unknown","text":"x"}`,
	} {
		if role, _ := ParseMessage(l); role != "" {
			t.Errorf("not a turn: %s → %s", l, role)
		}
		if IsTurnEnd(l) {
			t.Errorf("not a turn end: %s", l)
		}
	}
	if !IsTurnEnd(ACPLine{Type: ACPTurnEnd, StopReason: "end_turn"}.String()) {
		t.Fatal("acp.turn_end ends the turn")
	}
	if s, ok := ParseSession(ACPLine{Type: ACPSession, SessionID: "sess_1"}.String()); !ok || s != "sess_1" {
		t.Fatalf("session: %q %v", s, ok)
	}
	// A Claude stream-json line that merely mentions "acp." in its text is still Claude's.
	claude := `{"type":"assistant","message":{"content":[{"type":"text","text":"see \"acp.message\""}]}}`
	if role, text := ParseMessage(claude); role != "assistant" || text != `see "acp.message"` {
		t.Fatalf("claude line: %q %q", role, text)
	}
}
