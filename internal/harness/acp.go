package harness

import (
	"encoding/json"
	"strings"
)

// InputACP: the runner speaks the Agent Client Protocol (https://agentclientprotocol.com) to the
// harness over its stdio — JSON-RPC, a session per conversation, one session/prompt per message —
// instead of reading its stdout. Any ACP agent works: claude-agent-acp, codex-acp, gemini
// --experimental-acp. The runner writes what it learns as the ACP lines below, so the control
// plane's transcript, session and usage accounting read them like any other harness output.
const InputACP = "acp"

// ACP line types, written by the runner (one JSON object per line).
const (
	ACPSession    = "acp.session"     // session_id: the ACP session the conversation lives in
	ACPMessage    = "acp.message"     // text: one agent message (its chunks joined)
	ACPToolCall   = "acp.tool_call"   // a tool call the agent started: title, kind, status, diffs
	ACPToolUpdate = "acp.tool_update" // progress of a tool call: status, diffs
	ACPPermission = "acp.permission"  // a permission the agent asked for and the runner's decision
	ACPTurnEnd    = "acp.turn_end"    // stop_reason: the prompt turn is over
)

// ACPLine is one line of an ACP harness's output as the runner writes it.
type ACPLine struct {
	Type       string    `json:"type"`
	SessionID  string    `json:"session_id,omitempty"`
	Text       string    `json:"text,omitempty"`
	ToolCallID string    `json:"tool_call_id,omitempty"`
	Title      string    `json:"title,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Status     string    `json:"status,omitempty"`
	Diffs      []ACPDiff `json:"diffs,omitempty"`
	// Permission: the option the runner chose (its kind: allow_once, reject_once…) and why.
	Decision   string `json:"decision,omitempty"`
	StopReason string `json:"stop_reason,omitempty"`
}

// ACPDiff is a file change an ACP agent reported on a tool call. OldText is absent for a new file.
type ACPDiff struct {
	Path    string  `json:"path"`
	OldText *string `json:"old_text,omitempty"`
	NewText string  `json:"new_text"`
}

// String renders the line as the runner writes it.
func (l ACPLine) String() string {
	b, _ := json.Marshal(l)
	return string(b)
}

// parseACP decodes an ACP line; ok is false for anything else.
func parseACP(t string) (l ACPLine, ok bool) {
	if !strings.Contains(t, `"acp.`) || json.Unmarshal([]byte(t), &l) != nil || !strings.HasPrefix(l.Type, "acp.") {
		return ACPLine{}, false
	}
	return l, true
}

// Answers to an ACP agent's permission requests (spec.harness.permissions).
const (
	PermissionsAllow = "allow" // pick the agent's allow option: the sandbox is the boundary
	PermissionsDeny  = "deny"  // pick its reject option
)
