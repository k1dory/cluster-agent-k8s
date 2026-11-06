package harness

import (
	"encoding/json"
	"strings"

	"github.com/k1dory/acpx"
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
	// What the agent reports besides its messages and tool calls.
	ACPThought     = "acp.thought"      // text: the agent's reasoning before a message (its chunks joined)
	ACPPlan        = "acp.plan"         // entries: the agent's plan, whole, each time it changes
	ACPNotice      = "acp.notice"       // severity, title, text: a notice for the user (a limit, an error it recovered from)
	ACPCompaction  = "acp.compaction"   // compaction_id, status, error, text (its summary): the agent compacted its context
	ACPSessionInfo = "acp.session_info" // title: the session's title as the agent names it
	// What the agent asks a person, and the agent's commands.
	ACPRequest  = "acp.request"          // request: what the agent asks (a permission, a form, a link) and waits for
	ACPResolved = "acp.request_resolved" // request_id, outcome, by: how a request was answered
	ACPCommands = "acp.commands"         // commands: the slash commands the agent offers, the whole list each time it changes
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
	// DiffsReplace: this line's diffs replace those an earlier line of the same tool call
	// carried (an agent that sends a preview first and the real hunks later, or a permission
	// request whose diff is refined by the call's update). The diffs of a tool call are always
	// those of its last line that has any.
	DiffsReplace bool `json:"diffs_replace,omitempty"`
	// Permission: the option the runner chose (its kind: allow_once, reject_once…) and why.
	Decision   string `json:"decision,omitempty"`
	StopReason string `json:"stop_reason,omitempty"`
	// Notice: info, warning, error or the agent's own.
	Severity string `json:"severity,omitempty"`
	// Plan: the entries, in order.
	Entries []ACPPlanEntry `json:"entries,omitempty"`
	// Compaction: its id and, when it failed, why.
	CompactionID string `json:"compaction_id,omitempty"`
	Error        string `json:"error,omitempty"`
	// Request: what the agent asks a person (acpx.Request: request_id, kind, options, schema, url…).
	Request *acpx.Request `json:"request,omitempty"`
	// Resolution: the request answered, how (the option's kind, accept, decline, cancelled), and
	// by whom: user, timeout, policy (the profile answered), invalid (an answer that did not fit).
	RequestID string `json:"request_id,omitempty"`
	Outcome   string `json:"outcome,omitempty"`
	By        string `json:"by,omitempty"`
	// Commands: name, description and the hint for its input.
	Commands []ACPCommand `json:"commands,omitempty"`
}

// ACPCommand is one slash command an agent offers.
type ACPCommand struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Hint        string `json:"hint,omitempty"`
}

// ACPPlanEntry is one step of an agent's plan: pending, in_progress or completed.
type ACPPlanEntry struct {
	Content  string `json:"content"`
	Status   string `json:"status"`
	Priority string `json:"priority,omitempty"`
}

// ACPDiff is a file change an ACP agent reported on a tool call. OldText is absent for a new file.
// A change too large for the output keeps its path and sizes, without the texts (Truncated).
// Change is what the agent said the change is, when it says (codex-acp: add, update, delete,
// rename); OldPath is a renamed file's previous path.
type ACPDiff struct {
	Path      string  `json:"path"`
	Change    string  `json:"change,omitempty"`
	OldPath   string  `json:"old_path,omitempty"`
	OldText   *string `json:"old_text,omitempty"`
	NewText   string  `json:"new_text"`
	OldSize   int     `json:"old_size,omitempty"`
	NewSize   int     `json:"new_size,omitempty"`
	Truncated bool    `json:"truncated,omitempty"`
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

// How an ACP agent gets the sandbox's MCP servers (spec.harness.mcp).
const (
	MCPAuto   = "auto"   // the default: in session/new when the agent declares mcpCapabilities.http
	MCPAlways = "always" // always: for an agent that takes HTTP servers without declaring it (Hermes)
)

// Answers to an ACP agent's permission requests (spec.harness.permissions).
const (
	PermissionsAllow = "allow" // pick the agent's allow option: the sandbox is the boundary
	PermissionsDeny  = "deny"  // pick its reject option
	// PermissionsAsk: a person answers (acp.request, POST /requests/{id}); the agent may also ask
	// them questions (elicitation). Unanswered within the ask timeout: refused.
	PermissionsAsk = "ask"
)
