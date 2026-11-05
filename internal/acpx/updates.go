package acpx

import (
	"encoding/json"
	"strings"
)

// Session update kinds acp-go-sdk v0.13.5 does not decode (it hands its client an empty update
// for them). The Wire decodes them for the client that advertised them (WireOptions).
const (
	UpdateNotice                 = "notice"
	UpdateCompaction             = "compaction_update"
	UpdateCompactionSummaryChunk = "compaction_summary_chunk"
)

// Notice is a user-facing notice from the agent: a limit reached, a degraded service, an error
// it recovered from. Severity is info, warning, error or the agent's own.
type Notice struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// Compaction is the state of one compaction of the session's context: in_progress, completed,
// failed or cancelled. Summary is the text of its summary, when the update carries one.
type Compaction struct {
	ID      string `json:"compactionId"`
	Status  string `json:"status"`
	Summary string `json:"-"`
	Error   string `json:"error,omitempty"`
}

// CompactionSummaryChunk is a piece of a compaction's summary as it is written.
type CompactionSummaryChunk struct {
	ID   string `json:"compactionId"`
	Text string `json:"-"`
}

// ExtraUpdate is one of those updates; exactly one of its pointers is set.
type ExtraUpdate struct {
	SessionID    string
	Notice       *Notice
	Compaction   *Compaction
	SummaryChunk *CompactionSummaryChunk
}

// decodeExtraUpdate reads a session/update notification of a kind the SDK does not decode.
func decodeExtraUpdate(line []byte) (ExtraUpdate, bool) {
	var msg struct {
		Method string `json:"method"`
		Params struct {
			SessionID string          `json:"sessionId"`
			Update    json.RawMessage `json:"update"`
		} `json:"params"`
	}
	if json.Unmarshal(line, &msg) != nil || msg.Method != "session/update" {
		return ExtraUpdate{}, false
	}
	var kind struct {
		SessionUpdate string `json:"sessionUpdate"`
	}
	if json.Unmarshal(msg.Params.Update, &kind) != nil {
		return ExtraUpdate{}, false
	}
	u := ExtraUpdate{SessionID: msg.Params.SessionID}
	raw := msg.Params.Update
	switch kind.SessionUpdate {
	case UpdateNotice:
		var n struct {
			Notice
			Description *string `json:"description"`
		}
		if json.Unmarshal(raw, &n) != nil || n.Title == "" {
			return ExtraUpdate{}, false
		}
		if n.Description != nil {
			n.Notice.Description = *n.Description
		}
		u.Notice = &n.Notice
	case UpdateCompaction:
		var c struct {
			Compaction
			Summary []contentBlock `json:"summary"`
			Error   *string        `json:"error"`
		}
		if json.Unmarshal(raw, &c) != nil || c.ID == "" || c.Status == "" {
			return ExtraUpdate{}, false
		}
		c.Compaction.Summary = blocksText(c.Summary)
		if c.Error != nil {
			c.Compaction.Error = *c.Error
		}
		u.Compaction = &c.Compaction
	case UpdateCompactionSummaryChunk:
		var c struct {
			ID      string       `json:"compactionId"`
			Content contentBlock `json:"content"`
		}
		if json.Unmarshal(raw, &c) != nil || c.ID == "" {
			return ExtraUpdate{}, false
		}
		u.SummaryChunk = &CompactionSummaryChunk{ID: c.ID, Text: c.Content.Text}
	default:
		return ExtraUpdate{}, false
	}
	return u, true
}

// contentBlock is the text of an ACP content block (other kinds have none).
type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func blocksText(blocks []contentBlock) string {
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}
