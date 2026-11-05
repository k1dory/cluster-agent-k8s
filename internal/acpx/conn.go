package acpx

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	acp "github.com/coder/acp-go-sdk"
)

// Conn is the client side of one ACP connection: the SDK's connection (every method it has is
// Conn's) over a Wire, plus the calls the SDK does not type.
type Conn struct {
	*acp.ClientSideConnection
	Wire *Wire
}

// Dial connects client to an agent over its stdin and stdout through a Wire.
func Dial(client acp.Client, agentStdin io.Writer, agentStdout io.Reader, opts WireOptions) *Conn {
	w := NewWire(agentStdin, agentStdout, opts)
	return &Conn{ClientSideConnection: acp.NewClientSideConnection(client, w, w), Wire: w}
}

// SteerMethod is the steering extension (claude-agent-acp, codex-acp): a message joins the turn in
// progress instead of waiting for it to end.
const SteerMethod = "_session/steering"

// SteerOutcome is what became of a steered message.
type SteerOutcome string

const (
	// SteerInjected: the message joined the turn in progress.
	SteerInjected SteerOutcome = "injected"
	// SteerPromptRequired: no turn was running; the message was not taken and is to be sent as a
	// prompt of its own.
	SteerPromptRequired SteerOutcome = "promptRequired"
	// SteerStartedNewTurn: the agent started a turn with the message itself (an agent that ignores
	// idleBehavior). Its end is not the end of any prompt the client sent.
	SteerStartedNewTurn SteerOutcome = "startedNewTurn"
)

// Steer sends text into the turn in progress of a session. It asks the agent not to start a turn
// of its own when none is running (idleBehavior promptRequired), so the client keeps every turn a
// prompt it sent. An agent without steering (Wire.Steering false) is not asked: the result is
// SteerPromptRequired.
func (c *Conn) Steer(ctx context.Context, sessionID acp.SessionId, text string) (SteerOutcome, error) {
	if !c.Wire.Steering() {
		return SteerPromptRequired, nil
	}
	raw, err := c.CallExtension(ctx, SteerMethod, map[string]any{
		"sessionId": sessionID,
		"prompt":    []acp.ContentBlock{acp.TextBlock(text)},
		"_meta":     map[string]any{"steering": map[string]any{"idleBehavior": "promptRequired"}},
	})
	if err != nil {
		return "", err
	}
	var resp struct {
		Outcome SteerOutcome `json:"outcome"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", fmt.Errorf("%s: %w", SteerMethod, err)
	}
	return resp.Outcome, nil
}

// SessionMeta is the _meta of a session request (new, load, resume): the profile's free-form
// metadata (claude-agent-acp reads claudeCode.options from it: maxTurns, maxBudgetUsd…) and, when
// the agent takes one, the system prompt (moved to the request's systemPrompt by the Wire).
// nil when there is neither.
func SessionMeta(meta map[string]any, systemPrompt string) map[string]any {
	if len(meta) == 0 && systemPrompt == "" {
		return nil
	}
	out := make(map[string]any, len(meta)+1)
	for k, v := range meta {
		out[k] = v
	}
	if systemPrompt != "" {
		out[SystemPromptMetaKey] = systemPrompt
	}
	return out
}
