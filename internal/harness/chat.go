package harness

import (
	"encoding/json"
	"strings"
)

// Input modes: how the runner hands a message to the harness.
const (
	InputText       = "text"        // one line on stdin
	InputStreamJSON = "stream-json" // Claude Code --input-format stream-json: a JSON user message per line
)

// FormatInput renders a message for the harness's stdin in the given input mode.
func FormatInput(mode, text string) string {
	if mode == InputStreamJSON {
		b, _ := json.Marshal(map[string]any{
			"type":    "user",
			"message": map[string]any{"role": "user", "content": []map[string]string{{"type": "text", "text": text}}},
		})
		return string(b) + "\n"
	}
	return text + "\n"
}

// ParseMessage pulls a conversation turn out of one output line. role is "assistant" for text
// the agent said, "tool" for a tool call (text = the tool name), "" when the line is not a
// turn (progress, usage, system events). Understood: Claude Code stream-json (assistant
// messages with text / tool_use blocks) and Codex --json (agent_message items).
func ParseMessage(line string) (role, text string) {
	t := strings.TrimSpace(line)
	if len(t) < 2 || t[0] != '{' {
		return "", ""
	}
	switch {
	case strings.Contains(t, `"assistant"`):
		var v struct {
			Type    string `json:"type"`
			Message struct {
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
					Name string `json:"name"`
				} `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal([]byte(t), &v) != nil || v.Type != "assistant" {
			return "", ""
		}
		var texts, tools []string
		for _, c := range v.Message.Content {
			switch c.Type {
			case "text":
				if s := strings.TrimSpace(c.Text); s != "" {
					texts = append(texts, s)
				}
			case "tool_use":
				tools = append(tools, c.Name)
			}
		}
		switch {
		case len(texts) > 0:
			return "assistant", strings.Join(texts, "\n")
		case len(tools) > 0:
			return "tool", strings.Join(tools, ", ")
		}
	case strings.Contains(t, `"agent_message"`):
		var v struct {
			Type string `json:"type"`
			Item struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"item"`
		}
		if json.Unmarshal([]byte(t), &v) == nil && v.Type == "item.completed" && v.Item.Type == "agent_message" && strings.TrimSpace(v.Item.Text) != "" {
			return "assistant", strings.TrimSpace(v.Item.Text)
		}
	}
	return "", ""
}

// IsTurnEnd reports whether the line marks the end of an agent turn: Claude Code's `result`
// line, Codex's `turn.completed` event. The runner starts the idle countdown of an open
// conversation from here.
func IsTurnEnd(line string) bool {
	t := strings.TrimSpace(line)
	if len(t) < 2 || t[0] != '{' {
		return false
	}
	var v struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(t), &v) != nil {
		return false
	}
	return v.Type == "result" || v.Type == "turn.completed"
}
