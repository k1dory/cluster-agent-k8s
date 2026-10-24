// Package harness understands the output formats of agent harnesses enough to pull
// accounting data out of their streams. Everything else in the stream is passed through
// as opaque run.output events.
package harness

import (
	"encoding/json"
	"sort"
	"strings"

	"agent-sandbox/internal/model"
)

// Mode says how a parsed usage record relates to the run's running total.
type Mode int

const (
	// Increment: add to what was recorded so far (generic `{"type":"usage"}` lines, one per step).
	Increment Mode = iota
	// Total: the harness reported the whole run (Claude Code's final `result` line); replace.
	Total
)

// ParseUsage recognises a usage record in one output line. It returns ok=false for
// everything that is not one, cheaply: lines are only decoded when they look like JSON
// with a usage-bearing type.
func ParseUsage(line string) (u model.Usage, mode Mode, ok bool) {
	t := strings.TrimSpace(line)
	if len(t) < 2 || t[0] != '{' {
		return u, 0, false
	}
	switch {
	case strings.Contains(t, `"type":"usage"`), strings.Contains(t, `"type": "usage"`):
		if json.Unmarshal([]byte(t), &u) != nil || u.IsZero() {
			return model.Usage{}, 0, false
		}
		return u, Increment, true
	case strings.Contains(t, `"type":"result"`), strings.Contains(t, `"type": "result"`):
		return parseClaudeResult(t)
	}
	return u, 0, false
}

// claudeResult is the tail of Claude Code's `--output-format stream-json` stream.
type claudeResult struct {
	Type         string  `json:"type"`
	NumTurns     int     `json:"num_turns"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	Usage        struct {
		InputTokens              int64 `json:"input_tokens"`
		OutputTokens             int64 `json:"output_tokens"`
		CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
		CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	} `json:"usage"`
	ModelUsage map[string]json.RawMessage `json:"modelUsage"`
}

func parseClaudeResult(t string) (model.Usage, Mode, bool) {
	var r claudeResult
	if err := json.Unmarshal([]byte(t), &r); err != nil || r.Type != "result" {
		return model.Usage{}, 0, false
	}
	u := model.Usage{
		InputTokens: r.Usage.InputTokens, OutputTokens: r.Usage.OutputTokens,
		CacheRead: r.Usage.CacheReadInputTokens, CacheWrite: r.Usage.CacheCreationInputTokens,
		CostUSD: r.TotalCostUSD, Turns: r.NumTurns,
	}
	if len(r.ModelUsage) > 0 {
		models := make([]string, 0, len(r.ModelUsage))
		for m := range r.ModelUsage {
			models = append(models, m)
		}
		sort.Strings(models)
		u.Model = strings.Join(models, ",")
	}
	if u.IsZero() {
		return model.Usage{}, 0, false
	}
	return u, Total, true
}
