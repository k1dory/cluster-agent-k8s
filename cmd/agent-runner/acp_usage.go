package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"

	acp "github.com/coder/acp-go-sdk"

	"agent-sandbox/internal/model"
)

// acpUsage turns what an ACP agent reports about usage into one generic usage record per turn
// (`{"type":"usage"}`, which the control plane adds up). Agents differ in what they report:
//
//   - PromptResponse.usage is the turn's tokens for claude-agent-acp and codex-acp, the last
//     model call of the turn only for OpenCode (a turn with several calls is undercounted: the
//     agent reports no more), and the session's running total for Hermes (cumulativeUsage),
//     which is turned into the turn's share here;
//   - usage_update.cost is the session's cost so far (claude-agent-acp, including work the
//     agent does in the background between turns; OpenCode): the record carries what it grew
//     by since the previous turn;
//   - thoughtTokens are reasoning tokens. Agents that count them inside outputTokens
//     (codex-acp, Hermes: totalTokens = input + output) are left as they are; tokens reported
//     beside the output (totalTokens counts them on top) are added to it.
type acpUsage struct {
	cl         *acpClient
	cumulative bool
	path       string    // where the last cumulative usage of the session is kept ("" = memory)
	prev       acp.Usage // the last cumulative usage seen
	costBase   float64   // the session cost at the end of the previous turn
}

// cumulativeUsage names the agents (initialize agentInfo.name) whose PromptResponse.usage is the
// session's running total rather than the turn's.
var cumulativeUsage = map[string]bool{"hermes-agent": true}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func newACPUsage(agent, session string, cl *acpClient) *acpUsage {
	u := &acpUsage{cl: cl, cumulative: cumulativeUsage[agent]}
	if c, ok := cl.sessionCost(); ok {
		u.costBase = c
	}
	// The running total is the session's, and the session outlives the run (session/load in
	// the next one): its last value is kept on the workspace volume, or the next run would
	// count the whole conversation again.
	if u.cumulative && cl.usageDir != "" && session != "" {
		u.path = filepath.Join(cl.usageDir, unsafeFileChars.ReplaceAllString(session, "_")+".json")
		if b, err := os.ReadFile(u.path); err == nil {
			_ = json.Unmarshal(b, &u.prev)
		}
	}
	return u
}

// turn renders the usage of the turn that just ended; ok is false when the agent reported none.
func (a *acpUsage) turn(reported *acp.Usage) (string, bool) {
	var rec model.Usage
	got := false
	if reported != nil {
		u := *reported
		if a.cumulative {
			u = a.since(u)
		}
		rec.InputTokens, rec.OutputTokens = int64(u.InputTokens), int64(u.OutputTokens)
		if u.CachedReadTokens != nil {
			rec.CacheRead = int64(*u.CachedReadTokens)
		}
		if u.CachedWriteTokens != nil {
			rec.CacheWrite = int64(*u.CachedWriteTokens)
		}
		if t := intOf(u.ThoughtTokens); t > 0 && u.TotalTokens >= u.InputTokens+u.OutputTokens+t {
			rec.OutputTokens += int64(t)
		}
		got = true
	}
	if c, ok := a.cl.sessionCost(); ok {
		d := c - a.costBase
		if d < 0 { // a new agent process counts from zero again
			d = c
		}
		a.costBase = c
		if d > 0 {
			rec.CostUSD = d
			got = true
		}
	}
	if !got {
		return "", false
	}
	rec.Turns = 1
	b, _ := json.Marshal(struct {
		Type string `json:"type"`
		model.Usage
	}{"usage", rec})
	return string(b), true
}

// since is the share of a running total that is new since the last one; a total lower than the
// last (another session, a reset) counts whole.
func (a *acpUsage) since(u acp.Usage) acp.Usage {
	p := a.prev
	a.prev = u
	if a.path != "" {
		if b, err := json.Marshal(u); err == nil && os.MkdirAll(filepath.Dir(a.path), 0o700) == nil {
			_ = os.WriteFile(a.path, b, 0o600)
		}
	}
	if u.InputTokens < p.InputTokens || u.OutputTokens < p.OutputTokens || u.TotalTokens < p.TotalTokens ||
		intOf(u.CachedReadTokens) < intOf(p.CachedReadTokens) || intOf(u.CachedWriteTokens) < intOf(p.CachedWriteTokens) ||
		intOf(u.ThoughtTokens) < intOf(p.ThoughtTokens) {
		return u
	}
	d := acp.Usage{InputTokens: u.InputTokens - p.InputTokens, OutputTokens: u.OutputTokens - p.OutputTokens,
		TotalTokens: u.TotalTokens - p.TotalTokens}
	if u.CachedReadTokens != nil {
		v := *u.CachedReadTokens - intOf(p.CachedReadTokens)
		d.CachedReadTokens = &v
	}
	if u.CachedWriteTokens != nil {
		v := *u.CachedWriteTokens - intOf(p.CachedWriteTokens)
		d.CachedWriteTokens = &v
	}
	if u.ThoughtTokens != nil {
		v := *u.ThoughtTokens - intOf(p.ThoughtTokens)
		d.ThoughtTokens = &v
	}
	return d
}

func intOf(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
