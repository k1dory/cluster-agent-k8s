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
//
// Both running totals belong to the session, and the session outlives the run: the next run
// continues it (resume or load) in a new agent process, whose first report still counts from
// the session's start (OpenCode sums the session's messages; Claude Code restores the session's
// cost; Hermes keeps its totals). The last totals are therefore kept per session on the
// workspace volume (usageDir), and a cost the agent reports while the session opens (a load
// replaying its history) is the base the run counts from.
type acpUsage struct {
	cl         *acpClient
	cumulative bool
	path       string    // where the session's last totals are kept ("" = memory only)
	prev       acp.Usage // the last cumulative usage seen
	costBase   float64   // the session cost at the end of the previous turn
}

// acpSessionTotals is what is kept of a session between runs.
type acpSessionTotals struct {
	Usage *acp.Usage `json:"usage,omitempty"` // cumulativeUsage agents only
	Cost  *float64   `json:"cost,omitempty"`
}

// cumulativeUsage names the agents (initialize agentInfo.name) whose PromptResponse.usage is the
// session's running total rather than the turn's.
var cumulativeUsage = map[string]bool{"hermes-agent": true}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func newACPUsage(agent, session string, cl *acpClient) *acpUsage {
	u := &acpUsage{cl: cl, cumulative: cumulativeUsage[agent]}
	if cl.usageDir != "" && session != "" {
		u.path = filepath.Join(cl.usageDir, unsafeFileChars.ReplaceAllString(session, "_")+".json")
		var kept acpSessionTotals
		if b, err := os.ReadFile(u.path); err == nil && json.Unmarshal(b, &kept) == nil {
			if kept.Usage != nil {
				u.prev = *kept.Usage
			}
			if kept.Cost != nil {
				u.costBase = *kept.Cost
			}
		}
	}
	// What the agent reported while the session opened is the session's total now.
	if c, ok := cl.sessionCost(); ok {
		u.costBase = c
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
	costSeen := false
	if c, ok := a.cl.sessionCost(); ok {
		costSeen = true
		d := c - a.costBase
		if d < 0 { // a total lower than the last: the agent counts from zero again
			d = c
		}
		a.costBase = c
		if d > 0 {
			rec.CostUSD = d
			got = true
		}
	}
	if a.cumulative && reported != nil || costSeen {
		a.save()
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

// save keeps the session's last totals for the run that continues it.
func (a *acpUsage) save() {
	if a.path == "" {
		return
	}
	kept := acpSessionTotals{Cost: &a.costBase}
	if a.cumulative {
		prev := a.prev
		kept.Usage = &prev
	}
	if b, err := json.Marshal(kept); err == nil && os.MkdirAll(filepath.Dir(a.path), 0o700) == nil {
		_ = os.WriteFile(a.path, b, 0o600)
	}
}

// since is the share of a running total that is new since the last one; a total lower than the
// last (another session, a reset) counts whole.
func (a *acpUsage) since(u acp.Usage) acp.Usage {
	p := a.prev
	a.prev = u
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
