// Package usage turns runs and events into accounting: what a tenant, an agent slug, a
// sandbox or a run consumed over a period, and what it cost.
//
// Sources:
//   - runs: model tokens and cost as reported by the harness, wall time of each run;
//   - egress.* events: requests the agent made through the gateway, allowed and denied;
//   - status events: how long the sandbox pod was up (compute time), independent of runs.
package usage

import (
	"context"
	"fmt"
	"sort"
	"time"

	"agent-sandbox/internal/model"
	"agent-sandbox/internal/store"
)

// Group keys for a report.
const (
	ByTenant  = "tenant"
	BySlug    = "slug"
	BySandbox = "sandbox"
	ByRun     = "run"
	ByDay     = "day"
)

// Pricing converts resource time into money. Model cost comes from the harness already.
type Pricing struct {
	PodHourUSD float64 `yaml:"pod_hour_usd" json:"pod_hour_usd"` // one sandbox pod running for one hour
}

// Totals is one accounting line.
type Totals struct {
	Runs          int     `json:"runs"`
	RunsDone      int     `json:"runs_done"`
	RunsFailed    int     `json:"runs_failed"`
	RunsCancelled int     `json:"runs_cancelled"`
	RunSeconds    float64 `json:"run_seconds"`
	PodSeconds    float64 `json:"pod_seconds"`
	InputTokens   int64   `json:"input_tokens"`
	OutputTokens  int64   `json:"output_tokens"`
	CacheRead     int64   `json:"cache_read_tokens"`
	CacheWrite    int64   `json:"cache_write_tokens"`
	Turns         int     `json:"turns"`
	EgressAllowed int64   `json:"egress_allowed"`
	EgressDenied  int64   `json:"egress_denied"`
	ModelUSD      float64 `json:"model_usd"`   // as reported by the harness
	ComputeUSD    float64 `json:"compute_usd"` // pod_seconds × pricing
	TotalUSD      float64 `json:"total_usd"`
}

func (t *Totals) add(o Totals) {
	t.Runs += o.Runs
	t.RunsDone += o.RunsDone
	t.RunsFailed += o.RunsFailed
	t.RunsCancelled += o.RunsCancelled
	t.RunSeconds += o.RunSeconds
	t.PodSeconds += o.PodSeconds
	t.InputTokens += o.InputTokens
	t.OutputTokens += o.OutputTokens
	t.CacheRead += o.CacheRead
	t.CacheWrite += o.CacheWrite
	t.Turns += o.Turns
	t.EgressAllowed += o.EgressAllowed
	t.EgressDenied += o.EgressDenied
	t.ModelUSD += o.ModelUSD
}

// Row is Totals for one group key.
type Row struct {
	Key       string `json:"key"`
	Tenant    string `json:"tenant,omitempty"`
	Slug      string `json:"slug,omitempty"`
	SandboxID string `json:"sandbox_id,omitempty"`
	RunID     string `json:"run_id,omitempty"`
	Totals
}

// Report is the answer to GET /v1/usage.
type Report struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	GroupBy string    `json:"group_by"`
	Pricing Pricing   `json:"pricing"`
	Total   Totals    `json:"total"`
	Rows    []Row     `json:"rows"`
}

// Query selects what to account.
type Query struct {
	Tenant, Slug, SandboxID, RunID string
	From, To                       time.Time
	GroupBy                        string
}

type dims struct{ tenant, slug, sandbox, run string }

func (d dims) key(by string, day time.Time) string {
	switch by {
	case ByTenant:
		return d.tenant
	case BySlug:
		return d.slug
	case BySandbox:
		return d.sandbox
	case ByRun:
		return d.run
	case ByDay:
		return day.UTC().Format("2006-01-02")
	}
	return ""
}

// Build computes the report.
func Build(ctx context.Context, st store.Store, q Query, pr Pricing, now time.Time) (*Report, error) {
	switch q.GroupBy {
	case "", ByTenant, BySlug, BySandbox, ByRun, ByDay:
	default:
		return nil, fmt.Errorf("group_by must be one of tenant, slug, sandbox, run, day")
	}
	if q.To.IsZero() {
		q.To = now
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-30 * 24 * time.Hour)
	}
	f := store.Filter{Tenant: q.Tenant, Slug: q.Slug, SandboxID: q.SandboxID, RunID: q.RunID, From: q.From, To: q.To}
	rep := &Report{From: q.From, To: q.To, GroupBy: q.GroupBy, Pricing: pr}
	rows := map[string]*Row{}
	var order []string
	rowFor := func(d dims, day time.Time) *Row {
		k := d.key(q.GroupBy, day)
		r, ok := rows[k]
		if !ok {
			r = &Row{Key: k}
			switch q.GroupBy {
			case ByTenant:
				r.Tenant = d.tenant
			case BySlug:
				r.Slug = d.slug
			case BySandbox:
				r.SandboxID, r.Tenant, r.Slug = d.sandbox, d.tenant, d.slug
			case ByRun:
				r.RunID, r.SandboxID, r.Tenant, r.Slug = d.run, d.sandbox, d.tenant, d.slug
			}
			rows[k] = r
			order = append(order, k)
		}
		return r
	}

	runs, err := st.QueryRuns(ctx, f)
	if err != nil {
		return nil, err
	}
	for _, r := range runs {
		t := Totals{Runs: 1, RunSeconds: r.Seconds(now), InputTokens: r.Usage.InputTokens, OutputTokens: r.Usage.OutputTokens,
			CacheRead: r.Usage.CacheRead, CacheWrite: r.Usage.CacheWrite, Turns: r.Usage.Turns, ModelUSD: r.Usage.CostUSD}
		switch r.Status {
		case model.RunDone:
			t.RunsDone = 1
		case model.RunFailed:
			t.RunsFailed = 1
		case model.RunCancelled:
			t.RunsCancelled = 1
		}
		rowFor(dims{r.Tenant, r.Slug, r.SandboxID, r.ID}, r.CreatedAt).add(t)
	}

	ef := f
	ef.Types = []string{model.EventEgressOK, model.EventEgressDen}
	counts, err := st.CountEvents(ctx, ef)
	if err != nil {
		return nil, err
	}
	for _, c := range counts {
		t := Totals{}
		if c.Type == model.EventEgressOK {
			t.EgressAllowed = c.N
		} else {
			t.EgressDenied = c.N
		}
		rowFor(dims{c.Tenant, c.Slug, c.SandboxID, c.RunID}, c.Day).add(t)
	}

	// Pod time comes from status transitions; it is a property of the sandbox, not of a run.
	if q.GroupBy != ByRun && q.RunID == "" {
		for sb, secs := range podSeconds(ctx, st, f, now) {
			for _, s := range secs {
				rowFor(dims{sb.tenant, sb.slug, sb.sandbox, ""}, s.start).add(Totals{PodSeconds: s.seconds})
			}
		}
	}

	for _, k := range order {
		r := rows[k]
		r.ComputeUSD = r.PodSeconds / 3600 * pr.PodHourUSD
		r.TotalUSD = r.ModelUSD + r.ComputeUSD
		rep.Total.add(r.Totals)
		rep.Rows = append(rep.Rows, *r)
	}
	rep.Total.ComputeUSD = rep.Total.PodSeconds / 3600 * pr.PodHourUSD
	rep.Total.TotalUSD = rep.Total.ModelUSD + rep.Total.ComputeUSD
	sort.SliceStable(rep.Rows, func(i, j int) bool { return rep.Rows[i].Key < rep.Rows[j].Key })
	return rep, nil
}

type span struct {
	start   time.Time
	seconds float64
}

// podSeconds sums the intervals during which each sandbox had a pod, clipped to the window.
// A pod is up from the `waking` status until `stopping`, `sleeping`, `error` or `deleting`.
func podSeconds(ctx context.Context, st store.Store, f store.Filter, now time.Time) map[dims][]span {
	// Status events before the window matter: a pod that woke yesterday is still up today.
	// The store caps a page (Postgres: 1000 rows), so the log is walked page by page.
	sf := store.Filter{Tenant: f.Tenant, Slug: f.Slug, SandboxID: f.SandboxID, Types: []string{model.EventStatus}, To: f.To, Limit: 1000}
	var evs []*model.Event
	for {
		page, err := st.QueryEvents(ctx, sf)
		if err != nil {
			return nil
		}
		evs = append(evs, page...)
		if len(page) < sf.Limit {
			break
		}
		sf.AfterID = page[len(page)-1].ID
	}
	open := map[dims]time.Time{}
	out := map[dims][]span{}
	clip := func(d dims, from, to time.Time) {
		if from.Before(f.From) {
			from = f.From
		}
		if to.After(f.To) {
			to = f.To
		}
		if to.After(from) {
			out[d] = append(out[d], span{start: from, seconds: to.Sub(from).Seconds()})
		}
	}
	for _, e := range evs {
		d := dims{e.Tenant, e.Slug, e.SandboxID, ""}
		switch model.SandboxStatus(e.Data) {
		case model.StatusWaking:
			if _, up := open[d]; !up {
				open[d] = e.At
			}
		case model.StatusStopping, model.StatusSleeping, model.StatusError, model.StatusDeleting:
			if start, up := open[d]; up {
				clip(d, start, e.At)
				delete(open, d)
			}
		}
	}
	end := f.To
	if end.After(now) {
		end = now
	}
	for d, start := range open {
		clip(d, start, end)
	}
	return out
}
