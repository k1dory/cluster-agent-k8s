// sandboxctl is a thin CLI over the sandboxd API, so every interaction (create a sandbox,
// hand it a task, watch the output, answer the agent, sleep, wake, preview, delete) is one
// command and nobody has to hand-craft curl calls. Configuration: SANDBOXD_URL, SANDBOXD_TOKEN.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"agent-sandbox/internal/model"
)

const usage = `sandboxctl <command> [flags]

  create   -name shop -slug backend-dev -owner alice [-tenant t] [-repo url] [-idle 3600] [-ttl 86400]
           [-wake-on-preview=false] [-version stable] [-key idempotency-key]
  list     [-tenant t] [-owner o] [-slug s] [-status running] [-n 100] [-after cursor]
  get      <sandbox>
  update   <sandbox> [-idle 600] [-ttl 0] [-wake-on-preview=true] [-repo url]
  run      <sandbox> "task text" [-key k]  queue a task (wakes the sandbox)
  runs     <sandbox> [run] [-status queued] [-n 100] [-after cursor]
  watch    <sandbox> [-run id] [-after n]  follow the event stream (SSE)
  events   <sandbox> [-run id] [-after n] [-n 1000] [-json]   one JSON page of the log
  say      <sandbox> <run> "message"       send input to a queued or running agent
  cancel   <sandbox> <run>
  sleep    <sandbox> [-force]
  wake     <sandbox>
  touch    <sandbox>                       count as user activity (postpones sleep)
  preview  <sandbox> -port 3000 [-access link|sso|members]   (-port 0 removes)
  ticket   <sandbox> -user alice [-next /path]                sign-in link for a members/sso preview
  delete   <sandbox>
  policies
  whoami
  version                                  control plane build, agent versions, environment versions per slug
  rollout  -version 1.5.0 (-sandbox sb_1 | -instance 42 | -slug backend-dev | -all) [-percent 10] [-force] [-resume=false]
           move agents to a version: sleeping ones on next wake, idle ones now, busy ones when their run ends;
           -force interrupts runs and re-queues them as resume runs; -percent keeps a canary share
  usage    [-tenant t] [-slug s] [-sandbox id] [-run id] [-since 720h | -from DATE -to DATE] [-by tenant|slug|sandbox|run|day] [-json]
  trace    [-tenant t] [-slug s] [-sandbox id] [-run id] [-since 24h] [-type egress.deny,run.finished|all] [-n 500] [-f] [-json]

Environment: SANDBOXD_URL (default http://127.0.0.1:8080), SANDBOXD_TOKEN.
`

type cli struct {
	base, token string
	http        *http.Client
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	c := &cli{base: strings.TrimRight(env("SANDBOXD_URL", "http://127.0.0.1:8080"), "/"), token: os.Getenv("SANDBOXD_TOKEN"), http: &http.Client{Timeout: 60 * time.Second}}
	if err := c.run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "sandboxctl:", err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (c *cli) do(method, path string, body any, out any) error {
	_, err := c.doH(method, path, body, out, nil)
	return err
}

// doH is do with extra request headers; it returns the response headers (paging cursors).
func (c *cli) doH(method, path string, body any, out any, hdr map[string]string) (http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct {
			Error     string `json:"error"`
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		msg := fmt.Sprintf("%s %s: %s: %s", method, path, resp.Status, e.Error)
		if e.Code != "" {
			msg += " [" + e.Code
			if e.RequestID != "" {
				msg += " rid=" + e.RequestID
			}
			msg += "]"
		}
		return resp.Header, errors.New(msg)
	}
	if out != nil && len(data) > 0 {
		return resp.Header, json.Unmarshal(data, out)
	}
	return resp.Header, nil
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

// splitArgs lets flags follow positional arguments (`sandboxctl sleep sb_1 -force`), which
// Go's flag package does not do on its own.
func splitArgs(args []string) (pos, flags []string) {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			return args[:i], args[i:]
		}
	}
	return args, nil
}

func (c *cli) run(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	pos, flags := splitArgs(args)
	if cmd == "create" {
		pos, flags = nil, args
	}
	switch cmd {
	case "create":
		name := fs.String("name", "", "project name (DNS label)")
		slug := fs.String("slug", "", "agent definition slug")
		owner := fs.String("owner", "", "owner login")
		tenant := fs.String("tenant", "", "tenant (defaults to owner)")
		repo := fs.String("repo", "", "repository URL")
		idle := fs.Int("idle", -1, "idle timeout seconds (default server-side 3600, 0 = never)")
		ttl := fs.Int("ttl", 0, "delete the sandbox after this many seconds (0 = keep)")
		wop := fs.Bool("wake-on-preview", true, "wake a sleeping sandbox when its preview is opened")
		version := fs.String("version", "", "agent version name (see `sandboxctl version`); default server-side")
		key := fs.String("key", "", "Idempotency-Key: a repeat with the same key returns the same sandbox")
		_ = fs.Parse(flags)
		req := map[string]any{"name": *name, "slug": *slug, "owner": *owner, "tenant": *tenant, "repo": *repo, "wake_on_preview": *wop, "agent_version": *version}
		if *idle >= 0 {
			req["idle_timeout"] = *idle
		}
		if *ttl > 0 {
			req["ttl"] = *ttl
		}
		var sb model.Sandbox
		if _, err := c.doH("POST", "/v1/sandboxes", req, &sb, map[string]string{"Idempotency-Key": *key}); err != nil {
			return err
		}
		printJSON(sb)
	case "list":
		q := url.Values{}
		for _, name := range []string{"tenant", "owner", "slug", "status", "after"} {
			name := name
			fs.Func(name, "filter: "+name, func(v string) error { q.Set(name, v); return nil })
		}
		n := fs.Int("n", 100, "page size")
		_ = fs.Parse(flags)
		q.Set("limit", fmt.Sprint(*n))
		var sbs []model.Sandbox
		hdr, err := c.doH("GET", "/v1/sandboxes?"+q.Encode(), nil, &sbs, nil)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tSLUG\tOWNER\tTENANT\tSTATUS\tIP\tN\tAGENT\tENV\tIDLE\tEXPIRES\tPREVIEW")
		for _, s := range sbs {
			pv, exp := "", ""
			if s.Preview != nil {
				pv = fmt.Sprintf("%s:%d (%s)", s.Preview.Host, s.Preview.Port, s.Preview.Access)
			}
			if s.ExpiresAt != nil {
				exp = time.Until(*s.ExpiresAt).Round(time.Minute).String()
			}
			agent := shortImage(s.AgentVersion)
			if s.DesiredVersion != "" {
				agent += " → " + shortImage(s.DesiredVersion)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\n", s.ID, s.Name, s.Slug, s.Owner, s.Tenant, s.Status, s.IP, s.Instance,
				agent, s.EnvVersion, time.Since(s.LastActivity).Round(time.Second), exp, pv)
		}
		tw.Flush()
		if cur := hdr.Get("X-Next-Cursor"); cur != "" {
			fmt.Fprintf(os.Stderr, "more: -after %s\n", cur)
		}
	case "update":
		req := map[string]any{}
		fs.Func("idle", "idle timeout seconds (0 = never)", func(v string) error { n, err := strconv.Atoi(v); req["idle_timeout"] = n; return err })
		fs.Func("ttl", "seconds from now until deletion (0 removes the expiry)", func(v string) error { n, err := strconv.Atoi(v); req["ttl"] = n; return err })
		fs.Func("wake-on-preview", "true | false", func(v string) error { b, err := strconv.ParseBool(v); req["wake_on_preview"] = b; return err })
		fs.Func("repo", "repository URL", func(v string) error { req["repo"] = v; return nil })
		_ = fs.Parse(flags)
		var sb model.Sandbox
		if err := c.do("PATCH", "/v1/sandboxes/"+need(pos, 0, "sandbox"), req, &sb); err != nil {
			return err
		}
		printJSON(sb)
	case "get":
		_ = fs.Parse(flags)
		var sb model.Sandbox
		if err := c.do("GET", "/v1/sandboxes/"+need(pos, 0, "sandbox"), nil, &sb); err != nil {
			return err
		}
		printJSON(sb)
	case "run":
		key := fs.String("key", "", "Idempotency-Key: a repeat with the same key returns the same run")
		_ = fs.Parse(flags)
		id, task := need(pos, 0, "sandbox"), need(pos, 1, "task")
		var r model.Run
		if _, err := c.doH("POST", "/v1/sandboxes/"+id+"/runs", map[string]string{"task": task}, &r, map[string]string{"Idempotency-Key": *key}); err != nil {
			return err
		}
		printJSON(r)
	case "runs":
		q := url.Values{}
		for _, name := range []string{"status", "after"} {
			name := name
			fs.Func(name, "filter: "+name, func(v string) error { q.Set(name, v); return nil })
		}
		n := fs.Int("n", 100, "page size")
		_ = fs.Parse(flags)
		if len(pos) > 1 {
			var r model.Run
			if err := c.do("GET", "/v1/sandboxes/"+pos[0]+"/runs/"+pos[1], nil, &r); err != nil {
				return err
			}
			printJSON(r)
			return nil
		}
		q.Set("limit", fmt.Sprint(*n))
		var rs []model.Run
		hdr, err := c.doH("GET", "/v1/sandboxes/"+need(pos, 0, "sandbox")+"/runs?"+q.Encode(), nil, &rs, nil)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "RUN\tSTATUS\tEXIT\tCOST $\tTOKENS IN/OUT\tCREATED\tTASK")
		for _, r := range rs {
			t := strings.ReplaceAll(r.Task, "\n", " ")
			if len(t) > 60 {
				t = t[:60] + "…"
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%.4f\t%d/%d\t%s\t%s\n", r.ID, r.Status, r.ExitCode, r.Usage.CostUSD, r.Usage.InputTokens, r.Usage.OutputTokens,
				r.CreatedAt.Format(time.RFC3339), t)
		}
		tw.Flush()
		if cur := hdr.Get("X-Next-Cursor"); cur != "" {
			fmt.Fprintf(os.Stderr, "more: -after %s\n", cur)
		}
	case "events":
		runID := fs.String("run", "", "only this run")
		after := fs.Int64("after", 0, "events after this id")
		n := fs.Int("n", 1000, "page size")
		raw := fs.Bool("json", false, "print raw event JSON")
		_ = fs.Parse(flags)
		path := fmt.Sprintf("/v1/sandboxes/%s/events?stream=false&after=%d&limit=%d", need(pos, 0, "sandbox"), *after, *n)
		if *runID != "" {
			path += "&run=" + url.QueryEscape(*runID)
		}
		var evs []model.Event
		hdr, err := c.doH("GET", path, nil, &evs, nil)
		if err != nil {
			return err
		}
		for _, e := range evs {
			if *raw {
				b, _ := json.Marshal(e)
				fmt.Println(string(b))
			} else {
				printTrace(e)
			}
		}
		if cur := hdr.Get("X-Next-Cursor"); cur != "" {
			fmt.Fprintf(os.Stderr, "more: -after %s\n", cur)
		}
	case "touch":
		_ = fs.Parse(flags)
		return c.do("POST", "/v1/sandboxes/"+need(pos, 0, "sandbox")+"/touch", nil, nil)
	case "ticket":
		user := fs.String("user", "", "user the ticket is issued to")
		next := fs.String("next", "/", "path to open after sign-in")
		_ = fs.Parse(flags)
		var out map[string]string
		if err := c.do("POST", "/v1/sandboxes/"+need(pos, 0, "sandbox")+"/preview/ticket", map[string]string{"user": *user, "next": *next}, &out); err != nil {
			return err
		}
		fmt.Println(out["redirect"])
	case "whoami":
		var out map[string]any
		if err := c.do("GET", "/v1/whoami", nil, &out); err != nil {
			return err
		}
		printJSON(out)
	case "version":
		var out map[string]any
		if err := c.do("GET", "/v1/version", nil, &out); err != nil {
			return err
		}
		printJSON(out)
	case "rollout":
		req := map[string]any{}
		version := fs.String("version", "", "target agent version (name or, as admin, image reference)")
		sandbox := fs.String("sandbox", "", "one sandbox id")
		instance := fs.Int("instance", 0, "one agent by its identity number")
		slug := fs.String("slug", "", "every sandbox of this slug")
		all := fs.Bool("all", false, "every sandbox (of your tenant; everything as admin)")
		percent := fs.Int("percent", 0, "canary: only this share of the selection (deterministic)")
		force := fs.Bool("force", false, "interrupt runs in progress and re-queue them as resume runs")
		fs.Func("resume", "true | false: queue a resume run for each interrupted run (default true)", func(v string) error {
			b, err := strconv.ParseBool(v)
			req["resume"] = b
			return err
		})
		_ = fs.Parse(flags)
		req["version"], req["sandbox"], req["instance"], req["slug"], req["all"], req["percent"], req["force"] =
			*version, *sandbox, *instance, *slug, *all, *percent, *force
		var out struct {
			Version  string `json:"version"`
			Selected int    `json:"selected"`
			Targeted int    `json:"targeted"`
			Items    []struct {
				Sandbox, Slug, From, Mode, Reason, RunID, ResumeID string
			} `json:"items"`
		}
		if err := c.do("POST", "/v1/rollouts", req, &out); err != nil {
			return err
		}
		fmt.Printf("rollout to %s: %d selected, %d targeted\n", out.Version, out.Selected, out.Targeted)
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SANDBOX\tSLUG\tFROM\tMODE\tRUN\tRESUME\tNOTE")
		for _, it := range out.Items {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", it.Sandbox, it.Slug, shortImage(it.From), it.Mode, it.RunID, it.ResumeID, it.Reason)
		}
		tw.Flush()
	case "watch":
		runID := fs.String("run", "", "only this run")
		after := fs.Int64("after", 0, "replay from event id")
		raw := fs.Bool("json", false, "print raw event JSON")
		_ = fs.Parse(flags)
		return c.watch(need(pos, 0, "sandbox"), *runID, *after, *raw)
	case "say":
		_ = fs.Parse(flags)
		id, run, text := need(pos, 0, "sandbox"), need(pos, 1, "run"), need(pos, 2, "message")
		return c.do("POST", "/v1/sandboxes/"+id+"/runs/"+run+"/input", map[string]string{"text": text}, nil)
	case "cancel":
		_ = fs.Parse(flags)
		var r model.Run
		if err := c.do("POST", "/v1/sandboxes/"+need(pos, 0, "sandbox")+"/runs/"+need(pos, 1, "run")+"/cancel", nil, &r); err != nil {
			return err
		}
		printJSON(r)
	case "sleep":
		force := fs.Bool("force", false, "cancel a run in progress")
		_ = fs.Parse(flags)
		var sb model.Sandbox
		if err := c.do("POST", fmt.Sprintf("/v1/sandboxes/%s/sleep?force=%v", need(pos, 0, "sandbox"), *force), nil, &sb); err != nil {
			return err
		}
		printJSON(sb)
	case "wake":
		_ = fs.Parse(flags)
		var sb model.Sandbox
		if err := c.do("POST", "/v1/sandboxes/"+need(pos, 0, "sandbox")+"/wake", nil, &sb); err != nil {
			return err
		}
		printJSON(sb)
	case "preview":
		port := fs.Int("port", 0, "application port inside the sandbox (0 removes the preview)")
		access := fs.String("access", "", "link | sso | members")
		_ = fs.Parse(flags)
		var sb model.Sandbox
		if err := c.do("PUT", "/v1/sandboxes/"+need(pos, 0, "sandbox")+"/preview", map[string]any{"port": *port, "access": *access}, &sb); err != nil {
			return err
		}
		printJSON(sb)
	case "delete":
		_ = fs.Parse(flags)
		return c.do("DELETE", "/v1/sandboxes/"+need(pos, 0, "sandbox"), nil, nil)
	case "policies":
		var ps []string
		if err := c.do("GET", "/v1/policies", nil, &ps); err != nil {
			return err
		}
		fmt.Println(strings.Join(ps, "\n"))
	case "usage":
		q := scopeFlags(fs)
		by := fs.String("by", "", "group rows by tenant | slug | sandbox | run | day")
		raw := fs.Bool("json", false, "print the full report as JSON")
		_ = fs.Parse(flags)
		if *by != "" {
			q.Set("group_by", *by)
		}
		var rep usageReport
		if err := c.do("GET", "/v1/usage?"+q.Encode(), nil, &rep); err != nil {
			return err
		}
		if *raw {
			printJSON(rep)
			return nil
		}
		printUsage(rep)
	case "trace":
		q := scopeFlags(fs)
		typ := fs.String("type", "", "comma-separated event types, or all (default: everything but run.output)")
		n := fs.Int("n", 500, "max events")
		follow := fs.Bool("f", false, "follow live (SSE)")
		raw := fs.Bool("json", false, "print raw event JSON")
		_ = fs.Parse(flags)
		if *typ != "" {
			q.Set("type", *typ)
		}
		q.Set("limit", fmt.Sprint(*n))
		if *follow {
			return c.follow("/v1/trace?stream=true&"+q.Encode(), *raw, nil)
		}
		var evs []model.Event
		if err := c.do("GET", "/v1/trace?"+q.Encode(), nil, &evs); err != nil {
			return err
		}
		for _, e := range evs {
			if *raw {
				b, _ := json.Marshal(e)
				fmt.Println(string(b))
			} else {
				printTrace(e)
			}
		}
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

// shortImage trims a registry path to the last component (name:tag) for tables.
func shortImage(ref string) string {
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		return ref[i+1:]
	}
	return ref
}

func need(pos []string, i int, what string) string {
	if len(pos) <= i {
		fmt.Fprintln(os.Stderr, "missing argument:", what)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	return pos[i]
}

// scopeFlags registers the filters shared by usage and trace and returns them as query values.
func scopeFlags(fs *flag.FlagSet) url.Values {
	q := url.Values{}
	for _, name := range []string{"tenant", "slug", "sandbox", "run", "since", "from", "to"} {
		name := name
		fs.Func(name, "filter: "+name, func(v string) error { q.Set(name, v); return nil })
	}
	return q
}

type usageReport struct {
	From, To time.Time
	GroupBy  string `json:"group_by"`
	Total    usageTotals
	Rows     []struct {
		Key string
		usageTotals
	}
}

type usageTotals struct {
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
	EgressAllowed int64   `json:"egress_allowed"`
	EgressDenied  int64   `json:"egress_denied"`
	ModelUSD      float64 `json:"model_usd"`
	ComputeUSD    float64 `json:"compute_usd"`
	TotalUSD      float64 `json:"total_usd"`
}

func printUsage(rep usageReport) {
	fmt.Printf("%s → %s\n", rep.From.Local().Format("2006-01-02 15:04"), rep.To.Local().Format("2006-01-02 15:04"))
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	key := strings.ToUpper(rep.GroupBy)
	if key == "" {
		key = "SCOPE"
	}
	fmt.Fprintf(tw, "%s\tRUNS\tOK/FAIL/CANCEL\tRUN TIME\tPOD TIME\tIN TOK\tOUT TOK\tCACHE R/W\tEGRESS OK/DENY\tMODEL $\tCOMPUTE $\tTOTAL $\n", key)
	line := func(k string, t usageTotals) {
		fmt.Fprintf(tw, "%s\t%d\t%d/%d/%d\t%s\t%s\t%d\t%d\t%d/%d\t%d/%d\t%.4f\t%.4f\t%.4f\n", k, t.Runs, t.RunsDone, t.RunsFailed, t.RunsCancelled,
			dur(t.RunSeconds), dur(t.PodSeconds), t.InputTokens, t.OutputTokens, t.CacheRead, t.CacheWrite, t.EgressAllowed, t.EgressDenied,
			t.ModelUSD, t.ComputeUSD, t.TotalUSD)
	}
	if rep.GroupBy != "" {
		for _, r := range rep.Rows {
			line(r.Key, r.usageTotals)
		}
	}
	line("total", rep.Total)
	tw.Flush()
}

func dur(sec float64) string {
	return (time.Duration(sec) * time.Second).Round(time.Second).String()
}

func printTrace(e model.Event) {
	who := e.Tenant + "/" + e.Slug
	switch e.Type {
	case model.EventEgressOK, model.EventEgressDen:
		var eg model.Egress
		_ = json.Unmarshal([]byte(e.Data), &eg)
		mark := "→"
		extra := ""
		if e.Type == model.EventEgressDen {
			mark = "✗"
			extra = fmt.Sprintf("  %d %s", eg.Code, eg.Reason)
		}
		fmt.Printf("%s %-28s %s %s %s %s%s\n", e.At.Local().Format("15:04:05"), who, e.SandboxID, mark, eg.Method, eg.Host+eg.Path, extra)
	case model.EventRunOutput:
		fmt.Printf("%s %-28s %s   %s\n", e.At.Local().Format("15:04:05"), who, e.SandboxID, e.Data)
	default:
		fmt.Println(strings.TrimRight(fmt.Sprintf("%s %-28s %s %s %s %s", e.At.Local().Format("15:04:05"), who, e.SandboxID, e.Type, e.RunID, e.Data), " "))
	}
}

// watch follows one sandbox's SSE stream and prints events readably.
func (c *cli) watch(id, runID string, after int64, raw bool) error {
	path := fmt.Sprintf("/v1/sandboxes/%s/events?after=%d", id, after)
	if runID != "" {
		path += "&run=" + runID
	}
	return c.follow(path, raw, func(e model.Event) bool {
		switch e.Type {
		case model.EventRunOutput:
			fmt.Println(e.Data)
		case model.EventInput:
			fmt.Printf("» %s\n", e.Data)
		default:
			fmt.Printf("[%s] %s %s %s\n", e.At.Local().Format("15:04:05"), e.Type, e.RunID, e.Data)
		}
		return e.Type == model.EventRunDone && runID != "" && e.RunID == runID
	})
}

// follow reads an SSE endpoint, reconnecting with Last-Event-ID. print returns true to stop;
// nil means the trace format.
func (c *cli) follow(path string, raw bool, print func(model.Event) bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var after int64
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, "GET", c.base+path, nil)
		if after > 0 {
			req.Header.Set("Last-Event-ID", fmt.Sprint(after))
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "text/event-stream")
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintln(os.Stderr, "watch:", err, "(retrying)")
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("events: %s: %s", resp.Status, strings.TrimSpace(string(b)))
		}
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var e model.Event
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e); err != nil {
				continue
			}
			after = e.ID
			if raw {
				fmt.Println(strings.TrimPrefix(line, "data: "))
				continue
			}
			if print == nil {
				printTrace(e)
				continue
			}
			if print(e) {
				resp.Body.Close()
				return nil
			}
		}
		resp.Body.Close()
		if ctx.Err() == nil {
			time.Sleep(time.Second)
		}
	}
	return nil
}
