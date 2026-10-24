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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"agent-sandbox/internal/catalog"
	"agent-sandbox/internal/model"
	"agent-sandbox/internal/plan"
)

const usage = `sandboxctl <command> [flags]

  create   -name shop (-slug backend-dev | -agent backend[@3]) -owner alice [-tenant t] [-repo url] [-idle 3600]
           [-ttl 86400] [-wake-on-preview=false] [-version stable] [-key idempotency-key]
  plan     -f file.yaml [-tenant t] [-json]         validate a bundle (--- separated documents) and show what apply would change; writes nothing
  apply    -f file.yaml [-tenant t] [-key k] [-json]  plan the bundle, then apply it through the controller: one
           transaction per step, continued by key after any failure (apply -resume <id> continues a stopped one)
  applies  [-tenant t] [-json]              applies of the scope, newest first; applies <id> shows one
  get      agent|environment|connection|binding <name> [-revision N] [-tenant t]
  list     agents|environments|connections|bindings [-tenant t]
  revisions agent|environment|connection|binding <name> [-tenant t]
  remove   agent|environment|connection|binding <name> [-tenant t]
  settings <tenant> [-revisions | -reset]     a tenant's quotas and allowed environments (admin writes with apply)
  list     [-tenant t] [-owner o] [-slug s] [-status running] [-n 100] [-after cursor]
  get      <sandbox>
  update   <sandbox> [-idle 600] [-ttl 0] [-wake-on-preview=true] [-repo url]
  run      <sandbox> "task text" [-key k]  queue a task (wakes the sandbox)
  chat     <sandbox> [-raw]                 talk to the agent: replay, then your lines go in, its answers come out
                                           (/attach <file>, /files [path], /close, /quit)
  messages <sandbox> [-after n] [-raw] [-json]   the conversation so far (one page)
  files    <sandbox> [path] [-depth 1] [-json]   list the workspace (wakes a sleeping sandbox)
  cat      <sandbox> <path>                 print a workspace file
  put      <sandbox> <local> [remote]       upload a file into the workspace (default uploads/<name>)
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
		agentRef := fs.String("agent", "", "AgentDefinition reference: name or name@revision (replaces -slug)")
		key := fs.String("key", "", "Idempotency-Key: a repeat with the same key returns the same sandbox")
		_ = fs.Parse(flags)
		req := map[string]any{"name": *name, "slug": *slug, "owner": *owner, "tenant": *tenant, "repo": *repo, "agent_version": *version, "agent_ref": *agentRef}
		if *agentRef == "" || fs.Lookup("wake-on-preview").Value.String() != "true" {
			req["wake_on_preview"] = *wop // with an agent, the environment's lifecycle decides unless set explicitly
		}
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
		if len(pos) > 0 && catalogPath(pos[0]) != "" {
			tenant := fs.String("tenant", "", "scope (admin: tenant or empty for shared)")
			_ = fs.Parse(flags)
			q := url.Values{}
			if *tenant != "" {
				q.Set("tenant", *tenant)
			}
			var items []model.CatalogItem
			if err := c.do("GET", "/v1/"+catalogPath(pos[0])+"?"+q.Encode(), nil, &items); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tTENANT\tREVISION\tUPDATED\tDESCRIPTION")
			for _, it := range items {
				tenant := it.Tenant
				if tenant == "" {
					tenant = "(shared)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", it.Name, tenant, it.Revision, it.CreatedAt.Format(time.RFC3339), it.Description)
			}
			tw.Flush()
			return nil
		}
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
		if len(pos) > 0 && catalogPath(pos[0]) != "" {
			rev := fs.Int("revision", 0, "revision (0 = latest)")
			tenant := fs.String("tenant", "", "scope (admin: tenant or empty for shared)")
			_ = fs.Parse(flags)
			q := url.Values{}
			if *rev > 0 {
				q.Set("revision", fmt.Sprint(*rev))
			}
			if *tenant != "" {
				q.Set("tenant", *tenant)
			}
			var out any
			if err := c.do("GET", "/v1/"+catalogPath(pos[0])+"/"+need(pos, 1, "name")+"?"+q.Encode(), nil, &out); err != nil {
				return err
			}
			printJSON(out)
			return nil
		}
		_ = fs.Parse(flags)
		var sb model.Sandbox
		if err := c.do("GET", "/v1/sandboxes/"+need(pos, 0, "sandbox"), nil, &sb); err != nil {
			return err
		}
		printJSON(sb)
	case "apply":
		file := fs.String("f", "", "YAML file: one document, or several separated by ---")
		tenant := fs.String("tenant", "", "default scope for documents without a tenant (admin)")
		key := fs.String("key", "", "idempotency key (default: the plan fingerprint)")
		resume := fs.String("resume", "", "continue the apply with this id instead of submitting a bundle")
		asJSON := fs.Bool("json", false, "print the apply as JSON")
		_ = fs.Parse(flags)
		q := ""
		if *tenant != "" {
			q = "?tenant=" + url.QueryEscape(*tenant)
		}
		var a model.Apply
		if *resume != "" {
			if err := c.do("POST", "/v1/applies/"+url.PathEscape(*resume)+"/resume", nil, &a); err != nil {
				return err
			}
		} else {
			if *file == "" {
				return errors.New("apply: -f is required")
			}
			raw, err := os.ReadFile(*file)
			if err != nil {
				return err
			}
			docs, err := catalog.ParseYAMLAll(raw)
			if err != nil {
				return err
			}
			var p plan.Plan
			if err := c.do("POST", "/v1/plan"+q, map[string]any{"documents": docs}, &p); err != nil {
				return err
			}
			if !p.Valid {
				printPlan(p)
				os.Exit(2)
			}
			if err := c.do("POST", "/v1/apply"+q, map[string]any{"documents": docs, "plan": p.Fingerprint, "key": *key}, &a); err != nil {
				return err
			}
		}
		if *asJSON {
			printJSON(a)
		} else {
			printApply(a)
		}
		if a.Status != model.ApplyDone {
			os.Exit(3)
		}
	case "applies":
		tenant := fs.String("tenant", "", "scope (admin)")
		asJSON := fs.Bool("json", false, "print JSON")
		_ = fs.Parse(flags)
		if len(pos) > 0 {
			var a model.Apply
			if err := c.do("GET", "/v1/applies/"+url.PathEscape(pos[0]), nil, &a); err != nil {
				return err
			}
			if *asJSON {
				printJSON(a)
			} else {
				printApply(a)
			}
			return nil
		}
		q := ""
		if *tenant != "" {
			q = "?tenant=" + url.QueryEscape(*tenant)
		}
		var list []model.Apply
		if err := c.do("GET", "/v1/applies"+q, nil, &list); err != nil {
			return err
		}
		if *asJSON {
			printJSON(list)
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSTATUS\tSTEPS\tCREATED\tBY\tERROR")
		for _, a := range list {
			done := 0
			for _, st := range a.Steps {
				if st.Status == model.StepDone || st.Status == model.StepSkipped {
					done++
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%d/%d\t%s\t%s\t%s\n", a.ID, a.Status, done, len(a.Steps), a.CreatedAt.Local().Format(time.RFC3339), a.Subject, a.Error)
		}
		tw.Flush()
	case "settings":
		revisions := fs.Bool("revisions", false, "show the history")
		reset := fs.Bool("reset", false, "return the tenant to the server defaults (admin)")
		_ = fs.Parse(flags)
		base := "/v1/tenants/" + url.PathEscape(need(pos, 0, "tenant")) + "/settings"
		switch {
		case *reset:
			return c.do("DELETE", base, nil, nil)
		case *revisions:
			var revs []model.CatalogItem
			if err := c.do("GET", base+"/revisions", nil, &revs); err != nil {
				return err
			}
			printRevisions(revs)
		default:
			var out any
			if err := c.do("GET", base, nil, &out); err != nil {
				return err
			}
			printJSON(out)
		}
	case "revisions", "remove":
		tenant := fs.String("tenant", "", "scope (admin: tenant or empty for shared)")
		_ = fs.Parse(flags)
		path := catalogPath(need(pos, 0, "agent|environment|connection|binding"))
		if path == "" {
			return errors.New("expected agent, environment, connection or binding")
		}
		q := ""
		if *tenant != "" {
			q = "?tenant=" + url.QueryEscape(*tenant)
		}
		if cmd == "remove" {
			return c.do("DELETE", "/v1/"+path+"/"+need(pos, 1, "name")+q, nil, nil)
		}
		var revs []model.CatalogItem
		if err := c.do("GET", "/v1/"+path+"/"+need(pos, 1, "name")+"/revisions"+q, nil, &revs); err != nil {
			return err
		}
		printRevisions(revs)
	case "run":
		key := fs.String("key", "", "Idempotency-Key: a repeat with the same key returns the same run")
		_ = fs.Parse(flags)
		id, task := need(pos, 0, "sandbox"), need(pos, 1, "task")
		var r model.Run
		if _, err := c.doH("POST", "/v1/sandboxes/"+id+"/runs", map[string]string{"task": task}, &r, map[string]string{"Idempotency-Key": *key}); err != nil {
			return err
		}
		printJSON(r)
	case "chat":
		raw := fs.Bool("raw", false, "also show harness output that is not a message")
		_ = fs.Parse(flags)
		return c.chat(need(pos, 0, "sandbox"), *raw)
	case "messages":
		after := fs.Int64("after", 0, "continue after this message id")
		raw := fs.Bool("raw", false, "include harness output that is not a message")
		asJSON := fs.Bool("json", false, "print JSON")
		_ = fs.Parse(flags)
		var msgs []model.Message
		if err := c.do("GET", fmt.Sprintf("/v1/sandboxes/%s/messages?after=%d&raw=%v", need(pos, 0, "sandbox"), *after, *raw), nil, &msgs); err != nil {
			return err
		}
		if *asJSON {
			printJSON(msgs)
			return nil
		}
		for _, m := range msgs {
			printMessage(m)
		}
	case "files":
		depth := fs.Int("depth", 1, "levels to list (1..8)")
		asJSON := fs.Bool("json", false, "print JSON")
		_ = fs.Parse(flags)
		dir := ""
		if len(pos) > 1 {
			dir = pos[1]
		}
		var out struct {
			Entries   []model.FSEntry `json:"entries"`
			Truncated bool            `json:"truncated"`
		}
		if err := c.do("GET", fmt.Sprintf("/v1/sandboxes/%s/files?path=%s&depth=%d", need(pos, 0, "sandbox"), url.QueryEscape(dir), *depth), nil, &out); err != nil {
			return err
		}
		if *asJSON {
			printJSON(out)
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "TYPE\tSIZE\tMODIFIED\tPATH")
		for _, e := range out.Entries {
			size := ""
			if e.Type == "file" {
				size = fmt.Sprint(e.Size)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Type, size, e.ModTime.Local().Format("2006-01-02 15:04"), e.Path)
		}
		tw.Flush()
		if out.Truncated {
			fmt.Println("(listing truncated)")
		}
	case "cat":
		_ = fs.Parse(flags)
		resp, err := c.raw("GET", "/v1/sandboxes/"+need(pos, 0, "sandbox")+"/files/content?path="+url.QueryEscape(need(pos, 1, "path")), "", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, err = io.Copy(os.Stdout, resp.Body)
		return err
	case "put":
		_ = fs.Parse(flags)
		local := need(pos, 1, "local file")
		remote := "uploads/" + filepath.Base(local)
		if len(pos) > 2 {
			remote = pos[2]
		}
		f, err := os.Open(local)
		if err != nil {
			return err
		}
		defer f.Close()
		resp, err := c.raw("PUT", "/v1/sandboxes/"+need(pos, 0, "sandbox")+"/files/content?path="+url.QueryEscape(remote), "application/octet-stream", f)
		if err != nil {
			return err
		}
		resp.Body.Close()
		fmt.Println("uploaded", remote)
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
				Sandbox  string `json:"sandbox"`
				Slug     string `json:"slug"`
				From     string `json:"from"`
				Mode     string `json:"mode"`
				Reason   string `json:"reason"`
				RunID    string `json:"run_id"`
				ResumeID string `json:"resume_id"`
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

// catalogPath maps a CLI noun to the API path of a versioned resource ("" when it is not one).
func catalogPath(noun string) string {
	switch noun {
	case "agent", "agents":
		return "agents"
	case "environment", "environments", "env":
		return "environments"
	case "connection", "connections":
		return "connections"
	case "binding", "bindings":
		return "bindings"
	}
	return ""
}

// kindPath maps a document kind to its API path ("" for kinds without a plain path).
func kindPath(kind string) string {
	return map[string]string{model.KindAgent: "agents", model.KindEnvironment: "environments",
		model.KindConnection: "connections", model.KindBinding: "bindings"}[kind]
}

func printPlan(p plan.Plan) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ACTION\tKIND\tTENANT\tNAME\tREVISION\tCHANGES")
	for _, c := range p.Changes {
		detail := ""
		switch {
		case len(c.Errors) > 0:
			detail = strings.Join(c.Errors, "; ")
		case c.Action == plan.ActionNoop:
			detail = "-"
		default:
			parts := make([]string, 0, len(c.Diff))
			for _, f := range c.Diff {
				switch {
				case f.From == nil:
					parts = append(parts, fmt.Sprintf("+%s=%v", f.Path, f.To))
				case f.To == nil:
					parts = append(parts, fmt.Sprintf("-%s", f.Path))
				default:
					parts = append(parts, fmt.Sprintf("%s: %v -> %v", f.Path, f.From, f.To))
				}
			}
			detail = strings.Join(parts, ", ")
		}
		rev := fmt.Sprintf("%d -> %d", c.CurrentRevision, c.CurrentRevision+1)
		if c.Action == plan.ActionNoop || c.Action == plan.ActionInvalid {
			rev = fmt.Sprint(c.CurrentRevision)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", c.Action, c.Kind, c.Tenant, c.Name, rev, detail)
	}
	tw.Flush()
	for _, e := range p.Errors {
		fmt.Println("bundle:", e)
	}
	fmt.Printf("bundle %s: %d to create, %d to update, %d unchanged, %d invalid\n", p.Bundle, p.Summary.Create, p.Summary.Update, p.Summary.Noop, p.Summary.Invalid)
}

func printApply(a model.Apply) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "STEP\tKIND\tTENANT\tNAME\tACTION\tSTATUS\tREVISION\tERROR")
	for i, st := range a.Steps {
		rev := ""
		if st.Revision > 0 {
			rev = fmt.Sprint(st.Revision)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", i+1, st.Kind, st.Tenant, st.Name, st.Action, st.Status, rev, st.Error)
	}
	tw.Flush()
	fmt.Printf("apply %s: %s", a.ID, a.Status)
	if a.Error != "" {
		fmt.Printf(" (%s)", a.Error)
	}
	fmt.Println()
	if a.Status != model.ApplyDone {
		fmt.Printf("continue with: sandboxctl apply -resume %s\n", a.ID)
	}
}

func printRevisions(revs []model.CatalogItem) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "REVISION\tCREATED\tBY\tDELETED\tDESCRIPTION")
	for _, r := range revs {
		deleted := ""
		if r.DeletedAt != nil {
			deleted = r.DeletedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", r.Revision, r.CreatedAt.Format(time.RFC3339), r.CreatedBy, deleted, r.Description)
	}
	tw.Flush()
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

// raw performs a request with an arbitrary body and returns the response (the caller closes
// it); a non-2xx status is an error with the server's message.
func (c *cli) raw(method, path, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return nil, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, e.Error)
	}
	return resp, nil
}

func printMessage(m model.Message) {
	at := m.At.Local().Format("15:04:05")
	switch m.Role {
	case model.RoleUser:
		fmt.Printf("%s you » %s\n", at, m.Text)
	case model.RoleAssistant:
		fmt.Printf("%s agent: %s\n", at, m.Text)
	case model.RoleTool:
		fmt.Printf("%s   ⚙ %s\n", at, m.Text)
	case model.RoleLog:
		fmt.Printf("%s   | %s\n", at, m.Text)
	default:
		fmt.Printf("%s [%s]\n", at, m.Text)
	}
}

// chat replays the conversation, follows it live and sends what you type. Lines starting
// with / are commands: /attach <file>, /files [path], /close, /quit.
func (c *cli) chat(id string, raw bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var after int64
	for {
		var msgs []model.Message
		resp, err := c.raw("GET", fmt.Sprintf("/v1/sandboxes/%s/messages?after=%d&raw=%v", id, after, raw), "", nil)
		if err != nil {
			return err
		}
		next, _ := strconv.ParseInt(resp.Header.Get("X-Next-Cursor"), 10, 64)
		_ = json.NewDecoder(resp.Body).Decode(&msgs)
		resp.Body.Close()
		for _, m := range msgs {
			printMessage(m)
		}
		if next <= after {
			break
		}
		after = next
	}
	fmt.Println("— type a message and press Enter; /attach <file>, /files [path], /close, /quit —")
	go c.followMessages(ctx, id, after, raw)
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for ctx.Err() == nil && sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var err error
		switch cmd, arg, _ := strings.Cut(line, " "); cmd {
		case "/quit", "/exit":
			return nil
		case "/close":
			err = c.do("POST", "/v1/sandboxes/"+id+"/messages/close", nil, nil)
		case "/files":
			var out struct {
				Entries []model.FSEntry `json:"entries"`
			}
			if err = c.do("GET", "/v1/sandboxes/"+id+"/files?path="+url.QueryEscape(strings.TrimSpace(arg)), nil, &out); err == nil {
				for _, e := range out.Entries {
					fmt.Printf("  %-8s %s\n", e.Type, e.Path)
				}
			}
		case "/attach":
			local := strings.TrimSpace(arg)
			remote := "uploads/" + filepath.Base(local)
			var f *os.File
			if f, err = os.Open(local); err == nil {
				var resp *http.Response
				resp, err = c.raw("PUT", "/v1/sandboxes/"+id+"/files/content?path="+url.QueryEscape(remote), "application/octet-stream", f)
				f.Close()
				if err == nil {
					resp.Body.Close()
					err = c.do("POST", "/v1/sandboxes/"+id+"/messages", map[string]any{"text": "", "attachments": []string{remote}}, nil)
				}
			}
		default:
			err = c.do("POST", "/v1/sandboxes/"+id+"/messages", map[string]any{"text": line}, nil)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "chat:", err)
		}
	}
	return nil
}

// followMessages prints the conversation as it grows (SSE, reconnecting with Last-Event-ID).
func (c *cli) followMessages(ctx context.Context, id string, after int64, raw bool) {
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/v1/sandboxes/%s/messages/stream?raw=%v", c.base, id, raw), nil)
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "text/event-stream")
		if after > 0 {
			req.Header.Set("Last-Event-ID", fmt.Sprint(after))
		}
		resp, err := (&http.Client{}).Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			fmt.Fprintln(os.Stderr, "chat: stream:", resp.Status)
			return
		}
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var m model.Message
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m) != nil {
				continue
			}
			after = m.ID
			if m.Role != model.RoleUser { // what you typed is already on your screen
				printMessage(m)
			}
		}
		resp.Body.Close()
	}
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
