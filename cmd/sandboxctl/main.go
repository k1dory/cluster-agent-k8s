// sandboxctl is a thin CLI over the sandboxd API, so every interaction (create a sandbox,
// hand it a task, watch the output, answer the agent, sleep, wake, preview, delete) is one
// command and nobody has to hand-craft curl calls. Configuration: SANDBOXD_URL, SANDBOXD_TOKEN.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"agent-sandbox/internal/model"
)

const usage = `sandboxctl <command> [flags]

  create   -name shop -slug backend-dev -owner alice [-tenant t] [-repo url] [-idle 3600]
  list
  get      <sandbox>
  run      <sandbox> "task text"          queue a task (wakes the sandbox)
  runs     <sandbox>                      list runs
  watch    <sandbox> [-run id] [-after n] follow the event stream (SSE)
  say      <sandbox> <run> "message"      send input to a running agent
  cancel   <sandbox> <run>
  sleep    <sandbox> [-force]
  wake     <sandbox>
  preview  <sandbox> -port 3000 [-access link|sso|members]   (-port 0 removes)
  delete   <sandbox>
  policies

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
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, e.Error)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
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
		_ = fs.Parse(flags)
		req := map[string]any{"name": *name, "slug": *slug, "owner": *owner, "tenant": *tenant, "repo": *repo}
		if *idle >= 0 {
			req["idle_timeout"] = *idle
		}
		var sb model.Sandbox
		if err := c.do("POST", "/v1/sandboxes", req, &sb); err != nil {
			return err
		}
		printJSON(sb)
	case "list":
		var sbs []model.Sandbox
		if err := c.do("GET", "/v1/sandboxes", nil, &sbs); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tSLUG\tOWNER\tSTATUS\tIP\tN\tIDLE\tPREVIEW")
		for _, s := range sbs {
			pv := ""
			if s.Preview != nil {
				pv = fmt.Sprintf("%s:%d (%s)", s.Preview.Host, s.Preview.Port, s.Preview.Access)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", s.ID, s.Name, s.Slug, s.Owner, s.Status, s.IP, s.Instance,
				time.Since(s.LastActivity).Round(time.Second), pv)
		}
		tw.Flush()
	case "get":
		_ = fs.Parse(flags)
		var sb model.Sandbox
		if err := c.do("GET", "/v1/sandboxes/"+need(pos, 0, "sandbox"), nil, &sb); err != nil {
			return err
		}
		printJSON(sb)
	case "run":
		_ = fs.Parse(flags)
		id, task := need(pos, 0, "sandbox"), need(pos, 1, "task")
		var r model.Run
		if err := c.do("POST", "/v1/sandboxes/"+id+"/runs", map[string]string{"task": task}, &r); err != nil {
			return err
		}
		printJSON(r)
	case "runs":
		_ = fs.Parse(flags)
		var rs []model.Run
		if err := c.do("GET", "/v1/sandboxes/"+need(pos, 0, "sandbox")+"/runs", nil, &rs); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "RUN\tSTATUS\tEXIT\tCREATED\tTASK")
		for _, r := range rs {
			t := strings.ReplaceAll(r.Task, "\n", " ")
			if len(t) > 60 {
				t = t[:60] + "…"
			}
			fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n", r.ID, r.Status, r.ExitCode, r.CreatedAt.Format(time.RFC3339), t)
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
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
	return nil
}

func need(pos []string, i int, what string) string {
	if len(pos) <= i {
		fmt.Fprintln(os.Stderr, "missing argument:", what)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	return pos[i]
}

// watch follows the SSE stream, reconnecting with Last-Event-ID, and prints events readably.
func (c *cli) watch(id, runID string, after int64, raw bool) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	for ctx.Err() == nil {
		url := fmt.Sprintf("%s/v1/sandboxes/%s/events?after=%d", c.base, id, after)
		if runID != "" {
			url += "&run=" + runID
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
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
			switch e.Type {
			case model.EventRunOutput:
				fmt.Println(e.Data)
			case model.EventInput:
				fmt.Printf("» %s\n", e.Data)
			default:
				fmt.Printf("[%s] %s %s %s\n", e.At.Format("15:04:05"), e.Type, e.RunID, e.Data)
			}
			if e.Type == model.EventRunDone && runID != "" && e.RunID == runID {
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
