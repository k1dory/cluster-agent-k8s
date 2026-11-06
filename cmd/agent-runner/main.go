// agent-runner is PID 1 of the agent container: it long-polls the control plane for runs,
// executes the harness command for each, streams its output back, forwards the user's
// messages into the harness (keeping a conversation open in stream-json mode) and serves the
// workspace file operations the control plane asks for.
//
// Everything goes through the mTLS gateway with the certificate agent-init obtained.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"agent-sandbox/internal/harness"
	"agent-sandbox/internal/model"
)

type client struct {
	base string
	http *http.Client
	// attempts: run id → the attempt the control plane handed the run out under, sent back as
	// X-Run-Attempt with every call about the run, so a run handed out again (this runner's
	// claim response was lost) refuses whatever still acts on the earlier attempt.
	attempts sync.Map
}

// stampRun adds X-Run-Attempt to a call about a run this runner holds (/agent/runs/{id}/...).
func (c *client) stampRun(req *http.Request) {
	rest, ok := strings.CutPrefix(req.URL.Path, "/agent/runs/")
	if !ok {
		return
	}
	id, _, _ := strings.Cut(rest, "/")
	if n, ok := c.attempts.Load(id); ok {
		req.Header.Set("X-Run-Attempt", fmt.Sprint(n))
	}
}

func newClient() (*client, error) {
	base := strings.TrimRight(os.Getenv("API_URL"), "/")
	if base == "" {
		return nil, errors.New("API_URL is not set")
	}
	cert, pool, err := loadIdentity(certDir())
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return &client{base: base, http: &http.Client{Transport: tr, Timeout: 3 * time.Minute}}, nil
}

func (c *client) do(ctx context.Context, method, path string, body []byte, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.stampRun(req)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return resp.StatusCode, json.Unmarshal(data, out)
	}
	return resp.StatusCode, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// The shutdown budget counts from the signal, whichever part of the way out looks first.
	context.AfterFunc(ctx, func() { shutdownDeadline(ctx, 0) })
	c, err := newClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-runner:", err)
		os.Exit(1)
	}
	workspaceRepo.ensure(ctx) // a failure is said again in the next run, which tries once more
	go serveFiles(ctx, c, workspaceRoot())
	// Harnesses that cannot present the client certificate reach the gateway through the
	// bridge (bridge.go); its address is in their environment.
	go serveGatewayBridge(ctx, certDir())
	_ = os.Setenv("SANDBOX_GATEWAY_BRIDGE", "http://"+gatewayBridgeAddr)
	fmt.Println("agent-runner: waiting for runs")
	serveAndDrain(ctx, c)
}

// serveAndDrain serves runs until ctx ends, then waits for what is left of a harness's process
// group to be stopped before the runner exits: as PID 1 its exit takes the container down, and a
// SIGKILL still pending would never be sent.
func serveAndDrain(ctx context.Context, c *client) {
	serveRuns(ctx, c)
	groupKills.Wait()
}

// serveRuns long-polls for runs and executes them one after the other until ctx ends (SIGTERM).
func serveRuns(ctx context.Context, c *client) {
	for ctx.Err() == nil {
		var run model.Run
		code, err := c.do(ctx, http.MethodGet, "/agent/runs/next?wait=30s", nil, &run)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintln(os.Stderr, "agent-runner: poll:", err)
			sleepCtx(ctx, 5*time.Second)
			continue
		}
		if code == http.StatusNoContent {
			continue
		}
		if run.Attempt > 0 {
			c.attempts.Store(run.ID, run.Attempt)
		}
		exit := execute(ctx, c, &run)
		// A result that was not acknowledged within the budget stays pending: the run is still
		// `running` on the control plane, and while the pod is healthy nothing else settles it. No
		// other run is taken before it is acknowledged; only SIGTERM gives it up.
		for !c.finish(ctx, run.ID, exit) {
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintf(os.Stderr, "agent-runner: the result of run %s is still pending: no new run is taken until it is acknowledged\n", run.ID)
		}
		c.attempts.Delete(run.ID)
	}
}

// finishBudget is how long finish insists on an acknowledgement.
var finishBudget = 10 * time.Minute

// finish reports the result and insists on an acknowledgement: the control plane's /finish is
// idempotent, so a lost response is retried (capped exponential backoff with jitter) for
// finishBudget. settled is true once the result is settled: acknowledged, or refused with a 4xx
// (the run is gone or not ours). false: the budget ran out, or SIGTERM (ctx) and the shutdown
// budget did; the caller keeps the result pending (serveRuns). The reconciler fails a run whose
// pod is gone, never one whose pod is healthy.
func (c *client) finish(ctx context.Context, runID string, exit int) (settled bool) {
	body, _ := json.Marshal(map[string]int{"exit_code": exit})
	dctx, done := deliveryCtx(ctx, finishBudget, 0)
	defer done()
	for attempt := 0; ; attempt++ {
		if attempt > 0 && !sleepCtx(dctx, backoff(attempt, time.Second, time.Minute)) {
			fmt.Fprintf(os.Stderr, "agent-runner: finish of run %s not acknowledged within the budget: %v\n", runID, dctx.Err())
			return false
		}
		code, err := c.do(dctx, http.MethodPost, "/agent/runs/"+runID+"/finish", body, nil)
		if err == nil {
			return true
		}
		if code >= 400 && code < 500 {
			fmt.Fprintln(os.Stderr, "agent-runner: finish refused:", err)
			return true
		}
		fmt.Fprintln(os.Stderr, "agent-runner: finish (will retry):", err)
	}
}

// cloneTimeout bounds one clone of $SANDBOX_REPO: a clone the gateway holds open, or a remote
// that never answers, would otherwise keep the runner from ever taking a run.
var cloneTimeout = 15 * time.Minute

// workspaceRepo remembers which repository the workspace holds a checkout of. A clone that
// failed (refused by the policy, timed out) is tried again before the next run, and the run's
// output says so: the harness then starts outside a checkout.
var workspaceRepo repoSync

type repoSync struct {
	mu    sync.Mutex
	ready string // "repo\x00dir" once the checkout is there
}

// ensure makes sure of the checkout; the result is a notice for the run's output, "" when there
// is nothing to say.
func (r *repoSync) ensure(ctx context.Context) string {
	key := os.Getenv("SANDBOX_REPO") + "\x00" + repoDir()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ready == key {
		return ""
	}
	if err := ensureRepo(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "agent-runner: repository:", err)
		return "[agent-runner] repository: " + err.Error() + ": the run starts outside the checkout"
	}
	r.ready = key
	return ""
}

// ensureRepo clones $SANDBOX_REPO into /workspace/repo once (the workspace volume persists
// across pods) so a run starts inside a checkout. Git goes through the gateway with the
// identity agent-init configured; the policy decides whether the clone is allowed.
func ensureRepo(ctx context.Context) error {
	repo := os.Getenv("SANDBOX_REPO")
	if repo == "" {
		return nil
	}
	dir := repoDir()
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		// The workspace volume persists; it must hold the repository that was asked for, not the
		// one a previous configuration cloned. A different origin is moved aside, never reused and
		// never deleted: it may hold work nobody pushed (uncommitted files, local commits).
		origin := gitOrigin(ctx, dir)
		if origin == repo {
			return nil
		}
		aside := fmt.Sprintf("%s.replaced-%d", dir, time.Now().UnixNano())
		fmt.Printf("agent-runner: workspace holds %q, sandbox repo is %q: moving the old checkout to %s\n", origin, repo, aside)
		if err := os.Rename(dir, aside); err != nil {
			return fmt.Errorf("workspace at %s belongs to another repository (%s) and could not be moved: %w", dir, origin, err)
		}
	}
	// An empty directory is git's to create (or a restored checkout's place). Anything else at
	// the path, a file or a directory with content, is left exactly as it is: the clone refuses it.
	if fi, err := os.Lstat(dir); err == nil && fi.IsDir() {
		if entries, err := os.ReadDir(dir); err == nil && len(entries) == 0 {
			_ = os.Remove(dir)
		}
	}
	// A checkout of this repository moved aside earlier (the repository changed and changed back)
	// comes back as it was, with its work: switching back and forth neither clones again nor
	// leaves one more copy each time.
	if back := displacedCheckout(ctx, dir, repo); back != "" {
		if _, err := os.Lstat(dir); os.IsNotExist(err) {
			fmt.Printf("agent-runner: restoring the checkout of %q from %s\n", repo, back)
			if err := os.Rename(back, dir); err == nil {
				return nil
			}
		}
	}
	// Whether the clone creates the path: Lstat, since Stat follows a symlink there and calls a
	// dangling one absent. Only what the clone created is cleaned up after it.
	_, statErr := os.Lstat(dir)
	created := os.IsNotExist(statErr)
	fmt.Println("agent-runner: cloning", repo, "into", dir)
	cctx, done := context.WithTimeout(ctx, cloneTimeout)
	defer done()
	cmd := exec.CommandContext(cctx, "/bin/sh", "-lc", `git clone -- "$SANDBOX_REPO" "$SANDBOX_REPO_DIR"`)
	cmd.Env = append(os.Environ(), "SANDBOX_REPO_DIR="+dir)
	// git runs helpers (git-remote-https) that hold its output: the group goes as a whole.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return signalGroup(cmd, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	var tail tailWriter
	cmd.Stdout, cmd.Stderr = os.Stdout, io.MultiWriter(os.Stderr, &tail)
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if fi, err := os.Lstat(dir); created && err == nil && fi.IsDir() {
		_ = os.RemoveAll(dir) // a clone cut short leaves a .git that would pass for a checkout
	}
	if errors.Is(cctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("git clone of %s did not finish within %s", repo, cloneTimeout)
	}
	if msg := tail.last(); msg != "" {
		return fmt.Errorf("git clone of %s: %v: %s", repo, err, msg)
	}
	return fmt.Errorf("git clone of %s: %w", repo, err)
}

// gitOrigin is the origin URL of the checkout at dir ("" when it has none).
func gitOrigin(ctx context.Context, dir string) string {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// displacedCheckout is the latest checkout of repo moved aside from dir (dir.replaced*), "" when
// there is none.
func displacedCheckout(ctx context.Context, dir, repo string) string {
	aside, _ := filepath.Glob(dir + ".replaced*")
	slices.Sort(aside) // .replaced-<unix nanoseconds>: the latest last
	for i := len(aside) - 1; i >= 0; i-- {
		if _, err := os.Stat(filepath.Join(aside[i], ".git")); err == nil && gitOrigin(ctx, aside[i]) == repo {
			return aside[i]
		}
	}
	return ""
}

// tailWriter keeps the end of what is written to it (git's last words on a failed clone).
type tailWriter struct{ b []byte }

func (t *tailWriter) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = t.b[len(t.b)-4096:]
	}
	return len(p), nil
}

// last is the last non-empty line written (progress lines end in \r, not \n).
func (t *tailWriter) last() string {
	lines := strings.FieldsFunc(string(t.b), func(r rune) bool { return r == '\n' || r == '\r' })
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return truncate(l, 500)
		}
	}
	return ""
}

// withMCPConfig makes a harness command load $SANDBOX_MCP_CONFIG: a command that runs claude
// (first word, after any VAR=value assignments) and does not mention --mcp-config or the
// variable gets ` --mcp-config "$SANDBOX_MCP_CONFIG"` added to that claude invocation; anything
// else is returned as is, the variable being in its environment.
func withMCPConfig(cmdline string) string {
	cmd := parseHarnessCommand(cmdline)
	if !cmd.runsClaude() || cmd.hasOption("--mcp-config") || strings.Contains(cmdline, "SANDBOX_MCP_CONFIG") {
		return cmdline
	}
	return cmd.withArgs(`--mcp-config "$SANDBOX_MCP_CONFIG"`)
}

// withInstructions gives the agent's instructions (SANDBOX_INSTRUCTIONS, from its definition) to
// a harness command that runs claude: ` --append-system-prompt "$SANDBOX_INSTRUCTIONS"` is added
// to that claude invocation unless the command already mentions the variable or sets a system
// prompt of its own (an option, not a word that happens to contain "system-prompt"). Anything
// else is returned as is, the variable being in its environment.
func withInstructions(cmdline string) string {
	cmd := parseHarnessCommand(cmdline)
	if !cmd.runsClaude() || strings.Contains(cmdline, "SANDBOX_INSTRUCTIONS") ||
		cmd.hasOption("--system-prompt", "--append-system-prompt", "--system-prompt-file", "--append-system-prompt-file") {
		return cmdline
	}
	return cmd.withArgs(`--append-system-prompt "$SANDBOX_INSTRUCTIONS"`)
}

// runsClaude reports whether a harness command's program (its first word after any VAR=value
// assignments) is claude.
func runsClaude(cmdline string) bool { return parseHarnessCommand(cmdline).runsClaude() }

// harnessCommand is the leading simple command of a harness command line, as the shell would
// split it: words with their quotes kept, and where the simple command ends — at an unquoted
// newline, `;`, `&` (not `&&`'s cousin in a redirection: `2>&1`, `&>`), `|` or a `#` comment,
// outside any `$(…)` or backtick substitution — so that an argument can be added to the
// program's invocation rather than to whatever follows it (a `&& echo done`, a trailing newline
// from a YAML block scalar) or to a command inside a substitution. The words are not
// evaluated: "$VAR" stays "$VAR"; options and the program are matched on their quote-stripped
// text, so `"--system-prompt"` is the option too.
type harnessCommand struct {
	line  string
	words []string
	end   int // index in line where the simple command ends (len(line) when it is all of it)
}

func parseHarnessCommand(line string) harnessCommand {
	c := harnessCommand{line: line, end: len(line)}
	var word strings.Builder
	inWord, single, double, escaped, backtick := false, false, false, false, false
	subst := 0 // depth of $( … )
	flush := func() {
		if inWord {
			c.words = append(c.words, word.String())
			word.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case escaped:
			word.WriteByte(ch)
			escaped = false
		case single:
			word.WriteByte(ch)
			single = ch != '\''
		case double:
			word.WriteByte(ch)
			if ch == '\\' && i+1 < len(line) {
				i++
				word.WriteByte(line[i])
			} else if ch == '"' {
				double = false
			}
		case backtick:
			word.WriteByte(ch)
			backtick = ch != '`'
		case ch == '\\':
			word.WriteByte(ch)
			escaped, inWord = true, true
		case ch == '\'':
			word.WriteByte(ch)
			single, inWord = true, true
		case ch == '"':
			word.WriteByte(ch)
			double, inWord = true, true
		case ch == '`':
			word.WriteByte(ch)
			backtick, inWord = true, true
		case ch == '$' && i+1 < len(line) && line[i+1] == '(':
			word.WriteString("$(")
			subst++
			inWord = true
			i++
		case subst > 0:
			word.WriteByte(ch)
			if ch == '(' {
				subst++
			} else if ch == ')' {
				subst--
			}
		case ch == '&' && (i+1 < len(line) && line[i+1] == '>' || inWord && (line[i-1] == '>' || line[i-1] == '<')):
			word.WriteByte(ch) // a redirection: &>, >&, <&
			inWord = true
		case ch == '\n' || ch == ';' || ch == '&' || ch == '|' || (ch == '#' && !inWord):
			flush()
			c.end = i
			return c
		case ch == ' ' || ch == '\t':
			flush()
		default:
			word.WriteByte(ch)
			inWord = true
		}
	}
	flush()
	return c
}

// unquoted is a word's text without its shell quoting, statically: quotes dropped, backslash
// escapes resolved, nothing expanded.
func unquoted(w string) string {
	var out strings.Builder
	single, double := false, false
	for i := 0; i < len(w); i++ {
		ch := w[i]
		switch {
		case single:
			if ch == '\'' {
				single = false
			} else {
				out.WriteByte(ch)
			}
		case ch == '\\' && !single && i+1 < len(w):
			i++
			out.WriteByte(w[i])
		case ch == '\'' && !double:
			single = true
		case ch == '"':
			double = !double
		default:
			out.WriteByte(ch)
		}
	}
	return out.String()
}

// program is the first word that is not a VAR=value assignment, quotes stripped.
func (c harnessCommand) program() string {
	for _, w := range c.words {
		if isAssignment(w) {
			continue
		}
		return unquoted(w)
	}
	return ""
}

func (c harnessCommand) runsClaude() bool { return filepath.Base(c.program()) == "claude" }

// hasOption reports whether one of the options is given to the program, as `--opt` or
// `--opt=value`, quoted or not; an option's value, or a word that merely contains the name,
// does not count.
func (c harnessCommand) hasOption(names ...string) bool {
	past := false
	for _, raw := range c.words {
		if !past {
			past = !isAssignment(raw) // the program
			continue
		}
		w := unquoted(raw)
		for _, n := range names {
			if w == n || strings.HasPrefix(w, n+"=") {
				return true
			}
		}
	}
	return false
}

// withArgs adds args to the program's invocation: before whatever follows the simple command,
// keeping that (a `&& …`, a comment, a trailing newline) where it was.
func (c harnessCommand) withArgs(args string) string {
	head := strings.TrimRight(c.line[:c.end], " \t")
	// The blanks that stood between the last word and what follows stay where they were; blanks
	// that trailed the whole line go.
	tail := c.line[len(head):]
	if strings.TrimSpace(tail) == "" && !strings.Contains(tail, "\n") {
		tail = ""
	}
	return head + " " + args + tail
}

// isAssignment: a leading NAME=value word of a simple command (the value may be quoted).
func isAssignment(w string) bool {
	eq := strings.IndexByte(w, '=')
	if eq <= 0 {
		return false
	}
	for i, r := range w[:eq] {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// writeMCPConfig renders SANDBOX_MCP_SERVERS ([{name, url}]) as a Claude Code MCP
// configuration ({"mcpServers": {name: {type: http, url}}}) at path. Returns how many servers
// it wrote; nothing is written for an empty value. The URLs are the gateway bridge's
// (bridge.go), as for an ACP agent: whether Claude Code's MCP client presents the pod's client
// certificate itself is not something the platform should depend on.
func writeMCPConfig(servers, path string) (string, int, error) {
	if strings.TrimSpace(servers) == "" {
		return "", 0, nil
	}
	list, err := parseMCPServers(servers)
	if err != nil {
		return "", 0, err
	}
	cfg := map[string]map[string]map[string]string{"mcpServers": {}}
	for _, s := range list {
		cfg["mcpServers"][s.Name] = map[string]string{"type": "http", "url": gatewayBridgeURL(s.URL)}
	}
	if len(cfg["mcpServers"]) == 0 {
		return "", 0, nil
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", 0, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", 0, err
	}
	return path, len(cfg["mcpServers"]), nil
}

// parseMCPServers reads SANDBOX_MCP_SERVERS ([{name, url}]); entries without both are left out.
func parseMCPServers(raw string) ([]model.MCPServer, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var list []model.MCPServer
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, fmt.Errorf("SANDBOX_MCP_SERVERS: %w", err)
	}
	return slices.DeleteFunc(list, func(s model.MCPServer) bool { return s.Name == "" || s.URL == "" }), nil
}

// harnessDir is where a harness starts: inside the checkout when there is one, else $PWD (else
// the runner's own directory).
func harnessDir() string {
	if _, err := os.Stat(filepath.Join(repoDir(), ".git")); err == nil {
		return repoDir()
	}
	if d := os.Getenv("PWD"); d != "" {
		return d
	}
	d, _ := os.Getwd()
	return d
}

// defaultResumePrompt tells a harness that a rollout interrupted it (a resume run without a
// message of its own).
const defaultResumePrompt = "The sandbox was restarted to update the agent. Continue the task where you left off."

// envValue is the value of name in env (the last one wins, as for exec), "" when absent.
func envValue(env []string, name string) string {
	for i := len(env) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(env[i], name+"="); ok {
			return v
		}
	}
	return ""
}

func repoDir() string {
	if d := os.Getenv("SANDBOX_REPO_DIR"); d != "" {
		return d
	}
	return "/workspace/repo"
}

// harnessOf is the harness a run starts: the configured one, or without one Claude over ACP
// (claude-agent-acp in the image).
func harnessOf(cmdline, input string) (string, string) {
	if cmdline == "" {
		cmdline = "claude-agent-acp"
		if input == "" {
			input = harness.InputACP
		}
	}
	return cmdline, input
}

// execute runs the harness for one task. Output lines are batched to the control plane;
// user input events are written to the harness stdin.
func execute(ctx context.Context, c *client, run *model.Run) int {
	cmdline, input := harnessOf(os.Getenv("HARNESS_CMD"), os.Getenv("HARNESS_INPUT"))
	// Everything before the harness runs (a clone can take minutes, a notice can wait on the
	// control plane) is under a watch for the run's cancel, and so is the run itself until
	// forwardInput, which acts on a cancel during the run, has taken over.
	w := watchCancel(ctx, c, run.ID)
	defer w.release()
	defer w.stop()
	notice := workspaceRepo.ensure(w.ctx)
	if notice != "" && !w.cancelled() {
		c.postWhile(ctx, w.ctx, run.ID, []string{notice})
	}
	if w.cancelled() {
		return c.cancelledBeforeStart(ctx, run.ID)
	}
	env := append(os.Environ(), "SANDBOX_TASK="+run.Task, "SANDBOX_RUN_ID="+run.ID)
	// The profile's harness files (a Codex config.toml, Claude Code settings) are in place
	// before the harness reads them. A file that cannot be written fails the run: a harness
	// started without its provider settings would talk to the wrong endpoint.
	if n, err := writeHarnessFiles(os.Getenv("SANDBOX_HARNESS_FILES"), os.Getenv("HOME")); err != nil {
		c.postWhile(ctx, w.ctx, run.ID, []string{"[agent-runner] harness files: " + err.Error()})
		return 1
	} else if n > 0 {
		fmt.Printf("agent-runner: %d harness file(s) written from the profile\n", n)
	}
	// The MCP servers the agent's connections give it (SANDBOX_MCP_SERVERS, JSON) become a
	// Claude Code mcp-config file. Every command that runs claude loads it (the run command and
	// the resume command, however the deployment spelled them) unless it names the file itself;
	// a command that is not claude gets $SANDBOX_MCP_CONFIG and decides on its own. The gateway
	// decides what each call may do; this only tells the harness where the servers are.
	mcpConfig := ""
	if path, n, err := writeMCPConfig(os.Getenv("SANDBOX_MCP_SERVERS"), filepath.Join(os.Getenv("HOME"), ".sandbox-mcp.json")); err != nil {
		fmt.Printf("agent-runner: mcp servers ignored: %v\n", err)
	} else if n > 0 {
		mcpConfig = path
		env = append(env, "SANDBOX_MCP_CONFIG="+path)
		fmt.Printf("agent-runner: %d mcp server(s) registered from the sandbox's connections\n", n)
	}
	// A resume run continues a conversation an earlier run started: after a rollout (the harness
	// is told to carry on) or as the next message of the conversation (the message is the
	// prompt). The harness's own session lives on the workspace volume.
	if run.ResumeOf != "" {
		env = append(env, "SANDBOX_RESUME_OF="+run.ResumeOf, "SANDBOX_SESSION="+run.Session)
		switch {
		case run.Mode == model.RunMessage:
			env = append(env, "SANDBOX_RESUME_PROMPT="+run.Task)
		case os.Getenv("SANDBOX_RESUME_PROMPT") == "":
			env = append(env, "SANDBOX_RESUME_PROMPT="+defaultResumePrompt)
		}
	}
	// An ACP harness is one program for the whole conversation: a resume is session/load of the
	// same agent, MCP servers go into session/new, the runner is its client (acp.go).
	if input == harness.InputACP {
		return executeACP(ctx, c, run, cmdline, env, w)
	}
	if run.ResumeOf != "" {
		switch resume := os.Getenv("HARNESS_RESUME_CMD"); {
		case run.Session != "" && resume != "":
			cmdline = resume
			fmt.Printf("agent-runner: run %s resumes %s (session %s)\n", run.ID, run.ResumeOf, run.Session)
		case run.Session != "":
			fmt.Printf("agent-runner: run %s resumes %s but HARNESS_RESUME_CMD is not set: running the task again\n", run.ID, run.ResumeOf)
		default:
			fmt.Printf("agent-runner: run %s resumes %s but no session id was captured: running the task again\n", run.ID, run.ResumeOf)
		}
	}
	if mcpConfig != "" {
		cmdline = withMCPConfig(cmdline)
	}
	// The agent definition's instructions are what makes a task like "triage the new incidents"
	// mean something: without them the harness sees the task text alone.
	if os.Getenv("SANDBOX_INSTRUCTIONS") != "" {
		cmdline = withInstructions(cmdline)
	}
	fmt.Printf("agent-runner: run %s: %q\n", run.ID, truncate(run.Task, 80))
	runCtx, cancel := context.WithCancel(w.ctx) // a cancel the watch sees stops the harness too
	defer cancel()
	cmd := exec.CommandContext(runCtx, "/bin/sh", "-lc", cmdline)
	// The harness and everything it starts are one process group, signalled as a whole, as the
	// ACP path does: the shell of a compound HARNESS_CMD (or a harness's own helpers) would
	// otherwise leave children running after the run, writing into the workspace. A cancelled run
	// is interrupted first, as Ctrl-C at a terminal interrupts its foreground group: `claude -p`
	// ends its turn and writes its result on SIGINT, while after SIGTERM alone the turn never
	// completes. SIGTERM follows if the harness is still there, SIGKILL after WaitDelay, and what is
	// left of the group once the harness exited is ended by endGroup.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	exited := make(chan struct{})
	grace := interruptGrace
	cmd.Cancel = func() error {
		err := signalGroup(cmd, syscall.SIGINT)
		go func() {
			select {
			case <-exited:
			case <-time.After(grace):
				_ = signalGroup(cmd, syscall.SIGTERM)
			}
		}()
		return err
	}
	cmd.WaitDelay = 20 * time.Second
	cmd.Env = env
	cmd.Dir = harnessDir()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 1
	}
	// The output pipe is the runner's own, not StdoutPipe's, which Wait closes as soon as the
	// harness exits (what it wrote last could still be unread). This one reads to EOF: until the
	// harness and whatever it left holding the pipe are gone (endGroup).
	stdout, out, err := os.Pipe()
	if err != nil {
		return 1
	}
	cmd.Stdout, cmd.Stderr = out, out
	if w.cancelled() {
		_, _, _ = stdin.Close(), stdout.Close(), out.Close()
		return c.cancelledBeforeStart(ctx, run.ID)
	}
	err = cmd.Start()
	_ = out.Close() // the harness has its copy
	if err != nil {
		_ = stdout.Close()
		c.post(ctx, run.ID, []string{"[agent-runner] cannot start harness: " + err.Error()})
		return 127
	}
	defer stdout.Close()
	// After SIGTERM the harness has until the shutdown budget leaves only enough time for its
	// output and the result: then its group is killed, and the output pipe closed shortly after
	// (what still holds it left the group).
	defer stopAtShutdown(ctx, func() {
		_ = signalGroup(cmd, syscall.SIGKILL)
		time.AfterFunc(500*time.Millisecond, func() { _ = stdout.Close() })
	})()
	chat := newChat(os.Getenv("HARNESS_INPUT"), chatIdle())
	// Harnesses that take the task on stdin get it first (in stream-json mode as the first user
	// message); CLI-arg harnesses just ignore it. In text mode that is all stdin ever carries, so
	// it is closed right after: `claude -p` (and any harness reading a non-terminal stdin) reads
	// stdin to its end before it starts, and an open pipe kept it waiting for the whole run.
	// The control plane delivers a text-mode harness's follow-up messages as the next run (the
	// resume command), never as input to this one.
	go func() {
		_, _ = io.WriteString(stdin, harness.FormatInput(chat.mode, run.Task))
		if chat.mode != harness.InputStreamJSON {
			_ = stdin.Close()
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); streamOutput(ctx, c, run.ID, stdout, chat.sawLine) }()
	go func() { defer wg.Done(); forwardInput(runCtx, c, run.ID, stdinSink{stdin, chat.mode}, cancel, chat) }()
	w.stop() // forwardInput reads the input from its start: a cancel since is its

	err = cmd.Wait()
	close(exited)
	cancel()
	endGroup(cmd)
	// The output ends when nothing of the group holds the pipe any more. A process that left the
	// group (setsid) and kept it is not waited for past the group's kill: the pipe is closed.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(groupKillDelay + 2*time.Second):
		_ = stdout.Close()
		<-done
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}

// errRunCancelled is the cause of a setup context ended by the run's cancel (watchCancel).
var errRunCancelled = errors.New("run cancelled")

// runWatch follows the run's input for a run.cancel from the moment the run is claimed until
// forwardInput has taken over (stop). ctx is the run's: it ends, cause errRunCancelled, when a
// cancel comes, whether the harness has started or not. Reading the input consumes nothing:
// forwardInput reads the same events from the start.
type runWatch struct {
	ctx     context.Context
	stop    func() // ends the watch; idempotent
	release func() // ends ctx once the run is over
}

func (w *runWatch) cancelled() bool { return errors.Is(context.Cause(w.ctx), errRunCancelled) }

func watchCancel(ctx context.Context, c *client, runID string) *runWatch {
	setup, cancel := context.WithCancelCause(ctx)
	watch, endWatch := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var after int64
		for watch.Err() == nil {
			var evs []model.Event
			code, err := c.do(watch, http.MethodGet, fmt.Sprintf("/agent/runs/%s/input?after=%d&wait=30s", runID, after), nil, &evs)
			if code == http.StatusConflict {
				fmt.Println("agent-runner: the run was handed out again: this attempt stops")
				cancel(errRunCancelled)
				return
			}
			if err != nil {
				if !sleepCtx(watch, 2*time.Second) {
					return
				}
				continue
			}
			for _, e := range evs {
				after = e.ID
				if e.Type == model.EventRunCancel {
					fmt.Println("agent-runner: run cancelled by the control plane before its harness took input")
					cancel(errRunCancelled)
					return
				}
			}
		}
	}()
	var once sync.Once
	return &runWatch{ctx: setup, stop: func() { once.Do(func() { endWatch(); <-done }) }, release: func() { cancel(context.Canceled) }}
}

// cancelledBeforeStart ends a run cancelled before its harness started: a notice (tried briefly:
// the run is over either way) and exit 1.
func (c *client) cancelledBeforeStart(ctx context.Context, runID string) int {
	dctx, done := deliveryCtx(ctx, 10*time.Second, finishReserve)
	defer done()
	_ = c.postBatch(dctx, runID, []string{"[agent-runner] run cancelled before the harness started"})
	return 1
}

// interruptGrace is how long a cancelled harness has after SIGINT before SIGTERM.
var interruptGrace = 5 * time.Second

// maxOutputLine is the longest output line the runner forwards. A longer one is dropped with a
// notice and reading goes on: a reader that stopped would leave the harness (or the ACP bridge)
// blocked on its next write for the rest of the run.
const maxOutputLine = 1 << 20

// readLines sends r's lines to out, each without its newline, until EOF or a read error; a line
// longer than max is replaced by a notice.
func readLines(r io.Reader, max int, out chan<- string) {
	br := bufio.NewReaderSize(r, 64<<10)
	var line []byte
	dropped := 0
	for {
		chunk, err := br.ReadSlice('\n')
		switch {
		case dropped > 0:
			dropped += len(chunk)
		case len(line)+len(chunk) > max+1: // +1: the newline does not count
			dropped = len(line) + len(chunk)
			line = line[:0]
		default:
			line = append(line, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if dropped > 0 {
			if err == nil {
				dropped-- // the newline
			}
			out <- fmt.Sprintf("[agent-runner] dropped an output line of %d bytes (limit %d)", dropped, max)
			dropped = 0
		} else if len(line) > 0 || err == nil {
			out <- strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		}
		line = line[:0]
		if err != nil {
			return
		}
	}
}

// streamOutput reads the harness's output lines into the run's spool until EOF, then waits for
// the spool to be delivered (outputDrainBudget at most): the run is finished only after its
// output. Reading never waits on the control plane (outputSpool). ctx is the process's signal
// context.
func streamOutput(ctx context.Context, c *client, runID string, r io.Reader, onLine func(string)) {
	spool := newOutputSpool(ctx, c, runID)
	spool.read(r, onLine)
	spool.close(outputDrainBudget)
}

func newBatchID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// storedCount pulls "stored N lines" out of a 413 message, so a retry resumes after them.
func storedCount(msg string) int {
	i := strings.Index(msg, "stored ")
	if i < 0 {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(msg[i:], "stored %d", &n)
	return n
}

// chatState tracks an open conversation: how messages are written to the harness and when
// the harness last finished a turn, so an idle conversation is closed (stdin), which lets
// the harness exit and the run finish. The next message then resumes the session in a new run.
type chatState struct {
	mode string
	idle time.Duration
	mu   sync.Mutex
	// turnEnd is when the harness last completed a turn with nothing sent since (zero: a turn
	// is in progress, or nothing has been said yet).
	turnEnd time.Time
	// now is the clock (nil: time.Now); a test sets its own.
	now func() time.Time
}

func (s *chatState) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func newChat(mode string, idle time.Duration) *chatState {
	if mode == "" {
		mode = harness.InputText
	}
	return &chatState{mode: mode, idle: idle}
}

// chatIdle reads HARNESS_CHAT_IDLE (seconds; 0 or unset = 10 minutes).
func chatIdle() time.Duration {
	var n int
	if _, err := fmt.Sscanf(os.Getenv("HARNESS_CHAT_IDLE"), "%d", &n); err != nil || n <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(n) * time.Second
}

// sawLine follows the harness's output: a turn end starts the idle countdown, and a turn (the
// agent speaking or calling a tool) stops it again — the harness went on with a message that was
// queued while the previous turn ran.
func (s *chatState) sawLine(line string) {
	switch {
	case harness.IsTurnEnd(line):
		s.turnEnded()
	default:
		if role, _ := harness.ParseMessage(line); role != "" {
			s.sent()
		}
	}
}

func (s *chatState) turnEnded() {
	s.mu.Lock()
	s.turnEnd = s.clock()
	s.mu.Unlock()
}

func (s *chatState) sent() {
	s.mu.Lock()
	s.turnEnd = time.Time{}
	s.mu.Unlock()
}

// idleFor is how long the conversation has been waiting for the user since the last turn; waiting
// is false while a turn runs or before the first one ended. (A turn that ended within the clock's
// last tick has waited 0 and is waiting all the same.)
func (s *chatState) idleFor() (idle time.Duration, waiting bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.turnEnd.IsZero() {
		return 0, false
	}
	return s.clock().Sub(s.turnEnd), true
}

// inputSink is where forwardInput hands the user's messages: the harness's stdin, or the
// prompts of an ACP session. Close ends the conversation.
type inputSink interface {
	Send(text string) error
	Close() error
}

// stdinSink writes each message to the harness's stdin in its input mode.
type stdinSink struct {
	w    io.WriteCloser
	mode string
}

func (s stdinSink) Send(text string) error {
	_, err := io.WriteString(s.w, harness.FormatInput(s.mode, text))
	return err
}

func (s stdinSink) Close() error { return s.w.Close() }

// streams says whether the harness takes messages during a run: stream-json on stdin, or the
// next prompt of an ACP session.
func (s *chatState) streams() bool {
	return s.mode == harness.InputStreamJSON || s.mode == harness.InputACP
}

// forwardInput delivers the user's messages to the harness: input events as lines (or
// stream-json user messages, or ACP prompts), run.cancel as a kill, run.close as end of input.
// In a streaming mode the conversation is also closed after the idle period following a
// completed turn.
func forwardInput(ctx context.Context, c *client, runID string, w inputSink, cancelRun context.CancelFunc, chat *chatState) {
	defer w.Close()
	var after int64
	// Once the conversation is closed (run.close, the idle period) the input is closed, and what
	// waits on a person is given up (promptQueue.Close); polling goes on for a cancel until the
	// run ends (ctx), so a harness still finishing its turn can always be stopped.
	closed := false
	closeInput := func(why string) {
		if !closed {
			closed = true
			fmt.Println("agent-runner: " + why)
			_ = w.Close()
		}
	}
	for ctx.Err() == nil {
		wait := 30 * time.Second
		if chat.streams() && !closed {
			if idle, waiting := chat.idleFor(); waiting {
				if idle >= chat.idle {
					closeInput(fmt.Sprintf("no message for %s after the last turn, closing the conversation", chat.idle))
					continue
				}
				wait = min(wait, chat.idle-idle)
			}
		}
		var evs []model.Event
		code, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/agent/runs/%s/input?after=%d&wait=%s", runID, after, wait.Round(time.Second)), nil, &evs)
		if code == http.StatusConflict {
			// Another attempt holds the run now (409 X-Run-Attempt): this one must not go on.
			fmt.Println("agent-runner: the run was handed out again: this attempt stops")
			cancelRun()
			return
		}
		if err != nil {
			if !sleepCtx(ctx, 2*time.Second) {
				return
			}
			continue
		}
		for _, e := range evs {
			after = e.ID
			switch e.Type {
			case model.EventRunCancel:
				fmt.Println("agent-runner: run cancelled by the control plane")
				cancelRun()
				return
			case model.EventRunClose:
				closeInput("conversation closed by the control plane")
				continue
			}
			if closed {
				continue // after the close: only a cancel matters
			}
			if e.Type == model.EventReply {
				// A person's answer to a request of the agent: to the conversation that holds it.
				if r, ok := w.(interface{ Reply(string) error }); ok {
					_ = r.Reply(e.Data)
				}
				continue
			}
			if !chat.streams() {
				// stdin is closed (see execute). The control plane turns a message for a
				// text-mode harness into the next run and refuses input, so this is an event
				// from before the sandbox's mode changed; cancel and close above still apply.
				fmt.Println("agent-runner: input event ignored: a text-mode harness reads only its task")
				continue
			}
			if err := w.Send(e.Data); err != nil {
				closeInput("input closed")
				continue
			}
			// An ACP conversation's activity is driveACP's: a message may join the turn in
			// progress (steering) or wait for it, and driveACP knows which.
			if chat.mode != harness.InputACP {
				chat.sent()
			}
		}
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
