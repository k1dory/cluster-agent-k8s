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
	"crypto/x509"
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
}

func newClient() (*client, error) {
	certDir := os.Getenv("CERT_DIR")
	if certDir == "" {
		certDir = "/certs"
	}
	base := strings.TrimRight(os.Getenv("API_URL"), "/")
	if base == "" {
		return nil, errors.New("API_URL is not set")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "tls.crt"), filepath.Join(certDir, "tls.key"))
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	pool := x509.NewCertPool()
	if gw, err := os.ReadFile(filepath.Join(certDir, "gateway-ca.crt")); err == nil && len(bytes.TrimSpace(gw)) > 0 {
		pool.AppendCertsFromPEM(gw)
	} else {
		pool, _ = x509.SystemCertPool()
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
	c, err := newClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-runner:", err)
		os.Exit(1)
	}
	if err := ensureRepo(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "agent-runner: repository:", err)
	}
	go serveFiles(ctx, c, workspaceRoot())
	fmt.Println("agent-runner: waiting for runs")
	for ctx.Err() == nil {
		var run model.Run
		code, err := c.do(ctx, http.MethodGet, "/agent/runs/next?wait=30s", nil, &run)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintln(os.Stderr, "agent-runner: poll:", err)
			time.Sleep(5 * time.Second)
			continue
		}
		if code == http.StatusNoContent {
			continue
		}
		exit := execute(ctx, c, &run)
		c.finish(run.ID, exit)
	}
}

// finish reports the result and insists on an acknowledgement: the control plane's /finish is
// idempotent, so a lost response is retried (with backoff, for several minutes) rather than
// leaving the run `running` forever. 4xx means the run is gone or not ours: stop.
func (c *client) finish(runID string, exit int) {
	body, _ := json.Marshal(map[string]int{"exit_code": exit})
	// There is nothing else to do until the result is delivered: retry until it is, or until the
	// control plane says the run is not ours any more (4xx). The pod has no other work queued
	// before this run is settled, and the reconciler fails the run if the pod itself dies.
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(min(1<<min(attempt, 6), 60)) * time.Second)
		}
		code, err := c.do(context.Background(), http.MethodPost, "/agent/runs/"+runID+"/finish", body, nil)
		if err == nil {
			return
		}
		if code >= 400 && code < 500 {
			fmt.Fprintln(os.Stderr, "agent-runner: finish refused:", err)
			return
		}
		fmt.Fprintln(os.Stderr, "agent-runner: finish (will retry):", err)
	}
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
		// one a previous configuration cloned. A different origin is moved aside, never reused.
		out, err := exec.CommandContext(ctx, "git", "-C", dir, "remote", "get-url", "origin").Output()
		origin := strings.TrimSpace(string(out))
		if err == nil && origin == repo {
			return nil
		}
		aside := fmt.Sprintf("%s.replaced-%d", dir, time.Now().Unix())
		fmt.Printf("agent-runner: workspace holds %q, sandbox repo is %q: moving the old checkout to %s\n", origin, repo, aside)
		if err := os.Rename(dir, aside); err != nil {
			return fmt.Errorf("workspace at %s belongs to another repository (%s) and could not be moved: %w", dir, origin, err)
		}
	}
	fmt.Println("agent-runner: cloning", repo, "into", dir)
	cmd := exec.CommandContext(ctx, "/bin/sh", "-lc", `git clone -- "$SANDBOX_REPO" "$SANDBOX_REPO_DIR"`)
	cmd.Env = append(os.Environ(), "SANDBOX_REPO_DIR="+dir)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// withMCPConfig makes a harness command load $SANDBOX_MCP_CONFIG: a command that runs claude
// (first word, after any VAR=value assignments) and does not mention --mcp-config or the
// variable gets ` --mcp-config "$SANDBOX_MCP_CONFIG"` appended; anything else is returned as
// is, the variable being in its environment.
func withMCPConfig(cmdline string) string {
	if strings.Contains(cmdline, "--mcp-config") || strings.Contains(cmdline, "SANDBOX_MCP_CONFIG") {
		return cmdline
	}
	program := ""
	for _, w := range strings.Fields(cmdline) {
		if strings.Contains(w, "=") && !strings.HasPrefix(w, "-") {
			continue // VAR=value prefix
		}
		program = w
		break
	}
	if filepath.Base(program) != "claude" {
		return cmdline
	}
	return strings.TrimRight(cmdline, " \t") + ` --mcp-config "$SANDBOX_MCP_CONFIG"`
}

// writeMCPConfig renders SANDBOX_MCP_SERVERS ([{name, url}]) as a Claude Code MCP
// configuration ({"mcpServers": {name: {type: http, url}}}) at path. Returns how many servers
// it wrote; nothing is written for an empty value.
func writeMCPConfig(servers, path string) (string, int, error) {
	if strings.TrimSpace(servers) == "" {
		return "", 0, nil
	}
	var list []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := json.Unmarshal([]byte(servers), &list); err != nil {
		return "", 0, fmt.Errorf("SANDBOX_MCP_SERVERS: %w", err)
	}
	cfg := map[string]map[string]map[string]string{"mcpServers": {}}
	for _, s := range list {
		if s.Name == "" || s.URL == "" {
			continue
		}
		cfg["mcpServers"][s.Name] = map[string]string{"type": "http", "url": s.URL}
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

func repoDir() string {
	if d := os.Getenv("SANDBOX_REPO_DIR"); d != "" {
		return d
	}
	return "/workspace/repo"
}

// execute runs the harness for one task. Output lines are batched to the control plane;
// user input events are written to the harness stdin.
func execute(ctx context.Context, c *client, run *model.Run) int {
	cmdline := os.Getenv("HARNESS_CMD")
	if cmdline == "" {
		cmdline = `claude -p "$SANDBOX_TASK" --output-format stream-json --verbose`
	}
	env := append(os.Environ(), "SANDBOX_TASK="+run.Task, "SANDBOX_RUN_ID="+run.ID)
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
			env = append(env, "SANDBOX_RESUME_PROMPT=The sandbox was restarted to update the agent. Continue the task where you left off.")
		}
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
	fmt.Printf("agent-runner: run %s: %q\n", run.ID, truncate(run.Task, 80))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "/bin/sh", "-lc", cmdline)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 20 * time.Second
	cmd.Env = env
	cmd.Dir = os.Getenv("PWD")
	if _, err := os.Stat(filepath.Join(repoDir(), ".git")); err == nil {
		cmd.Dir = repoDir() // the harness starts inside the checkout
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 1
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 1
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		c.post(run.ID, []string{"[agent-runner] cannot start harness: " + err.Error()})
		return 127
	}
	chat := newChat(os.Getenv("HARNESS_INPUT"), chatIdle())
	// Harnesses that take the task on stdin get it first (in stream-json mode as the first user
	// message); CLI-arg harnesses just ignore it.
	go func() { _, _ = io.WriteString(stdin, harness.FormatInput(chat.mode, run.Task)) }()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); streamOutput(c, run.ID, stdout, chat.sawLine) }()
	go func() { defer wg.Done(); forwardInput(runCtx, c, run.ID, stdin, cancel, chat) }()

	err = cmd.Wait()
	cancel()
	wg.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}

func streamOutput(c *client, runID string, r io.Reader, onLine func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var batch []string
	flush := func() {
		if len(batch) > 0 {
			c.post(runID, batch)
			batch = nil
		}
	}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	lines := make(chan string)
	go func() {
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				flush()
				return
			}
			fmt.Println(l) // also to pod stdout for kubectl logs / log shipping
			if onLine != nil {
				onLine(l)
			}
			batch = append(batch, l)
			if len(batch) >= 50 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// post ships a batch of output lines and insists on an acknowledgement: transient failures
// are retried, a 413 splits the batch, a single oversized line is dropped with a notice
// (the control plane keeps lines before it, so a retry never duplicates them).
func (c *client) post(runID string, lines []string) {
	body := []byte(strings.Join(lines, "\n") + "\n")
	batch := newBatchID()
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<attempt) * 500 * time.Millisecond)
		}
		req, _ := http.NewRequest(http.MethodPost, c.base+"/agent/runs/"+runID+"/events", bytes.NewReader(body))
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("X-Batch-Id", batch) // same id on every retry: the server skips lines it already stored
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		switch {
		case resp.StatusCode < 300:
			return
		case resp.StatusCode == http.StatusRequestEntityTooLarge:
			var ack struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(data, &ack)
			stored := storedCount(ack.Error)
			rest := lines[min(stored, len(lines)):]
			if len(rest) == len(lines) && len(lines) == 1 {
				fmt.Fprintf(os.Stderr, "agent-runner: dropping a %d-byte output line: %s\n", len(lines[0]), ack.Error)
				return
			}
			if len(rest) == len(lines) {
				c.post(runID, rest[:len(rest)/2])
				c.post(runID, rest[len(rest)/2:])
				return
			}
			c.post(runID, rest)
			return
		case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusNotFound:
			fmt.Fprintf(os.Stderr, "agent-runner: post output: %s: %s\n", resp.Status, strings.TrimSpace(string(data)))
			return
		default:
			lastErr = fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
		}
	}
	fmt.Fprintln(os.Stderr, "agent-runner: post output gave up:", lastErr)
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

func (s *chatState) sawLine(line string) {
	if harness.IsTurnEnd(line) {
		s.mu.Lock()
		s.turnEnd = time.Now()
		s.mu.Unlock()
	}
}

func (s *chatState) sent() {
	s.mu.Lock()
	s.turnEnd = time.Time{}
	s.mu.Unlock()
}

// idleFor is how long the conversation has been waiting for the user since the last turn.
func (s *chatState) idleFor() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.turnEnd.IsZero() {
		return 0
	}
	return time.Since(s.turnEnd)
}

// forwardInput delivers the user's messages to the harness: input events as lines (or
// stream-json user messages), run.cancel as a kill, run.close as end of input. In stream-json
// mode the conversation is also closed after the idle period following a completed turn.
func forwardInput(ctx context.Context, c *client, runID string, w io.WriteCloser, cancelRun context.CancelFunc, chat *chatState) {
	defer w.Close()
	var after int64
	for ctx.Err() == nil {
		wait := 30 * time.Second
		if chat.mode == harness.InputStreamJSON {
			if idle := chat.idleFor(); idle > 0 {
				if idle >= chat.idle {
					fmt.Printf("agent-runner: no message for %s after the last turn, closing the conversation\n", chat.idle)
					return
				}
				wait = min(wait, chat.idle-idle)
			}
		}
		var evs []model.Event
		_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/agent/runs/%s/input?after=%d&wait=%s", runID, after, wait.Round(time.Second)), nil, &evs)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(2 * time.Second)
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
				fmt.Println("agent-runner: conversation closed by the control plane")
				return
			}
			if _, err := io.WriteString(w, harness.FormatInput(chat.mode, e.Data)); err != nil {
				return
			}
			chat.sent()
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
