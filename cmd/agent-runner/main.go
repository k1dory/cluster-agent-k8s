// agent-runner is PID 1 of the agent container: it long-polls the control plane for runs,
// executes the harness command for each, streams its output back and forwards user input.
//
// Everything goes through the mTLS gateway with the certificate agent-init obtained.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
		body, _ := json.Marshal(map[string]int{"exit_code": exit})
		if _, err := c.do(context.Background(), http.MethodPost, "/agent/runs/"+run.ID+"/finish", body, nil); err != nil {
			fmt.Fprintln(os.Stderr, "agent-runner: finish:", err)
		}
	}
}

// execute runs the harness for one task. Output lines are batched to the control plane;
// user input events are written to the harness stdin.
func execute(ctx context.Context, c *client, run *model.Run) int {
	cmdline := os.Getenv("HARNESS_CMD")
	if cmdline == "" {
		cmdline = `claude -p "$SANDBOX_TASK" --output-format stream-json --verbose`
	}
	fmt.Printf("agent-runner: run %s: %q\n", run.ID, truncate(run.Task, 80))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "/bin/sh", "-lc", cmdline)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 20 * time.Second
	cmd.Env = append(os.Environ(), "SANDBOX_TASK="+run.Task, "SANDBOX_RUN_ID="+run.ID)
	cmd.Dir = os.Getenv("PWD")
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
	// Harnesses that take the task on stdin get it first; CLI-arg harnesses just ignore it.
	go func() { _, _ = io.WriteString(stdin, run.Task+"\n") }()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); streamOutput(c, run.ID, stdout) }()
	go func() { defer wg.Done(); forwardInput(runCtx, c, run.ID, stdin, cancel) }()

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

func streamOutput(c *client, runID string, r io.Reader) {
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
			batch = append(batch, l)
			if len(batch) >= 50 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func (c *client) post(runID string, lines []string) {
	body := []byte(strings.Join(lines, "\n") + "\n")
	req, _ := http.NewRequest(http.MethodPost, c.base+"/agent/runs/"+runID+"/events", bytes.NewReader(body))
	req.Header.Set("Content-Type", "text/plain")
	resp, err := c.http.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-runner: post output:", err)
		return
	}
	resp.Body.Close()
}

func forwardInput(ctx context.Context, c *client, runID string, w io.WriteCloser, cancelRun context.CancelFunc) {
	defer w.Close()
	var after int64
	for ctx.Err() == nil {
		var evs []model.Event
		_, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/agent/runs/%s/input?after=%d&wait=30s", runID, after), nil, &evs)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			time.Sleep(2 * time.Second)
			continue
		}
		for _, e := range evs {
			after = e.ID
			if e.Type == model.EventRunCancel {
				fmt.Println("agent-runner: run cancelled by the control plane")
				cancelRun()
				return
			}
			if _, err := io.WriteString(w, e.Data+"\n"); err != nil {
				return
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
