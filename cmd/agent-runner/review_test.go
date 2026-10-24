package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReviewFinishRetriesTransientFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ExitCode int `json:"exit_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ExitCode != 7 || r.URL.Path != "/agent/runs/run-review/finish" {
			t.Errorf("unexpected finish request: path=%s exit=%d err=%v", r.URL.Path, body.ExitCode, err)
		}
		if calls.Add(1) == 1 {
			http.Error(w, "temporary outage", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	c := &client{base: server.URL, http: server.Client()}
	c.finish("run-review", 7)
	if got := calls.Load(); got != 2 {
		t.Fatalf("finish calls=%d, want two with the same outcome", got)
	}
}

func TestReviewFinishStopsForRetiredRun(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "retired", http.StatusForbidden)
	}))
	defer server.Close()
	(&client{base: server.URL, http: server.Client()}).finish("run-review", 0)
	if calls.Load() != 1 {
		t.Fatalf("a terminal authorization error was retried %d times", calls.Load())
	}
}

func TestReviewRepoChangeCannotSilentlyReusePreviousCheckout(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root := t.TempDir()
	// Keep the test independent of a developer's Git credential, signing and URL config.
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_COUNT", "0")
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	a, b, checkout := filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "workspace")
	git("init", "--bare", a)
	git("init", "--bare", b)
	t.Setenv("SANDBOX_REPO_DIR", checkout)
	t.Setenv("SANDBOX_REPO", a)
	if err := ensureRepo(ctx); err != nil {
		t.Fatal(err)
	}
	if got := git("-C", checkout, "remote", "get-url", "origin"); got != a {
		t.Fatalf("initial clone origin=%q, want %q", got, a)
	}
	t.Setenv("SANDBOX_REPO", b)
	if err := ensureRepo(ctx); err != nil {
		return // Rejecting a workspace mismatch is safe; silently using A for B is not.
	}
	if got := git("-C", checkout, "remote", "get-url", "origin"); got != b {
		t.Fatalf("requested repo B, but ensureRepo succeeded with origin %q (repo A)", got)
	}
}

func TestMCPServersBecomeAHarnessConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "home", ".sandbox-mcp.json")
	if p, n, err := writeMCPConfig("", path); err != nil || n != 0 || p != "" {
		t.Fatalf("empty: %v %d %q", err, n, p)
	}
	if _, _, err := writeMCPConfig("not json", path); err == nil {
		t.Fatal("garbage accepted")
	}
	p, n, err := writeMCPConfig(`[{"name":"registry","url":"https://mcp.registry.example.com/mcp"},{"name":"","url":"x"},{"name":"shared/tools","url":"https://tools.example.com/rpc"}]`, path)
	if err != nil || n != 2 || p != path {
		t.Fatalf("write: %v %d %q", err, n, p)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Servers map[string]map[string]string `json:"mcpServers"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil || len(cfg.Servers) != 2 || cfg.Servers["registry"]["url"] != "https://mcp.registry.example.com/mcp" || cfg.Servers["registry"]["type"] != "http" || cfg.Servers["shared/tools"]["url"] != "https://tools.example.com/rpc" {
		t.Fatalf("config: %v %s", err, b)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v", info.Mode())
	}
}
