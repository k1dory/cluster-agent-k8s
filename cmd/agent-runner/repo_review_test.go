package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

func isolatedGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is required")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_COUNT", "0")
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
}

// A remote that never answers does not hold the runner: the clone ends at cloneTimeout and
// leaves no half-made .git behind that would pass for a checkout next time.
func TestCloneHasATimeout(t *testing.T) {
	isolatedGit(t)
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(hang)
	old := cloneTimeout
	cloneTimeout = time.Second
	defer func() { cloneTimeout = old }()
	dir := filepath.Join(t.TempDir(), "repo")
	t.Setenv("SANDBOX_REPO_DIR", dir)
	t.Setenv("SANDBOX_REPO", srv.URL+"/hangs.git")
	start := time.Now()
	err := ensureRepo(t.Context())
	if err == nil || !strings.Contains(err.Error(), "did not finish within 1s") || time.Since(start) > 10*time.Second {
		t.Fatalf("after %s: %v", time.Since(start), err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("a cut-short clone left %s: %v", dir, err)
	}
}

// A clone that fails is said in the run's output, not only on the pod's stderr, and is tried
// again before the next run.
func TestFailedCloneIsANoticeOfTheRun(t *testing.T) {
	isolatedGit(t)
	workspaceRepo = repoSync{}
	t.Cleanup(func() { workspaceRepo = repoSync{} })
	_, cp, c := setupACP(t, "")
	t.Setenv("HARNESS_INPUT", "")
	t.Setenv("ACP_FAKE_AGENT", "")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	t.Setenv("HARNESS_CMD", `pwd`)
	root := t.TempDir()
	t.Setenv("SANDBOX_REPO_DIR", filepath.Join(root, "repo"))
	t.Setenv("SANDBOX_REPO", filepath.Join(root, "missing.git"))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	execute(ctx, c, &model.Run{ID: "run_noclone", Task: "x"})
	cp.mu.Lock()
	out := strings.Join(cp.lines, "\n")
	cp.mu.Unlock()
	if !strings.Contains(out, "[agent-runner] repository: git clone of "+filepath.Join(root, "missing.git")) || !strings.Contains(out, "the run starts outside the checkout") {
		t.Fatalf("output:\n%s", out)
	}
	// The repository appears: the next run clones it and starts inside it.
	git := exec.Command("git", "init", "--bare", filepath.Join(root, "missing.git"))
	if b, err := git.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, b)
	}
	cp.mu.Lock()
	cp.lines = nil
	cp.mu.Unlock()
	execute(ctx, c, &model.Run{ID: "run_clone", Task: "x"})
	cp.mu.Lock()
	out = strings.Join(cp.lines, "\n")
	cp.mu.Unlock()
	if strings.Contains(out, "repository:") || !strings.Contains(out, filepath.Join(root, "repo")) {
		t.Fatalf("second run output:\n%s", out)
	}
}

// Switching the repository back and forth keeps one replaced checkout, not one per switch.
func TestReplacedCheckoutsDoNotAccumulate(t *testing.T) {
	isolatedGit(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	a, b, checkout := filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "ws", "repo")
	for _, bare := range []string{a, b} {
		if out, err := exec.Command("git", "init", "--bare", bare).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	t.Setenv("SANDBOX_REPO_DIR", checkout)
	for _, repo := range []string{a, b, a, b} {
		t.Setenv("SANDBOX_REPO", repo)
		if err := ensureRepo(ctx); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(checkout))
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "repo,repo.replaced" {
		t.Fatalf("workspace: %v", names)
	}
}
