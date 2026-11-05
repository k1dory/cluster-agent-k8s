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
	if len(names) != 2 || names[0] != "repo" || !strings.HasPrefix(names[1], "repo.replaced-") {
		t.Fatalf("workspace: %v", names)
	}
}

// Switching A → B → A → B never deletes a checkout: the one moved aside comes back with its
// uncommitted files and its local commits.
func TestRepositorySwitchKeepsTheWork(t *testing.T) {
	isolatedGit(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	a, b, checkout := filepath.Join(root, "a"), filepath.Join(root, "b"), filepath.Join(root, "ws", "repo")
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, "git", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "--bare", a)
	git("init", "--bare", b)
	t.Setenv("SANDBOX_REPO_DIR", checkout)
	work := func(repo, name string) {
		t.Helper()
		t.Setenv("SANDBOX_REPO", repo)
		if err := ensureRepo(ctx); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(checkout, name+".txt"), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
		git("-C", checkout, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "local "+name)
	}
	has := func(repo, name string) {
		t.Helper()
		t.Setenv("SANDBOX_REPO", repo)
		if err := ensureRepo(ctx); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(filepath.Join(checkout, name+".txt")); err != nil || string(b) != name {
			t.Fatalf("the uncommitted file of %s is gone: %v", name, err)
		}
		if log := git("-C", checkout, "log", "--format=%s"); !strings.Contains(log, "local "+name) {
			t.Fatalf("the local commit of %s is gone: %q", name, log)
		}
	}
	work(a, "work-a")
	work(b, "work-b")
	has(a, "work-a")
	has(b, "work-b")
	has(a, "work-a")
}

// A file where the checkout should be is not the runner's to remove: the clone fails, the file
// stays as it was, and the run is told.
func TestCloneLeavesAFileAtTheCheckoutPath(t *testing.T) {
	isolatedGit(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	repo, checkout := filepath.Join(root, "a"), filepath.Join(root, "repo")
	if out, err := exec.Command("git", "init", "--bare", repo).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := os.WriteFile(checkout, []byte("notes nobody pushed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANDBOX_REPO_DIR", checkout)
	t.Setenv("SANDBOX_REPO", repo)
	if err := ensureRepo(ctx); err == nil {
		t.Fatal("the clone replaced a file at the checkout path")
	}
	if b, err := os.ReadFile(checkout); err != nil || string(b) != "notes nobody pushed\n" {
		t.Fatalf("the file at the checkout path changed: %q %v", b, err)
	}
	// An empty directory there is fine: git creates it.
	if err := os.Remove(checkout); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(checkout, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureRepo(ctx); err != nil {
		t.Fatalf("an empty directory at the checkout path: %v", err)
	}
}

// A run cancelled while the clone runs stops the clone and never starts its harness.
func TestCancelDuringTheCloneStopsTheRun(t *testing.T) {
	isolatedGit(t)
	workspaceRepo = repoSync{}
	t.Cleanup(func() { workspaceRepo = repoSync{} })
	hang := make(chan struct{})
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}))
	defer remote.Close()
	defer close(hang)
	old := cloneTimeout
	cloneTimeout = 30 * time.Second
	defer func() { cloneTimeout = old }()
	_, cp, _ := setupACP(t, "")
	t.Setenv("HARNESS_INPUT", "")
	t.Setenv("ACP_FAKE_AGENT", "")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	marker := filepath.Join(t.TempDir(), "started")
	t.Setenv("HARNESS_CMD", `touch "`+marker+`"`)
	t.Setenv("SANDBOX_REPO_DIR", filepath.Join(t.TempDir(), "repo"))
	t.Setenv("SANDBOX_REPO", remote.URL+"/slow.git")
	// The control plane: the run is cancelled as soon as anyone looks.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/input") {
			time.Sleep(300 * time.Millisecond) // the clone is under way
			_, _ = w.Write([]byte(`[{"id":1,"type":"run.cancel"}]`))
			return
		}
		cp.ServeHTTP(w, r)
	}))
	defer srv.Close()
	start := time.Now()
	code := execute(t.Context(), &client{base: srv.URL, http: srv.Client()}, &model.Run{ID: "run_cancel_setup", Task: "x"})
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("the run went on for %s after its cancel", d)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the harness of a cancelled run was started")
	}
	cp.mu.Lock()
	out := strings.Join(cp.lines, "\n")
	cp.mu.Unlock()
	if code == 0 || !strings.Contains(out, "run cancelled before the harness started") {
		t.Fatalf("exit %d, output:\n%s", code, out)
	}
}
