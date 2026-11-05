package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"agent-sandbox/internal/model"
)

// The loops that wait out a failing control plane (the run poll, the input poll, the file
// requests poll) stop as soon as SIGTERM cancels their context, not after their pause.
func TestPollPausesEndWithTheContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := &client{base: srv.URL, http: srv.Client()}
	for name, loop := range map[string]func(context.Context){
		"runs":  func(ctx context.Context) { serveRuns(ctx, c) },
		"files": func(ctx context.Context) { serveFiles(ctx, c, t.TempDir()) },
		"input": func(ctx context.Context) {
			forwardInput(ctx, c, "run_x", stdinSink{&reviewMessageInput{}, ""}, func() {}, newChat("", time.Minute))
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, sigterm := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() { loop(ctx); close(done) }()
			time.Sleep(300 * time.Millisecond) // the first poll failed: the loop pauses
			sigterm()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("the loop slept through the cancellation")
			}
		})
	}
}

// What survives SIGTERM in a harness's process group is killed, and the runner's way out waits
// for that kill instead of leaving it to a goroutine that dies with the process.
func TestGroupKillIsAwaited(t *testing.T) {
	old := groupKillDelay
	groupKillDelay = 300 * time.Millisecond
	defer func() { groupKillDelay = old }()
	cmd := exec.Command("/bin/sh", "-c", `trap "" TERM; sleep 300`)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	time.Sleep(100 * time.Millisecond) // the trap is set
	start := time.Now()
	endGroup(cmd)
	groupKills.Wait()
	// The wait lasts until the kill: the group ignores SIGTERM, so only the SIGKILL at the delay
	// ends it, and it is gone right after.
	if d := time.Since(start); d < groupKillDelay-50*time.Millisecond {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		t.Fatalf("the wait returned after %s, before the kill at %s", d, groupKillDelay)
	}
	select {
	case <-exited:
	case <-time.After(200 * time.Millisecond):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		t.Fatal("the group outlived the awaited kill")
	}
}

// The runner's way out (SIGTERM, then main's return) waits for the pending kill of a harness's
// group: a child that ignores SIGTERM is gone when the runner process has exited. Run as a real
// process, since the kill would otherwise be lost with it.
func TestRunnerExitAwaitsTheGroupKill(t *testing.T) {
	_, _, _ = setupACP(t, "")
	t.Setenv("HARNESS_INPUT", "")
	t.Setenv("ACP_FAKE_AGENT", "")
	t.Setenv("SANDBOX_MCP_SERVERS", "")
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Setenv("HARNESS_CMD", `(trap "" TERM; exec sleep 300) >/dev/null 2>&1 & echo $! > "`+pidFile+`"; echo done`)
	finished := make(chan struct{})
	var once sync.Once
	handed := false
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/runs/next") && !handed:
			handed = true
			_ = json.NewEncoder(w).Encode(model.Run{ID: "run_exit", Task: "x"})
		case strings.HasSuffix(r.URL.Path, "/runs/next"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/finish"):
			once.Do(func() { close(finished) })
			w.WriteHeader(http.StatusNoContent)
		default:
			_, _ = w.Write([]byte("[]"))
		}
	}))
	defer srv.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunnerExitHelper$")
	cmd.Env = append(os.Environ(), "RUNNER_EXIT_HELPER=1", "RUNNER_EXIT_API="+srv.URL)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the run did not finish")
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	_ = cmd.Wait()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	for i := 0; syscall.Kill(pid, 0) == nil; i++ {
		if i == 10 { // reaping by init takes a moment; a pending kill never comes
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the harness's child %d outlived the runner", pid)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// TestRunnerExitHelper is the runner's main loop in a process of its own (RUNNER_EXIT_HELPER).
func TestRunnerExitHelper(t *testing.T) {
	if os.Getenv("RUNNER_EXIT_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	groupKillDelay = 500 * time.Millisecond
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	serveAndDrain(ctx, &client{base: os.Getenv("RUNNER_EXIT_API"), http: http.DefaultClient})
	os.Exit(0)
}
