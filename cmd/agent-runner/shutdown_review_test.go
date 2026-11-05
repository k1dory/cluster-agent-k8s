package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"syscall"
	"testing"
	"time"
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
	endGroup(cmd)
	groupKills.Wait()
	select {
	case <-exited:
	case <-time.After(time.Second):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		t.Fatal("the group outlived the awaited kill")
	}
}
