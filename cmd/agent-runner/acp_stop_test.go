package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// An adapter that leaves on EOF but leaves a child behind, writing under the test's home (what
// Hermes does): stopAdapter must end the whole process group before the test's directories are
// removed, or the removal races the child ("directory not empty") and the child outlives the test.
func TestStopAdapterEndsWhatTheAdapterLeftBehind(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, ".state")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	// The child keeps the pipes closed (so Wait does not hang on them) and keeps writing; where
	// setsid exists (Linux) it also leaves the adapter's session and group, as Hermes's detached
	// children do, so only the /proc sweep can reach it.
	detach := ""
	if _, err := exec.LookPath("setsid"); err == nil {
		detach = "setsid "
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c",
		`mkdir -p "$1"; `+detach+`sh -c 'exec >/dev/null 2>&1 </dev/null; echo $$ > "$1.pid"; i=0; while :; do i=$((i+1)); : > "$1/$i"; done' sh "$1" & cat >/dev/null`, "sh", state)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.Env = append(os.Environ(), "HOME="+home) // as openRealACP sets it: what names the descendants
	cmd.WaitDelay = 2 * time.Second
	stdin, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	// Independent of the helper under test: when the assertion below fails, the writer must not
	// outlive the test and race the TempDir's removal. Runs before the TempDir cleanup (LIFO).
	t.Cleanup(func() {
		until := time.Now().Add(2 * time.Second)
		for time.Now().Before(until) {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			var ws syscall.WaitStatus
			for {
				if pid, err := syscall.Wait4(-pgid, &ws, syscall.WNOHANG, nil); pid <= 0 || err != nil {
					break
				}
			}
			for _, pid := range processesWithEnv(home) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				_, _ = syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
			}
			if errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH) && len(processesWithEnv(home)) == 0 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if entries, _ := os.ReadDir(state); len(entries) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the child never wrote")
		}
		time.Sleep(10 * time.Millisecond)
	}
	raw, err := os.ReadFile(state + ".pid")
	if err != nil {
		t.Fatal(err)
	}
	writer, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	stopAdapter(stdin, cancel, cmd, home) // the adapter (cat) leaves on EOF; the child stays unless ended
	if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("the adapter's process group is still there after stopAdapter (kill 0: %v)", err)
	}
	if err := syscall.Kill(writer, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("the writer (pid %d, detached: %v) is still there after stopAdapter (kill 0: %v)", writer, detach != "", err)
	}
	if err := os.RemoveAll(state); err != nil {
		t.Fatalf("the home cannot be removed after stopAdapter: %v", err)
	}
}
