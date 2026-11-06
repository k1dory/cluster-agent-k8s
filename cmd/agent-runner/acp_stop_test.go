package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	// The child keeps the pipes closed (so Wait does not hang on them) and keeps writing; on Linux
	// it also leaves the adapter's session and group (setsid), as Hermes's detached children do,
	// so only the /proc sweep can reach it. Elsewhere there is no /proc to sweep, and the group
	// is all stopAdapter has.
	detach := ""
	if runtime.GOOS == "linux" {
		if _, err := exec.LookPath("setsid"); err != nil {
			t.Skip("no setsid here; the detached writer cannot be set up")
		}
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
	// Independent of the helper under test: when an assertion below fails, the writer must not
	// outlive the test and race the TempDir's removal. Runs before the TempDir cleanup (LIFO);
	// the writer's pid is known once it has written its pid file.
	var writer int
	t.Cleanup(func() {
		until := time.Now().Add(2 * time.Second)
		for time.Now().Before(until) {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			if writer > 0 {
				_ = syscall.Kill(writer, syscall.SIGKILL)
			}
			var ws syscall.WaitStatus
			for {
				if pid, err := syscall.Wait4(-pgid, &ws, syscall.WNOHANG, nil); pid <= 0 || err != nil {
					break
				}
			}
			if !groupAlive(pgid) && (writer <= 0 || !processAlive(writer)) {
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
	writer, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
	stopAdapter(stdin, cancel, cmd, home) // the adapter (cat) leaves on EOF; the child stays unless ended
	if groupAlive(pgid) {
		t.Fatal("the adapter's process group is still alive after stopAdapter")
	}
	if processAlive(writer) {
		t.Fatalf("the writer (pid %d, detached: %v) is still alive after stopAdapter", writer, detach != "")
	}
	if err := os.RemoveAll(state); err != nil {
		t.Fatalf("the home cannot be removed after stopAdapter: %v", err)
	}
}
