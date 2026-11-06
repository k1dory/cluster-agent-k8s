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

// A writer that left the adapter's session AND carries none of its environment (env -i), only
// the path as an argument — what some of Hermes's detached children look like: stopAdapter must
// still find it, through its command line or working directory.
func TestStopAdapterEndsAWriterWithAScrubbedEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc")
	}
	for _, bin := range []string{"setsid", "env"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("no %s here", bin)
		}
	}
	home := t.TempDir()
	state := filepath.Join(home, ".state")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c",
		`mkdir -p "$1"; cd /; setsid env -i /bin/sh -c 'exec >/dev/null 2>&1 </dev/null; echo $$ > "$1.pid"; i=0; while :; do i=$((i+1)); : > "$1/$i"; done' sh "$1" & cat >/dev/null`, "sh", state)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.WaitDelay = 2 * time.Second
	stdin, _ := cmd.StdinPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	var writer int
	t.Cleanup(func() {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		if writer > 0 {
			_ = syscall.Kill(writer, syscall.SIGKILL)
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
	if names, _ := processNames(filepath.Join("/proc", strconv.Itoa(writer)), home); strings.Contains(names, "env") {
		t.Fatalf("the writer still carries the home in its environment (%q); the test does not model a scrubbed child", names)
	}
	stopAdapter(stdin, cancel, cmd, home)
	if processAlive(writer) {
		t.Fatalf("the scrubbed writer (pid %d) is still alive after stopAdapter", writer)
	}
	if err := os.RemoveAll(state); err != nil {
		t.Fatalf("the home cannot be removed after stopAdapter: %v", err)
	}
}
