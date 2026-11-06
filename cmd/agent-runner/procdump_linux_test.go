package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// logProcesses logs every other process /proc shows, one line each: what is still there when
// the test's directories are about to be removed (registered right after t.TempDir, so it runs
// before that removal). The adapter's leftovers show up here with their group, session, cwd
// and whether their environment or command line names the test's home.
func logProcesses(t *testing.T, home string) {
	t.Helper()
	self := os.Getpid()
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil || pid == self {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(d, "stat"))
		if err != nil {
			continue
		}
		i := bytes.LastIndexByte(raw, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(raw[i+1:]))
		if len(f) < 4 {
			continue
		}
		comm := string(raw[bytes.IndexByte(raw, '(')+1 : i])
		cwd, _ := os.Readlink(filepath.Join(d, "cwd"))
		env, _ := os.ReadFile(filepath.Join(d, "environ"))
		cmdline, _ := os.ReadFile(filepath.Join(d, "cmdline"))
		cmd := strings.TrimSpace(string(bytes.ReplaceAll(cmdline, []byte{0}, []byte{' '})))
		if len(cmd) > 160 {
			cmd = cmd[:160] + "…"
		}
		t.Logf("proc %d ppid %s pgrp %s sid %s state %s comm %q cwd %q env-has-home %v cmd-has-home %v: %s",
			pid, f[1], f[2], f[3], f[0], comm, cwd, bytes.Contains(env, []byte(home)), strings.Contains(cmd, home), cmd)
	}
}
