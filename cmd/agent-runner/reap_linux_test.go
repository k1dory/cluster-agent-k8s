package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// processesWithEnv lists the other live processes that name marker (a test's home) in their
// environment, their command line or their working directory: the adapter's descendants,
// whichever session or group they moved to and however they were started (Hermes starts some
// of its children with a scrubbed environment and the path as an argument). Processes of other
// users cannot be read and are not ours; a zombie's environment is gone with its memory.
func processesWithEnv(marker string) []int {
	if marker == "" {
		return nil
	}
	self := os.Getpid()
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	var pids []int
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(d))
		if err != nil || pid == self {
			continue
		}
		if names, _ := processNames(d, marker); names != "" {
			pids = append(pids, pid)
		}
	}
	return pids
}

// processNames tells how the process in dir (/proc/<pid>) names marker: "env", "cmd", "cwd" in
// any combination, empty when it does not. The second value is the command's name (comm).
func processNames(dir, marker string) (names, comm string) {
	if raw, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		comm = strings.TrimSpace(string(raw))
	}
	m := []byte(marker)
	if env, err := os.ReadFile(filepath.Join(dir, "environ")); err == nil && bytes.Contains(env, m) {
		names += "env"
	}
	if cmd, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil && bytes.Contains(cmd, m) {
		names += "cmd"
	}
	if cwd, err := os.Readlink(filepath.Join(dir, "cwd")); err == nil && strings.HasPrefix(cwd, marker) {
		names += "cwd"
	}
	return names, comm
}

// logSurvivors logs, one line each, the other processes still there (state, group, session,
// whether they name home and by what, and their command name — never their arguments or
// environment, which may hold a stranger's secrets on a shared runner). For the cleanup of a
// test whose directories are about to be removed: what the dump of a failing run shows.
func logSurvivors(t *testing.T, home string) {
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
		names, comm := processNames(d, home)
		t.Logf("survivor pid %d ppid %s pgrp %s sid %s state %s names-home %q comm %q", pid, f[1], f[2], f[3], f[0], names, comm)
	}
}

// groupAlive tells whether a process of group pgid is still alive — a zombie is a member of its
// group until reaped, but it is done: kill(-pgid, 0) would not tell the two apart.
func groupAlive(pgid int) bool {
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	for _, d := range dirs {
		state, group, ok := procStat(filepath.Join(d, "stat"))
		if ok && group == pgid && state != "Z" && state != "X" {
			return true
		}
	}
	return false
}

// processAlive: the process exists and is not a zombie.
func processAlive(pid int) bool {
	state, _, ok := procStat(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	return ok && state != "Z" && state != "X"
}

// procStat reads a /proc/<pid>/stat: the state and the process group (fields 3 and 5; the
// command in field 2 is in parentheses and may hold spaces).
func procStat(path string) (state string, pgid int, ok bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, false
	}
	i := bytes.LastIndexByte(raw, ')')
	if i < 0 {
		return "", 0, false
	}
	f := strings.Fields(string(raw[i+1:]))
	if len(f) < 3 {
		return "", 0, false
	}
	pgid, err = strconv.Atoi(f[2])
	return f[0], pgid, err == nil
}
