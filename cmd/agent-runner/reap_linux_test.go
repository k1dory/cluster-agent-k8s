package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// processesWithEnv lists the other live processes whose environment names marker (a test's
// home): the adapter's descendants, whichever session or group they moved to. Processes of
// other users cannot be read and are not ours; a zombie's environment is gone with its memory.
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
		env, err := os.ReadFile(filepath.Join(d, "environ"))
		if err != nil || !bytes.Contains(env, []byte(marker)) {
			continue
		}
		pids = append(pids, pid)
	}
	return pids
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
