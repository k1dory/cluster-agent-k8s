package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// adoptOrphans makes the test binary the subreaper of its descendants: a process whose parent
// left is re-parented here, not to PID 1, so endProcessGroup can reap it. In a container whose
// PID 1 does not reap (a shell, a CI runner), a killed orphan would otherwise stay a zombie in
// its process group forever.
func adoptOrphans() {
	_ = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}

// processesWithEnv lists the other processes whose environment names marker (a test's home):
// the adapter's descendants, whichever session or group they moved to. Processes of other users
// cannot be read and are not ours.
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
