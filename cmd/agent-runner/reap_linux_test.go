package main

import "golang.org/x/sys/unix"

// adoptOrphans makes the test binary the subreaper of its descendants: a process whose parent
// left is re-parented here, not to PID 1, so endProcessGroup can reap it. In a container whose
// PID 1 does not reap (a shell, a CI runner), a killed orphan would otherwise stay a zombie in
// its process group forever.
func adoptOrphans() {
	_ = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}
