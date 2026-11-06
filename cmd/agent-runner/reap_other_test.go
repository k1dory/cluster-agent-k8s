//go:build !linux

package main

import (
	"errors"
	"syscall"
)

// processesWithEnv: no /proc here; the process-group sweep is all endProcessGroup has.
func processesWithEnv(string) []int { return nil }

// groupAlive: launchd (macOS) and init reap orphans promptly, so an existing group is a live one.
func groupAlive(pgid int) bool { return !errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH) }

func processAlive(pid int) bool { return !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }
