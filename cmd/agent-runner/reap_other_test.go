//go:build !linux

package main

import (
	"errors"
	"syscall"
	"testing"
)

// processesWithEnv: no /proc here; the process-group sweep is all endProcessGroup has.
func processesWithEnv(string) []int { return nil }

// groupAlive: launchd (macOS) and init reap orphans promptly, so an existing group is a live one.
func groupAlive(pgid int) bool { return !errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH) }

func processAlive(pid int) bool { return !errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) }

// logSurvivors: no /proc here.
func logSurvivors(*testing.T, string) {}

// processNames: no /proc here.
func processNames(string, string) (string, string) { return "", "" }
