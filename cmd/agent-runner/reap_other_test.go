//go:build !linux

package main

// adoptOrphans: nothing to do here; launchd (macOS) and init reap orphans.
func adoptOrphans() {}

// processesWithEnv: no /proc here; the process-group sweep is all endProcessGroup has.
func processesWithEnv(string) []int { return nil }
