//go:build !linux

package main

// adoptOrphans: nothing to do here; launchd (macOS) and init reap orphans.
func adoptOrphans() {}
