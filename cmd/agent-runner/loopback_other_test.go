//go:build !linux

package main

// loopbackUp is Linux's concern only (network namespaces).
func loopbackUp() error { return nil }
