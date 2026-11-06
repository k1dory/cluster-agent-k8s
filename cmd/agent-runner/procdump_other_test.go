//go:build !linux

package main

import "testing"

func logProcesses(*testing.T, string) {}
