//go:build !linux

package gateway

import "syscall"

// freebind is Linux-only; elsewhere the bind must name an address the host holds.
func freebind(_, _ string, _ syscall.RawConn) error { return nil }
