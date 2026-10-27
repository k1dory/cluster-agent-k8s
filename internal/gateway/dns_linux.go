package gateway

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// freebind lets the socket bind an address this host does not hold yet (IP_FREEBIND): the
// gateway address behind a VIP, before it moves to this node.
func freebind(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_FREEBIND, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
