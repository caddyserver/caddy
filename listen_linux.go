package caddy

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func Listen(network, addr string) (net.Listener, error) {
	config := &net.ListenConfig{Control: reusePort}
	return config.Listen(context.Background(), network, addr)
}

func reusePort(network, address string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr) {
		unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
}
