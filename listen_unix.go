// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TODO: Go 1.19 introduced the "unix" build tag. We have to support Go 1.18 until Go 1.20 is released.
// When Go 1.19 is our minimum, remove this build tag, since "_unix" in the filename will do this.
// (see also change needed in listen.go)
//go:build aix || android || darwin || dragonfly || freebsd || hurd || illumos || ios || linux || netbsd || openbsd || solaris

package caddy

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"sync/atomic"
	"syscall"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// reuseUnixSocket copies and reuses the unix domain socket (UDS) if we already
// have it open; if not, unlink it so we can have it. No-op if not a unix network.
func reuseUnixSocket(network, addr string) (any, error) {
	if !isUnixNetwork(network) {
		return nil, nil
	}

	socketKey := listenerKey(network, addr)

	socket, exists := unixSockets[socketKey]
	if exists {
		// make copy of file descriptor
		socketFile, err := socket.File() // does dup() deep down
		if err != nil {
			return nil, err
		}

		// use copied fd to make new Listener or PacketConn, then replace
		// it in the map so that future copies always come from the most
		// recent fd (as the previous ones will be closed, and we'd get
		// "use of closed network connection" errors) -- note that we
		// preserve the *pointer* to the counter (not just the value) so
		// that all socket wrappers will refer to the same value
		switch unixSocket := socket.(type) {
		case *unixListener:
			ln, err := net.FileListener(socketFile)
			if err != nil {
				return nil, err
			}
			atomic.AddInt32(unixSocket.count, 1)
			unixSockets[socketKey] = &unixListener{ln.(*net.UnixListener), socketKey, unixSocket.count}

		case *unixConn:
			pc, err := net.FilePacketConn(socketFile)
			if err != nil {
				return nil, err
			}
			atomic.AddInt32(unixSocket.count, 1)
			unixSockets[socketKey] = &unixConn{pc.(*net.UnixConn), addr, socketKey, unixSocket.count}
		}

		return unixSockets[socketKey], nil
	}

	// from what I can tell after some quick research, it's quite common for programs to
	// leave their socket file behind after they close, so the typical pattern is to
	// unlink it before you bind to it -- this is often crucial if the last program using
	// it was killed forcefully without a chance to clean up the socket, but there is a
	// race, as the comment in net.UnixListener.close() explains... oh well, I guess?
	if err := syscall.Unlink(addr); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	return nil, nil
}

func listenTCPOrUnix(ctx context.Context, lnKey string, network, address string, config net.ListenConfig) (net.Listener, error) {
	// wrap any Control function set by the user so we can also add our reusePort control without clobbering theirs
	oldControl := config.Control
	config.Control = func(network, address string, c syscall.RawConn) error {
		if oldControl != nil {
			if err := oldControl(network, address, c); err != nil {
				return err
			}
		}
		return reusePort(network, address, c)
	}
	return config.Listen(ctx, network, address)
}

// reusePort sets SO_REUSEPORT. Ineffective for unix sockets.
func reusePort(network, address string, conn syscall.RawConn) error {
	if isUnixNetwork(network) {
		return nil
	}
	return conn.Control(func(descriptor uintptr) {
		if err := unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			Log().Error("setting SO_REUSEPORT",
				zap.String("network", network),
				zap.String("address", address),
				zap.Uintptr("descriptor", descriptor),
				zap.Error(err))
		}
	})
}
