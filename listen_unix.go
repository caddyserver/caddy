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
	"net"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// ListenTimeout is the same as Listen, but with a configurable keep-alive timeout duration.
func ListenTimeout(network, addr string, keepalivePeriod time.Duration) (net.Listener, error) {
	// check to see if plugin provides listener
	if ln, err := getListenerFromPlugin(network, addr); err != nil || ln != nil {
		return ln, err
	}

	socketKey := listenerKey(network, addr)
	if isUnixNetwork(network) {
		unixSocketsMu.Lock()
		defer unixSocketsMu.Unlock()

		socket, exists := unixSockets[socketKey]
		if exists {
			// make copy of file descriptor
			socketFile, err := socket.File() // dup() deep down
			if err != nil {
				return nil, err
			}

			// use copy to make new listener
			ln, err := net.FileListener(socketFile)
			if err != nil {
				return nil, err
			}

			// the old socket fd will likely be closed soon, so replace it in the map
			unixSockets[socketKey] = ln.(*net.UnixListener)

			return ln.(*net.UnixListener), nil
		}

		// from what I can tell after some quick research, it's quite common for programs to
		// leave their socket file behind after they close, so the typical pattern is to
		// unlink it before you bind to it -- this is often crucial if the last program using
		// it was killed forcefully without a chance to clean up the socket, but there is a
		// race, as the comment in net.UnixListener.close() explains... oh well?
		if err := syscall.Unlink(addr); err != nil {
			return nil, err
		}
	}

	config := &net.ListenConfig{Control: reusePort, KeepAlive: keepalivePeriod}

	ln, err := config.Listen(context.Background(), network, addr)
	if err != nil {
		return nil, err
	}

	if uln, ok := ln.(*net.UnixListener); ok {
		// TODO: ideally, we should unlink the socket once we know we're done using it
		// (i.e. either on exit or a new config that doesn't use this socket; in UsagePool
		// terms, when the reference count reaches 0), but given that we unlink existing
		// socket before we create the new one anyway (see above), we don't necessarily
		// need to clean up after ourselves; still, doing so would probably be more tidy
		uln.SetUnlinkOnClose(false)
		unixSockets[socketKey] = uln
	}

	return ln, nil
}

// reusePort sets SO_REUSEPORT. Ineffective for unix sockets.
func reusePort(network, address string, conn syscall.RawConn) error {
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

// unixSockets keeps track of the currently-active unix sockets
// so we can transfer their FDs gracefully during reloads.
var (
	unixSockets   = make(map[string]*net.UnixListener)
	unixSocketsMu sync.Mutex
)
