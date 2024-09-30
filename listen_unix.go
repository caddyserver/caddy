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

// Even though the filename ends in _unix.go, we still have to specify the
// build constraint here, because the filename convention only works for
// literal GOOS values, and "unix" is a shortcut unique to build tags.
//go:build unix && !solaris

package caddy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// reuseUnixSocket copies and reuses the unix domain socket (UDS) if we already
// have it open; if not, unlink it so we can have it.
// No-op if not a unix network.
func reuseUnixSocket(network, addr string) (any, error) {
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
			unixSockets[socketKey] = &unixConn{pc.(*net.UnixConn), socketKey, unixSocket.count}
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

// listenReusable creates a new listener for the given network and address, and adds it to listenerPool.
func listenReusable(ctx context.Context, lnKey string, network, address string, config net.ListenConfig) (any, error) {
	// even though SO_REUSEPORT lets us bind the socket multiple times,
	// we still put it in the listenerPool so we can count how many
	// configs are using this socket; necessary to ensure we can know
	// whether to enforce shutdown delays, for example (see #5393).
	var (
		ln         io.Closer
		err        error
		socketFile *os.File
	)

	fd := slices.Contains([]string{"fd", "fdgram"}, network)
	if fd {
		socketFd, err := strconv.ParseUint(address, 0, strconv.IntSize)
		if err != nil {
			return nil, fmt.Errorf("invalid file descriptor: %v", err)
		}

		func() {
			socketFilesMu.Lock()
			defer socketFilesMu.Unlock()

			socketFdWide := uintptr(socketFd)
			var ok bool

			socketFile, ok = socketFiles[socketFdWide]

			if !ok {
				socketFile = os.NewFile(socketFdWide, lnKey)
				if socketFile != nil {
					socketFiles[socketFdWide] = socketFile
				}
			}
		}()

		if socketFile == nil {
			return nil, fmt.Errorf("invalid socket file descriptor: %d", socketFd)
		}
	} else {
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
	}

	datagram := slices.Contains([]string{"udp", "udp4", "udp6", "unixgram", "fdgram"}, network)
	if datagram {
		if fd {
			ln, err = net.FilePacketConn(socketFile)
		} else {
			ln, err = config.ListenPacket(ctx, network, address)
		}
	} else {
		if fd {
			ln, err = net.FileListener(socketFile)
		} else {
			ln, err = config.Listen(ctx, network, address)
		}
	}

	if err == nil {
		listenerPool.LoadOrStore(lnKey, nil)
	}

	if datagram {
		if !fd {
			// TODO: Not 100% sure this is necessary, but we do this for net.UnixListener, so...
			if unix, ok := ln.(*net.UnixConn); ok {
				one := int32(1)
				ln = &unixConn{unix, lnKey, &one}
				unixSockets[lnKey] = ln.(*unixConn)
			}
		}
		// lightly wrap the connection so that when it is closed,
		// we can decrement the usage pool counter
		if specificLn, ok := ln.(net.PacketConn); ok {
			ln = deletePacketConn{specificLn, lnKey}
		}
	} else {
		if !fd {
			// if new listener is a unix socket, make sure we can reuse it later
			// (we do our own "unlink on close" -- not required, but more tidy)
			if unix, ok := ln.(*net.UnixListener); ok {
				unix.SetUnlinkOnClose(false)
				one := int32(1)
				ln = &unixListener{unix, lnKey, &one}
				unixSockets[lnKey] = ln.(*unixListener)
			}
		}
		// lightly wrap the listener so that when it is closed,
		// we can decrement the usage pool counter
		if specificLn, ok := ln.(net.Listener); ok {
			ln = deleteListener{specificLn, lnKey}
		}
	}

	// other types, I guess we just return them directly
	return ln, err
}

// reusePort sets SO_REUSEPORT. Ineffective for unix sockets.
func reusePort(network, address string, conn syscall.RawConn) error {
	if IsUnixNetwork(network) {
		return nil
	}
	return conn.Control(func(descriptor uintptr) {
		if err := unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unixSOREUSEPORT, 1); err != nil {
			Log().Error("setting SO_REUSEPORT",
				zap.String("network", network),
				zap.String("address", address),
				zap.Uintptr("descriptor", descriptor),
				zap.Error(err))
		}
	})
}

type unixListener struct {
	*net.UnixListener
	mapKey string
	count  *int32 // accessed atomically
}

func (uln *unixListener) Close() error {
	newCount := atomic.AddInt32(uln.count, -1)
	if newCount == 0 {
		file, err := uln.File()
		var name string
		if err == nil {
			name = file.Name()
		}
		defer func() {
			unixSocketsMu.Lock()
			delete(unixSockets, uln.mapKey)
			unixSocketsMu.Unlock()
			if err == nil {
				_ = syscall.Unlink(name)
			}
		}()
	}
	return uln.UnixListener.Close()
}

type unixConn struct {
	*net.UnixConn
	mapKey string
	count  *int32 // accessed atomically
}

func (uc *unixConn) Close() error {
	newCount := atomic.AddInt32(uc.count, -1)
	if newCount == 0 {
		file, err := uc.File()
		var name string
		if err == nil {
			name = file.Name()
		}
		defer func() {
			unixSocketsMu.Lock()
			delete(unixSockets, uc.mapKey)
			unixSocketsMu.Unlock()
			if err == nil {
				_ = syscall.Unlink(name)
			}
		}()
	}
	return uc.UnixConn.Close()
}

func (uc *unixConn) Unwrap() net.PacketConn {
	return uc.UnixConn
}

// unixSockets keeps track of the currently-active unix sockets
// so we can transfer their FDs gracefully during reloads.
var unixSockets = make(map[string]interface {
	File() (*os.File, error)
})

// socketFiles is a fd -> *os.File map used to make a FileListener/FilePacketConn from a socket file descriptor.
var socketFiles = map[uintptr]*os.File{}

// socketFilesMu synchronizes socketFiles insertions
var socketFilesMu sync.Mutex

// deleteListener is a type that simply deletes itself
// from the listenerPool when it closes. It is used
// solely for the purpose of reference counting (i.e.
// counting how many configs are using a given socket).
type deleteListener struct {
	net.Listener
	lnKey string
}

func (dl deleteListener) Close() error {
	_, _ = listenerPool.Delete(dl.lnKey)
	return dl.Listener.Close()
}

// deletePacketConn is like deleteListener, but
// for net.PacketConns.
type deletePacketConn struct {
	net.PacketConn
	lnKey string
}

func (dl deletePacketConn) Close() error {
	_, _ = listenerPool.Delete(dl.lnKey)
	return dl.PacketConn.Close()
}

func (dl deletePacketConn) Unwrap() net.PacketConn {
	return dl.PacketConn
}
