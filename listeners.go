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

package caddy

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Listen is like net.Listen, except Caddy's listeners can overlap
// each other: multiple listeners may be created on the same socket
// at the same time. This is useful because during config changes,
// the new config is started while the old config is still running.
// When Caddy listeners are closed, the closing logic is virtualized
// so the underlying socket isn't actually closed until all uses of
// the socket have been finished. Always be sure to close listeners
// when you are done with them, just like normal listeners.
func Listen(network, addr string) (net.Listener, error) {
	lnKey := network + "/" + addr

	sharedLn, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		ln, err := net.Listen(network, addr)
		if err != nil {
			if isUnixNetwork(network) && isListenBindAddressAlreadyInUseError(err) {
				return nil, explainUnixBindAddressAlreadyInUseError(err)
			}
			return nil, err
		}
		return &sharedListener{Listener: ln, key: lnKey}, nil
	})
	if err != nil {
		return nil, err
	}

	return &fakeCloseListener{sharedListener: sharedLn.(*sharedListener)}, nil
}

// ListenPacket returns a net.PacketConn suitable for use in a Caddy module.
// It is like Listen except for PacketConns.
// Always be sure to close the PacketConn when you are done.
func ListenPacket(network, addr string) (net.PacketConn, error) {
	lnKey := network + "/" + addr

	sharedPc, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		pc, err := net.ListenPacket(network, addr)
		if err != nil {
			if isUnixNetwork(network) && isListenBindAddressAlreadyInUseError(err) {
				return nil, explainUnixBindAddressAlreadyInUseError(err)
			}
			return nil, err
		}
		return &sharedPacketConn{PacketConn: pc, key: lnKey}, nil
	})
	if err != nil {
		return nil, err
	}

	return &fakeClosePacketConn{sharedPacketConn: sharedPc.(*sharedPacketConn)}, nil
}

// fakeCloseListener is a private wrapper over a listener that
// is shared. The state of fakeCloseListener is not shared.
// This allows one user of a socket to "close" the listener
// while in reality the socket stays open for other users of
// the listener. In this way, servers become hot-swappable
// while the listener remains running. Listeners should be
// re-wrapped in a new fakeCloseListener each time the listener
// is reused. This type is atomic and values must not be copied.
type fakeCloseListener struct {
	closed          int32 // accessed atomically; belongs to this struct only
	*sharedListener       // embedded, so we also become a net.Listener
}

func (fcl *fakeCloseListener) Accept() (net.Conn, error) {
	// if the listener is already "closed", return error
	if atomic.LoadInt32(&fcl.closed) == 1 {
		return nil, fcl.fakeClosedErr()
	}

	// call underlying accept
	conn, err := fcl.sharedListener.Accept()
	if err == nil {
		return conn, nil
	}

	// since Accept() returned an error, it may be because our reference to
	// the listener (this fakeCloseListener) may have been closed, i.e. the
	// server is shutting down; in that case, we need to clear the deadline
	// that we set when Close() was called, and return a non-temporary and
	// non-timeout error value to the caller, masking the "true" error, so
	// that server loops / goroutines won't retry, linger, and leak
	if atomic.LoadInt32(&fcl.closed) == 1 {
		// we dereference the sharedListener explicitly even though it's embedded
		// so that it's clear in the code that side-effects are shared with other
		// users of this listener, not just our own reference to it; we also don't
		// do anything with the error because all we could do is log it, but we
		// expliclty assign it to nothing so we don't forget it's there if needed
		_ = fcl.sharedListener.clearDeadline()

		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fcl.fakeClosedErr()
		}
	}

	return nil, err
}

// Close stops accepting new connections without closing the
// underlying listener. The underlying listener is only closed
// if the caller is the last known user of the socket.
func (fcl *fakeCloseListener) Close() error {
	if atomic.CompareAndSwapInt32(&fcl.closed, 0, 1) {
		// There are two ways I know of to get an Accept()
		// function to return to the server loop that called
		// it: close the listener, or set a deadline in the
		// past. Obviously, we can't close the socket yet
		// since others may be using it (hence this whole
		// file). But we can set the deadline in the past,
		// and this is kind of cheating, but it works, and
		// it apparently even works on Windows.
		_ = fcl.sharedListener.setDeadline()
		_, _ = listenerPool.Delete(fcl.sharedListener.key)
	}
	return nil
}

// fakeClosedErr returns an error value that is not temporary
// nor a timeout, suitable for making the caller think the
// listener is actually closed
func (fcl *fakeCloseListener) fakeClosedErr() error {
	return &net.OpError{
		Op:   "accept",
		Net:  fcl.Addr().Network(),
		Addr: fcl.Addr(),
		Err:  errFakeClosed,
	}
}

// ErrFakeClosed is the underlying error value returned by
// fakeCloseListener.Accept() after Close() has been called,
// indicating that it is pretending to be closed so that the
// server using it can terminate, while the underlying
// socket is actually left open.
var errFakeClosed = fmt.Errorf("listener 'closed' 😉")

// fakeClosePacketConn is like fakeCloseListener, but for PacketConns.
type fakeClosePacketConn struct {
	closed            int32 // accessed atomically; belongs to this struct only
	*sharedPacketConn       // embedded, so we also become a net.PacketConn
}

func (fcpc *fakeClosePacketConn) Close() error {
	if atomic.CompareAndSwapInt32(&fcpc.closed, 0, 1) {
		_, _ = listenerPool.Delete(fcpc.sharedPacketConn.key)
	}
	return nil
}

// Supports QUIC implementation: https://github.com/caddyserver/caddy/issues/3998
func (fcpc fakeClosePacketConn) SetReadBuffer(bytes int) error {
	if conn, ok := fcpc.PacketConn.(interface{ SetReadBuffer(int) error }); ok {
		return conn.SetReadBuffer(bytes)
	}
	return fmt.Errorf("SetReadBuffer() not implemented for %T", fcpc.PacketConn)
}

// Supports QUIC implementation: https://github.com/caddyserver/caddy/issues/3998
func (fcpc fakeClosePacketConn) SyscallConn() (syscall.RawConn, error) {
	if conn, ok := fcpc.PacketConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		return conn.SyscallConn()
	}
	return nil, fmt.Errorf("SyscallConn() not implemented for %T", fcpc.PacketConn)
}

// sharedListener is a wrapper over an underlying listener. The listener
// and the other fields on the struct are shared state that is synchronized,
// so sharedListener structs must never be copied (always use a pointer).
type sharedListener struct {
	net.Listener
	key        string // uniquely identifies this listener
	deadline   bool   // whether a deadline is currently set
	deadlineMu sync.Mutex
}

func (sl *sharedListener) clearDeadline() error {
	var err error
	sl.deadlineMu.Lock()
	if sl.deadline {
		switch ln := sl.Listener.(type) {
		case *net.TCPListener:
			err = ln.SetDeadline(time.Time{})
		case *net.UnixListener:
			err = ln.SetDeadline(time.Time{})
		}
		sl.deadline = false
	}
	sl.deadlineMu.Unlock()
	return err
}

func (sl *sharedListener) setDeadline() error {
	timeInPast := time.Now().Add(-1 * time.Minute)
	var err error
	sl.deadlineMu.Lock()
	if !sl.deadline {
		switch ln := sl.Listener.(type) {
		case *net.TCPListener:
			err = ln.SetDeadline(timeInPast)
		case *net.UnixListener:
			err = ln.SetDeadline(timeInPast)
		}
		sl.deadline = true
	}
	sl.deadlineMu.Unlock()
	return err
}

// Destruct is called by the UsagePool when the listener is
// finally not being used anymore. It closes the socket.
func (sl *sharedListener) Destruct() error {
	return sl.Listener.Close()
}

// sharedPacketConn is like sharedListener, but for net.PacketConns.
type sharedPacketConn struct {
	net.PacketConn
	key string
}

// Destruct closes the underlying socket.
func (spc *sharedPacketConn) Destruct() error {
	return spc.PacketConn.Close()
}

// NetworkAddress contains the individual components
// for a parsed network address of the form accepted
// by ParseNetworkAddress(). Network should be a
// network value accepted by Go's net package. Port
// ranges are given by [StartPort, EndPort].
type NetworkAddress struct {
	Network   string
	Host      string
	StartPort uint
	EndPort   uint
}

// IsUnixNetwork returns true if na.Network is
// unix, unixgram, or unixpacket.
func (na NetworkAddress) IsUnixNetwork() bool {
	return isUnixNetwork(na.Network)
}

// JoinHostPort is like net.JoinHostPort, but where the port
// is StartPort + offset.
func (na NetworkAddress) JoinHostPort(offset uint) string {
	if na.IsUnixNetwork() {
		return na.Host
	}
	return net.JoinHostPort(na.Host, strconv.Itoa(int(na.StartPort+offset)))
}

// PortRangeSize returns how many ports are in
// pa's port range. Port ranges are inclusive,
// so the size is the difference of start and
// end ports plus one.
func (na NetworkAddress) PortRangeSize() uint {
	return (na.EndPort - na.StartPort) + 1
}

func (na NetworkAddress) isLoopback() bool {
	if na.IsUnixNetwork() {
		return true
	}
	if na.Host == "localhost" {
		return true
	}
	if ip := net.ParseIP(na.Host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (na NetworkAddress) isWildcardInterface() bool {
	if na.Host == "" {
		return true
	}
	if ip := net.ParseIP(na.Host); ip != nil {
		return ip.IsUnspecified()
	}
	return false
}

func (na NetworkAddress) port() string {
	if na.StartPort == na.EndPort {
		return strconv.FormatUint(uint64(na.StartPort), 10)
	}
	return fmt.Sprintf("%d-%d", na.StartPort, na.EndPort)
}

// String reconstructs the address string to the form expected
// by ParseNetworkAddress(). If the address is a unix socket,
// any non-zero port will be dropped.
func (na NetworkAddress) String() string {
	return JoinNetworkAddress(na.Network, na.Host, na.port())
}

func isUnixNetwork(netw string) bool {
	return netw == "unix" || netw == "unixgram" || netw == "unixpacket"
}

func isListenBindAddressAlreadyInUseError(err error) bool {
	switch networkOperationError := err.(type) {
	case *net.OpError:
		switch syscallError := networkOperationError.Err.(type) {
		case *os.SyscallError:
			if syscallError.Syscall == "bind" {
				return true
			}
		}
	}

	return false
}

type ErrorWithExplanation struct {
	Explanation string
	Err         error
}

func (e *ErrorWithExplanation) Unwrap() error { return e.Err }
func (e *ErrorWithExplanation) Error() string {
	if e == nil {
		return "<nil>\n" + e.Explanation
	}
	return e.Err.Error() + "\n" + e.Explanation
}

func explainUnixBindAddressAlreadyInUseError(err error) error {
	return &ErrorWithExplanation{
		Explanation: "This can happen either when you have two programs " +
			"(or two instances of caddy) attempting to listen on the same " +
			"socket file at the same time, or when caddy did not exit cleanly " +
			"last time it was run and thus did not get a chance to delete " +
			"the socket file when it shut down",
		Err: err,
	}
}

// ParseNetworkAddress parses addr into its individual
// components. The input string is expected to be of
// the form "network/host:port-range" where any part is
// optional. The default network, if unspecified, is tcp.
// Port ranges are inclusive.
//
// Network addresses are distinct from URLs and do not
// use URL syntax.
func ParseNetworkAddress(addr string) (NetworkAddress, error) {
	var host, port string
	network, host, port, err := SplitNetworkAddress(addr)
	if network == "" {
		network = "tcp"
	}
	if err != nil {
		return NetworkAddress{}, err
	}
	if isUnixNetwork(network) {
		return NetworkAddress{
			Network: network,
			Host:    host,
		}, nil
	}
	ports := strings.SplitN(port, "-", 2)
	if len(ports) == 1 {
		ports = append(ports, ports[0])
	}
	var start, end uint64
	start, err = strconv.ParseUint(ports[0], 10, 16)
	if err != nil {
		return NetworkAddress{}, fmt.Errorf("invalid start port: %v", err)
	}
	end, err = strconv.ParseUint(ports[1], 10, 16)
	if err != nil {
		return NetworkAddress{}, fmt.Errorf("invalid end port: %v", err)
	}
	if end < start {
		return NetworkAddress{}, fmt.Errorf("end port must not be less than start port")
	}
	if (end - start) > maxPortSpan {
		return NetworkAddress{}, fmt.Errorf("port range exceeds %d ports", maxPortSpan)
	}
	return NetworkAddress{
		Network:   network,
		Host:      host,
		StartPort: uint(start),
		EndPort:   uint(end),
	}, nil
}

// SplitNetworkAddress splits a into its network, host, and port components.
// Note that port may be a port range (:X-Y), or omitted for unix sockets.
func SplitNetworkAddress(a string) (network, host, port string, err error) {
	if idx := strings.Index(a, "/"); idx >= 0 {
		network = strings.ToLower(strings.TrimSpace(a[:idx]))
		a = a[idx+1:]
	}
	if isUnixNetwork(network) {
		host = a
		return
	}
	host, port, err = net.SplitHostPort(a)
	return
}

// JoinNetworkAddress combines network, host, and port into a single
// address string of the form accepted by ParseNetworkAddress(). For
// unix sockets, the network should be "unix" (or "unixgram" or
// "unixpacket") and the path to the socket should be given as the
// host parameter.
func JoinNetworkAddress(network, host, port string) string {
	var a string
	if network != "" {
		a = network + "/"
	}
	if (host != "" && port == "") || isUnixNetwork(network) {
		a += host
	} else if port != "" {
		a += net.JoinHostPort(host, port)
	}
	return a
}

// ListenerWrapper is a type that wraps a listener
// so it can modify the input listener's methods.
// Modules that implement this interface are found
// in the caddy.listeners namespace. Usually, to
// wrap a listener, you will define your own struct
// type that embeds the input listener, then
// implement your own methods that you want to wrap,
// calling the underlying listener's methods where
// appropriate.
type ListenerWrapper interface {
	WrapListener(net.Listener) net.Listener
}

// listenerPool stores and allows reuse of active listeners.
var listenerPool = NewUsagePool()

const maxPortSpan = 65535

// Interface guards (see https://github.com/caddyserver/caddy/issues/3998)
var (
	_ (interface{ SetReadBuffer(int) error }) = (*fakeClosePacketConn)(nil)
	_ (interface {
		SyscallConn() (syscall.RawConn, error)
	}) = (*fakeClosePacketConn)(nil)
)
