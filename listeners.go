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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"go.uber.org/zap"
)

// ListenPacket returns a net.PacketConn suitable for use in a Caddy module.
// It is like Listen except for PacketConns.
// Always be sure to close the PacketConn when you are done.
func ListenPacket(network, addr string) (net.PacketConn, error) {
	lnKey := listenerKey(network, addr)

	sharedPc, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		pc, err := net.ListenPacket(network, addr)
		if err != nil {
			// https://github.com/caddyserver/caddy/pull/4534
			if isUnixNetwork(network) && isListenBindAddressAlreadyInUseError(err) {
				return nil, fmt.Errorf("%w: this can happen if Caddy was forcefully killed", err)
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

// ListenQUIC returns a quic.EarlyListener suitable for use in a Caddy module.
// Note that the context passed to Accept is currently ignored, so using
// a context other than context.Background is meaningless.
func ListenQUIC(addr string, tlsConf *tls.Config, activeRequests *int64) (quic.EarlyListener, error) {
	lnKey := listenerKey("udp", addr)

	sharedEl, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		el, err := quic.ListenAddrEarly(addr, http3.ConfigureTLSConfig(tlsConf), &quic.Config{
			RequireAddressValidation: func(clientAddr net.Addr) bool {
				var highLoad bool
				if activeRequests != nil {
					highLoad = atomic.LoadInt64(activeRequests) > 1000 // TODO: make tunable?
				}
				return highLoad
			},
		})
		if err != nil {
			return nil, err
		}
		return &sharedQuicListener{EarlyListener: el, key: lnKey}, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	return &fakeCloseQuicListener{
		sharedQuicListener: sharedEl.(*sharedQuicListener),
		context:            ctx, contextCancel: cancel,
	}, err
}

// ListenerUsage returns the current usage count of the given listener address.
func ListenerUsage(network, addr string) int {
	count, _ := listenerPool.References(listenerKey(network, addr))
	return count
}

func listenerKey(network, addr string) string {
	return network + "/" + addr
}

type fakeCloseQuicListener struct {
	closed              int32 // accessed atomically; belongs to this struct only
	*sharedQuicListener       // embedded, so we also become a quic.EarlyListener
	context             context.Context
	contextCancel       context.CancelFunc
}

// Currently Accept ignores the passed context, however a situation where
// someone would need a hotswappable QUIC-only (not http3, since it uses context.Background here)
// server on which Accept would be called with non-empty contexts
// (mind that the default net listeners' Accept doesn't take a context argument)
// sounds way too rare for us to sacrifice efficiency here.
func (fcql *fakeCloseQuicListener) Accept(_ context.Context) (quic.EarlyConnection, error) {
	conn, err := fcql.sharedQuicListener.Accept(fcql.context)
	if err == nil {
		return conn, nil
	}

	// if the listener is "closed", return a fake closed error instead
	if atomic.LoadInt32(&fcql.closed) == 1 && errors.Is(err, context.Canceled) {
		return nil, fakeClosedErr(fcql)
	}
	return nil, err
}

func (fcql *fakeCloseQuicListener) Close() error {
	if atomic.CompareAndSwapInt32(&fcql.closed, 0, 1) {
		fcql.contextCancel()
		_, _ = listenerPool.Delete(fcql.sharedQuicListener.key)
	}
	return nil
}

// fakeClosedErr returns an error value that is not temporary
// nor a timeout, suitable for making the caller think the
// listener is actually closed
func fakeClosedErr(l interface{ Addr() net.Addr }) error {
	return &net.OpError{
		Op:   "accept",
		Net:  l.Addr().Network(),
		Addr: l.Addr(),
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

// sharedQuicListener is like sharedListener, but for quic.EarlyListeners.
type sharedQuicListener struct {
	quic.EarlyListener
	key string
}

// Destruct closes the underlying QUIC listener.
func (sql *sharedQuicListener) Destruct() error {
	return sql.EarlyListener.Close()
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

func (na NetworkAddress) Expand() []NetworkAddress {
	size := na.PortRangeSize()
	addrs := make([]NetworkAddress, size)
	for portOffset := uint(0); portOffset < size; portOffset++ {
		na2 := na
		na2.StartPort, na2.EndPort = na.StartPort+portOffset, na.StartPort+portOffset
		addrs[portOffset] = na2
	}
	return addrs
}

// PortRangeSize returns how many ports are in
// pa's port range. Port ranges are inclusive,
// so the size is the difference of start and
// end ports plus one.
func (na NetworkAddress) PortRangeSize() uint {
	if na.EndPort < na.StartPort {
		return 0
	}
	return (na.EndPort - na.StartPort) + 1
}

func (na NetworkAddress) isLoopback() bool {
	if na.IsUnixNetwork() {
		return true
	}
	if na.Host == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(na.Host); err == nil {
		return ip.IsLoopback()
	}
	return false
}

func (na NetworkAddress) isWildcardInterface() bool {
	if na.Host == "" {
		return true
	}
	if ip, err := netip.ParseAddr(na.Host); err == nil {
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

// String reconstructs the address string for human display.
// The output can be parsed by ParseNetworkAddress(). If the
// address is a unix socket, any non-zero port will be dropped.
func (na NetworkAddress) String() string {
	if na.Network == "tcp" && (na.Host != "" || na.port() != "") {
		na.Network = "" // omit default network value for brevity
	}
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
	if err != nil {
		return NetworkAddress{}, err
	}
	if network == "" {
		network = "tcp"
	}
	if isUnixNetwork(network) {
		return NetworkAddress{
			Network: network,
			Host:    host,
		}, nil
	}
	var start, end uint64
	if port != "" {
		before, after, found := strings.Cut(port, "-")
		if !found {
			after = before
		}
		start, err = strconv.ParseUint(before, 10, 16)
		if err != nil {
			return NetworkAddress{}, fmt.Errorf("invalid start port: %v", err)
		}
		end, err = strconv.ParseUint(after, 10, 16)
		if err != nil {
			return NetworkAddress{}, fmt.Errorf("invalid end port: %v", err)
		}
		if end < start {
			return NetworkAddress{}, fmt.Errorf("end port must not be less than start port")
		}
		if (end - start) > maxPortSpan {
			return NetworkAddress{}, fmt.Errorf("port range exceeds %d ports", maxPortSpan)
		}
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
	beforeSlash, afterSlash, slashFound := strings.Cut(a, "/")
	if slashFound {
		network = strings.ToLower(strings.TrimSpace(beforeSlash))
		a = afterSlash
	}
	if isUnixNetwork(network) {
		host = a
		return
	}
	host, port, err = net.SplitHostPort(a)
	if err == nil || a == "" {
		return
	}
	// in general, if there was an error, it was likely "missing port",
	// so try adding a bogus port to take advantage of standard library's
	// robust parser, then strip the artificial port before returning
	// (don't overwrite original error though; might still be relevant)
	var err2 error
	host, port, err2 = net.SplitHostPort(a + ":0")
	if err2 == nil {
		err = nil
		port = ""
	}
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

// RegisterNetwork registers a network type with Caddy so that if a listener is
// created for that network type, getListener will be invoked to get the listener.
// This should be called during init() and will panic if the network type is standard
// or reserved, or if it is already registered. EXPERIMENTAL and subject to change.
func RegisterNetwork(network string, getListener ListenerFunc) {
	network = strings.TrimSpace(strings.ToLower(network))

	if network == "tcp" || network == "tcp4" || network == "tcp6" ||
		network == "udp" || network == "udp4" || network == "udp6" ||
		network == "unix" || network == "unixpacket" || network == "unixgram" ||
		strings.HasPrefix("ip:", network) || strings.HasPrefix("ip4:", network) || strings.HasPrefix("ip6:", network) {
		panic("network type " + network + " is reserved")
	}

	if _, ok := networkTypes[strings.ToLower(network)]; ok {
		panic("network type " + network + " is already registered")
	}

	networkTypes[network] = getListener
}

// ListenerFunc is a function that can return a listener given a network and address.
// The listeners must be capable of overlapping: with Caddy, new configs are loaded
// before old ones are unloaded, so listeners may overlap briefly if the configs
// both need the same listener. EXPERIMENTAL and subject to change.
type ListenerFunc func(network, addr string) (net.Listener, error)

var networkTypes = map[string]ListenerFunc{}

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
