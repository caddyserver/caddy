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
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"go.uber.org/zap"
)

// NetworkAddress represents one or more network addresses.
// It contains the individual components for a parsed network
// address of the form accepted by ParseNetworkAddress().
type NetworkAddress struct {
	// Should be a network value accepted by Go's net package or
	// by a plugin providing a listener for that network type.
	Network string

	// The "main" part of the network address is the host, which
	// often takes the form of a hostname, DNS name, IP address,
	// or socket path.
	Host string

	// For addresses that contain a port, ranges are given by
	// [StartPort, EndPort]; i.e. for a single port, StartPort
	// and EndPort are the same. For no port, they are 0.
	StartPort uint
	EndPort   uint
}

// TODO: is this even useful? I might remove this.
func (na NetworkAddress) ListenAll(ctx context.Context, portOffset uint, config net.ListenConfig) ([]any, error) {
	var listeners []any
	var err error

	// if one of the addresses has a failure, we need to close
	// any that did open a socket to avoid leaking resources
	defer func() {
		if err == nil {
			return
		}
		for _, ln := range listeners {
			if cl, ok := ln.(io.Closer); ok {
				cl.Close()
			}
		}
	}()

	// an address can contain a port range, which represents multiple addresses;
	// some addresses don't use ports at all and have a port range size of 1;
	// whatever the case, iterate each address represented and bind a socket
	for portOffset := uint(0); portOffset < na.PortRangeSize(); portOffset++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// create (or reuse) the listener ourselves
		var ln any
		ln, err = na.Listen(ctx, portOffset, config)
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, ln)
	}

	return listeners, nil
}

// Listen is similar to net.Listen, with a few differences:
//
// Listen announces on the network address using the port calculated by adding
// portOffset to the start port. (For network types that do not use ports, the
// portOffset is ignored.)
//
// The provided ListenConfig is used to create the listener. Its Control function,
// if set, may be wrapped by an internally-used Control function. The provided
// context may be used to cancel long operations early. The context is not used
// to close the actual listener after it has been created.
//
// Caddy's listeners can overlap each other: multiple listeners may be created on
// the same socket at the same time. This is useful because during config changes,
// the new config is started while the old config is still running. How this is
// accomplished varies by platform and network type. For example, on Unix, SO_REUSEPORT
// is set except on Unix sockets, for which the file descriptor is duplicated and
// reused; on Windows, the close logic is virtualized using timeouts. Like normal
// listeners, be sure to Close() them when you are done.
//
// This method returns any type, as the implementations of listeners for various
// network types are not interchangeable. The type of listener returned is switched
// on the network type. Stream-based networks ("tcp", "unix", "unixpacket", etc.)
// return a net.Listener; datagram-based networks ("udp", "unixgram", etc.) return
// a net.PacketConn; and so forth. The actual concrete types are not guaranteed to
// be standard, exported types (wrapping is necessary to provide graceful reloads).
//
// Unix sockets will be unlinked before being created, to ensure we can bind to
// it even if the previous program using it exited uncleanly; it will also be
// unlinked upon a graceful exit (or when a new config does not use that socket).
//
// TODO: Experimental API: subject to change or removal.
func (na NetworkAddress) Listen(ctx context.Context, portOffset uint, config net.ListenConfig) (any, error) {
	if na.IsUnixNetwork() {
		unixSocketsMu.Lock()
		defer unixSocketsMu.Unlock()
	}

	// check to see if plugin provides listener
	if ln, err := getListenerFromPlugin(ctx, na.Network, na.JoinHostPort(portOffset), config); ln != nil || err != nil {
		return ln, err
	}

	// create (or reuse) the listener ourselves
	return na.listen(ctx, portOffset, config)
}

func (na NetworkAddress) listen(ctx context.Context, portOffset uint, config net.ListenConfig) (any, error) {
	var ln any
	var err error

	address := na.JoinHostPort(portOffset)

	// if this is a unix socket, see if we already have it open
	if socket, err := reuseUnixSocket(na.Network, address); socket != nil || err != nil {
		return socket, err
	}

	lnKey := listenerKey(na.Network, address)

	switch na.Network {
	case "tcp", "tcp4", "tcp6", "unix", "unixpacket":
		ln, err = listenTCPOrUnix(ctx, lnKey, na.Network, address, config)
	case "unixgram":
		ln, err = config.ListenPacket(ctx, na.Network, address)
	case "udp", "udp4", "udp6":
		sharedPc, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
			pc, err := config.ListenPacket(ctx, na.Network, address)
			if err != nil {
				return nil, err
			}
			return &sharedPacketConn{PacketConn: pc, key: lnKey}, nil
		})
		if err != nil {
			return nil, err
		}
		ln = &fakeClosePacketConn{sharedPacketConn: sharedPc.(*sharedPacketConn)}
	}
	if strings.HasPrefix(na.Network, "ip") {
		ln, err = config.ListenPacket(ctx, na.Network, address)
	}
	if err != nil {
		return nil, err
	}
	if ln == nil {
		return nil, fmt.Errorf("unsupported network type: %s", na.Network)
	}

	// if new listener is a unix socket, make sure we can reuse it later
	// (we do our own "unlink on close" -- not required, but more tidy)
	one := int32(1)
	switch unix := ln.(type) {
	case *net.UnixListener:
		unix.SetUnlinkOnClose(false)
		ln = &unixListener{unix, lnKey, &one}
		unixSockets[lnKey] = ln.(*unixListener)
	case *net.UnixConn:
		ln = &unixConn{unix, address, lnKey, &one}
		unixSockets[lnKey] = ln.(*unixConn)
	}

	return ln, nil
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

// Expand returns one NetworkAddress for each port in the port range.
//
// This is EXPERIMENTAL and subject to change or removal.
func (na NetworkAddress) Expand() []NetworkAddress {
	size := na.PortRangeSize()
	addrs := make([]NetworkAddress, size)
	for portOffset := uint(0); portOffset < size; portOffset++ {
		addrs[portOffset] = na.At(portOffset)
	}
	return addrs
}

// At returns a NetworkAddress with a port range of just 1
// at the given port offset; i.e. a NetworkAddress that
// represents precisely 1 address only.
func (na NetworkAddress) At(portOffset uint) NetworkAddress {
	na2 := na
	na2.StartPort, na2.EndPort = na.StartPort+portOffset, na.StartPort+portOffset
	return na2
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

// DEPRECATED: Use NetworkAddress.Listen instead. This function will likely be changed or removed in the future.
func Listen(network, addr string) (net.Listener, error) {
	// a 0 timeout means Go uses its default
	return ListenTimeout(network, addr, 0)
}

// DEPRECATED: Use NetworkAddress.Listen instead. This function will likely be changed or removed in the future.
func ListenTimeout(network, addr string, keepalivePeriod time.Duration) (net.Listener, error) {
	netAddr, err := ParseNetworkAddress(JoinNetworkAddress(network, addr, ""))
	if err != nil {
		return nil, err
	}

	ln, err := netAddr.Listen(context.TODO(), 0, net.ListenConfig{KeepAlive: keepalivePeriod})
	if err != nil {
		return nil, err
	}

	return ln.(net.Listener), nil
}

// DEPRECATED: Use NetworkAddress.Listen instead. This function will likely be changed or removed in the future.
func ListenPacket(network, addr string) (net.PacketConn, error) {
	netAddr, err := ParseNetworkAddress(JoinNetworkAddress(network, addr, ""))
	if err != nil {
		return nil, err
	}

	ln, err := netAddr.Listen(context.TODO(), 0, net.ListenConfig{})
	if err != nil {
		return nil, err
	}

	return ln.(net.PacketConn), nil
}

// ListenQUIC returns a quic.EarlyListener suitable for use in a Caddy module.
// The network will be transformed into a QUIC-compatible type (if unix, then
// unixgram will be used; otherwise, udp will be used).
//
// NOTE: This API is EXPERIMENTAL and may be changed or removed.
//
// TODO: See if we can find a more elegant solution closer to the new NetworkAddress.Listen API.
func ListenQUIC(ln net.PacketConn, tlsConf *tls.Config, activeRequests *int64) (quic.EarlyListener, error) {
	lnKey := listenerKey(ln.LocalAddr().Network(), ln.LocalAddr().String())

	sharedEarlyListener, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		earlyLn, err := quic.ListenEarly(ln, http3.ConfigureTLSConfig(tlsConf), &quic.Config{
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

		return &sharedQuicListener{EarlyListener: earlyLn, key: lnKey}, nil
	})
	if err != nil {
		return nil, err
	}

	// TODO: to serve QUIC over a unix socket, currently we need to hold onto
	// the underlying net.PacketConn (which we wrap as unixConn to keep count
	// of closes) because closing the quic.EarlyListener doesn't actually close
	// the underlying PacketConn, but we need to for unix sockets since we dup
	// the file descriptor and thus need to close the original; track issue:
	// https://github.com/lucas-clemente/quic-go/issues/3560#issuecomment-1258959608
	var unix *unixConn
	if uc, ok := ln.(*unixConn); ok {
		unix = uc
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &fakeCloseQuicListener{
		sharedQuicListener: sharedEarlyListener.(*sharedQuicListener),
		uc:                 unix,
		context:            ctx,
		contextCancel:      cancel,
	}, nil
}

// ListenerUsage returns the current usage count of the given listener address.
func ListenerUsage(network, addr string) int {
	count, _ := listenerPool.References(listenerKey(network, addr))
	return count
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

// errFakeClosed is the underlying error value returned by
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

type fakeCloseQuicListener struct {
	closed              int32     // accessed atomically; belongs to this struct only
	*sharedQuicListener           // embedded, so we also become a quic.EarlyListener
	uc                  *unixConn // underlying unix socket, if UDS
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
		if fcql.uc != nil {
			// unix sockets need to be closed ourselves because we dup() the file
			// descriptor when we reuse them, so this avoids a resource leak
			fcql.uc.Close()
		}
	}
	return nil
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

type unixListener struct {
	*net.UnixListener
	mapKey string
	count  *int32 // accessed atomically
}

func (uln *unixListener) Close() error {
	newCount := atomic.AddInt32(uln.count, -1)
	if newCount == 0 {
		defer func() {
			addr := uln.Addr().String()
			unixSocketsMu.Lock()
			delete(unixSockets, uln.mapKey)
			unixSocketsMu.Unlock()
			syscall.Unlink(addr)
		}()
	}
	return uln.UnixListener.Close()
}

type unixConn struct {
	*net.UnixConn
	filename string
	mapKey   string
	count    *int32 // accessed atomically
}

func (uc *unixConn) Close() error {
	newCount := atomic.AddInt32(uc.count, -1)
	if newCount == 0 {
		defer func() {
			unixSocketsMu.Lock()
			delete(unixSockets, uc.mapKey)
			unixSocketsMu.Unlock()
			syscall.Unlink(uc.filename)
		}()
	}
	return uc.UnixConn.Close()
}

// unixSockets keeps track of the currently-active unix sockets
// so we can transfer their FDs gracefully during reloads.
var (
	unixSockets = make(map[string]interface {
		File() (*os.File, error)
	})
	unixSocketsMu sync.Mutex
)

// getListenerFromPlugin returns a listener on the given network and address
// if a plugin has registered the network name. It may return (nil, nil) if
// no plugin can provide a listener.
func getListenerFromPlugin(ctx context.Context, network, addr string, config net.ListenConfig) (any, error) {
	// get listener from plugin if network type is registered
	if getListener, ok := networkTypes[network]; ok {
		Log().Debug("getting listener from plugin", zap.String("network", network))
		return getListener(ctx, network, addr, config)
	}

	return nil, nil
}

func listenerKey(network, addr string) string {
	return network + "/" + addr
}

// ListenerFunc is a function that can return a listener given a network and address.
// The listeners must be capable of overlapping: with Caddy, new configs are loaded
// before old ones are unloaded, so listeners may overlap briefly if the configs
// both need the same listener. EXPERIMENTAL and subject to change.
type ListenerFunc func(ctx context.Context, network, addr string, cfg net.ListenConfig) (any, error)

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
