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
	"io/fs"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/internal"
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

// ListenAll calls Listen() for all addresses represented by this struct, i.e. all ports in the range.
// (If the address doesn't use ports or has 1 port only, then only 1 listener will be created.)
// It returns an error if any listener failed to bind, and closes any listeners opened up to that point.
//
// TODO: Experimental API: subject to change or removal.
func (na NetworkAddress) ListenAll(ctx context.Context, config net.ListenConfig) ([]any, error) {
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
// to close the listener after it has been created.
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
	var (
		ln                  any
		err                 error
		address             string
		unixFileMode        fs.FileMode
		isAbtractUnixSocket bool
	)

	// split unix socket addr early so lnKey
	// is independent of permissions bits
	if na.IsUnixNetwork() {
		var err error
		address, unixFileMode, err = internal.SplitUnixSocketPermissionsBits(na.Host)
		if err != nil {
			return nil, err
		}
		isAbtractUnixSocket = strings.HasPrefix(address, "@")
	} else {
		address = na.JoinHostPort(portOffset)
	}

	// if this is a unix socket, see if we already have it open,
	// force socket permissions on it and return early
	if socket, err := reuseUnixSocket(na.Network, address); socket != nil || err != nil {
		if !isAbtractUnixSocket {
			if err := os.Chmod(address, unixFileMode); err != nil {
				return nil, fmt.Errorf("unable to set permissions (%s) on %s: %v", unixFileMode, address, err)
			}
		}
		return socket, err
	}

	lnKey := listenerKey(na.Network, address)

	if strings.HasPrefix(na.Network, "ip") {
		ln, err = config.ListenPacket(ctx, na.Network, address)
	} else {
		ln, err = listenReusable(ctx, lnKey, na.Network, address, config)
	}
	if err != nil {
		return nil, err
	}
	if ln == nil {
		return nil, fmt.Errorf("unsupported network type: %s", na.Network)
	}

	if IsUnixNetwork(na.Network) {
		if !isAbtractUnixSocket {
			if err := os.Chmod(address, unixFileMode); err != nil {
				return nil, fmt.Errorf("unable to set permissions (%s) on %s: %v", unixFileMode, address, err)
			}
		}
	}

	return ln, nil
}

// IsUnixNetwork returns true if na.Network is
// unix, unixgram, or unixpacket.
func (na NetworkAddress) IsUnixNetwork() bool {
	return IsUnixNetwork(na.Network)
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

// IsUnixNetwork returns true if the netw is a unix network.
func IsUnixNetwork(netw string) bool {
	return strings.HasPrefix(netw, "unix")
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
	return ParseNetworkAddressWithDefaults(addr, "tcp", 0)
}

// ParseNetworkAddressWithDefaults is like ParseNetworkAddress but allows
// the default network and port to be specified.
func ParseNetworkAddressWithDefaults(addr, defaultNetwork string, defaultPort uint) (NetworkAddress, error) {
	var host, port string
	network, host, port, err := SplitNetworkAddress(addr)
	if err != nil {
		return NetworkAddress{}, err
	}
	if network == "" {
		network = defaultNetwork
	}
	if IsUnixNetwork(network) {
		_, _, err := internal.SplitUnixSocketPermissionsBits(host)
		return NetworkAddress{
			Network: network,
			Host:    host,
		}, err
	}
	var start, end uint64
	if port == "" {
		start = uint64(defaultPort)
		end = uint64(defaultPort)
	} else {
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
	if IsUnixNetwork(network) {
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
	if (host != "" && port == "") || IsUnixNetwork(network) {
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
func (na NetworkAddress) ListenQUIC(ctx context.Context, portOffset uint, config net.ListenConfig, tlsConf *tls.Config, activeRequests *int64) (http3.QUICEarlyListener, error) {
	lnKey := listenerKey("quic"+na.Network, na.JoinHostPort(portOffset))

	sharedEarlyListener, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		lnAny, err := na.Listen(ctx, portOffset, config)
		if err != nil {
			return nil, err
		}

		ln := lnAny.(net.PacketConn)

		h3ln := ln
		for {
			// retrieve the underlying socket, so quic-go can optimize.
			if unwrapper, ok := h3ln.(interface{ Unwrap() net.PacketConn }); ok {
				h3ln = unwrapper.Unwrap()
			} else {
				break
			}
		}

		sqs := newSharedQUICState(tlsConf, activeRequests)
		// http3.ConfigureTLSConfig only uses this field and tls App sets this field as well
		//nolint:gosec
		quicTlsConfig := &tls.Config{GetConfigForClient: sqs.getConfigForClient}
		earlyLn, err := quic.ListenEarly(h3ln, http3.ConfigureTLSConfig(quicTlsConfig), &quic.Config{
			Allow0RTT: true,
			RequireAddressValidation: func(clientAddr net.Addr) bool {
				// TODO: make tunable?
				return sqs.getActiveRequests() > 1000
			},
		})
		if err != nil {
			return nil, err
		}
		// using the original net.PacketConn to close them properly
		return &sharedQuicListener{EarlyListener: earlyLn, packetConn: ln, sqs: sqs, key: lnKey}, nil
	})
	if err != nil {
		return nil, err
	}

	sql := sharedEarlyListener.(*sharedQuicListener)
	// add current tls.Config to sqs, so GetConfigForClient will always return the latest tls.Config in case of context cancellation,
	// and the request counter will reflect current http server
	ctx, cancel := sql.sqs.addState(tlsConf, activeRequests)

	return &fakeCloseQuicListener{
		sharedQuicListener: sql,
		context:            ctx,
		contextCancel:      cancel,
	}, nil
}

// DEPRECATED: Use NetworkAddress.ListenQUIC instead. This function will likely be changed or removed in the future.
// TODO: See if we can find a more elegant solution closer to the new NetworkAddress.Listen API.
func ListenQUIC(ln net.PacketConn, tlsConf *tls.Config, activeRequests *int64) (http3.QUICEarlyListener, error) {
	lnKey := listenerKey("quic+"+ln.LocalAddr().Network(), ln.LocalAddr().String())

	sharedEarlyListener, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		sqs := newSharedQUICState(tlsConf, activeRequests)
		// http3.ConfigureTLSConfig only uses this field and tls App sets this field as well
		//nolint:gosec
		quicTlsConfig := &tls.Config{GetConfigForClient: sqs.getConfigForClient}
		earlyLn, err := quic.ListenEarly(ln, http3.ConfigureTLSConfig(quicTlsConfig), &quic.Config{
			Allow0RTT: true,
			RequireAddressValidation: func(clientAddr net.Addr) bool {
				// TODO: make tunable?
				return sqs.getActiveRequests() > 1000
			},
		})
		if err != nil {
			return nil, err
		}
		return &sharedQuicListener{EarlyListener: earlyLn, sqs: sqs, key: lnKey}, nil
	})
	if err != nil {
		return nil, err
	}

	sql := sharedEarlyListener.(*sharedQuicListener)
	// add current tls.Config and request counter to sqs, so GetConfigForClient will always return the latest tls.Config in case of context cancellation,
	// and the request counter will reflect current http server
	ctx, cancel := sql.sqs.addState(tlsConf, activeRequests)

	return &fakeCloseQuicListener{
		sharedQuicListener: sql,
		context:            ctx,
		contextCancel:      cancel,
	}, nil
}

// ListenerUsage returns the current usage count of the given listener address.
func ListenerUsage(network, addr string) int {
	count, _ := listenerPool.References(listenerKey(network, addr))
	return count
}

// contextAndCancelFunc groups context and its cancelFunc
type contextAndCancelFunc struct {
	context.Context
	context.CancelFunc
}

// sharedQUICState manages GetConfigForClient and current number of active requests
// see issue: https://github.com/caddyserver/caddy/pull/4849
type sharedQUICState struct {
	rmu                   sync.RWMutex
	tlsConfs              map[*tls.Config]contextAndCancelFunc
	requestCounters       map[*tls.Config]*int64
	activeTlsConf         *tls.Config
	activeRequestsCounter *int64
}

// newSharedQUICState creates a new sharedQUICState
func newSharedQUICState(tlsConfig *tls.Config, activeRequests *int64) *sharedQUICState {
	sqtc := &sharedQUICState{
		tlsConfs:              make(map[*tls.Config]contextAndCancelFunc),
		requestCounters:       make(map[*tls.Config]*int64),
		activeTlsConf:         tlsConfig,
		activeRequestsCounter: activeRequests,
	}
	sqtc.addState(tlsConfig, activeRequests)
	return sqtc
}

// getConfigForClient is used as tls.Config's GetConfigForClient field
func (sqs *sharedQUICState) getConfigForClient(ch *tls.ClientHelloInfo) (*tls.Config, error) {
	sqs.rmu.RLock()
	defer sqs.rmu.RUnlock()
	return sqs.activeTlsConf.GetConfigForClient(ch)
}

// getActiveRequests returns the number of active requests
func (sqs *sharedQUICState) getActiveRequests() int64 {
	// Prevent a race when a context is cancelled and active request counter is being changed
	sqs.rmu.RLock()
	defer sqs.rmu.RUnlock()
	return atomic.LoadInt64(sqs.activeRequestsCounter)
}

// addState adds tls.Config and activeRequests to the map if not present and returns the corresponding context and its cancelFunc
// so that when cancelled, the active tls.Config and request counter will change
func (sqs *sharedQUICState) addState(tlsConfig *tls.Config, activeRequests *int64) (context.Context, context.CancelFunc) {
	sqs.rmu.Lock()
	defer sqs.rmu.Unlock()

	if cacc, ok := sqs.tlsConfs[tlsConfig]; ok {
		return cacc.Context, cacc.CancelFunc
	}

	ctx, cancel := context.WithCancel(context.Background())
	wrappedCancel := func() {
		cancel()

		sqs.rmu.Lock()
		defer sqs.rmu.Unlock()

		delete(sqs.tlsConfs, tlsConfig)
		delete(sqs.requestCounters, tlsConfig)
		if sqs.activeTlsConf == tlsConfig {
			// select another tls.Config and request counter, if there is none,
			// related sharedQuicListener will be destroyed anyway
			for tc, counter := range sqs.requestCounters {
				sqs.activeTlsConf = tc
				sqs.activeRequestsCounter = counter
				break
			}
		}
	}
	sqs.tlsConfs[tlsConfig] = contextAndCancelFunc{ctx, wrappedCancel}
	sqs.requestCounters[tlsConfig] = activeRequests
	// there should be at most 2 tls.Configs
	if len(sqs.tlsConfs) > 2 {
		Log().Warn("quic listener tls configs are more than 2", zap.Int("number of configs", len(sqs.tlsConfs)))
	}
	return ctx, wrappedCancel
}

// sharedQuicListener is like sharedListener, but for quic.EarlyListeners.
type sharedQuicListener struct {
	*quic.EarlyListener
	packetConn net.PacketConn // we have to hold these because quic-go won't close listeners it didn't create
	sqs        *sharedQUICState
	key        string
}

// Destruct closes the underlying QUIC listener and its associated net.PacketConn.
func (sql *sharedQuicListener) Destruct() error {
	// close EarlyListener first to stop any operations being done to the net.PacketConn
	_ = sql.EarlyListener.Close()
	// then close the net.PacketConn
	return sql.packetConn.Close()
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

var unixSocketsMu sync.Mutex

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
