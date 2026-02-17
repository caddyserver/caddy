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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	h3qlog "github.com/quic-go/quic-go/http3/qlog"
	"go.uber.org/zap"
	"golang.org/x/time/rate"

	"github.com/caddyserver/caddy/v2/internal"
)

// listenFdsStart is the first file descriptor number for systemd socket activation.
// File descriptors 0, 1, 2 are reserved for stdin, stdout, stderr.
const listenFdsStart = 3

// InterfaceDelimiter is used to separate interface name from binding mode
const InterfaceDelimiter = "||"

const (
	// maxInterfaceNameUnix represents the maximum interface name length on Unix-like systems
	// Based on IFNAMSIZ = 16 (15 characters + null terminator)
	maxInterfaceNameUnix = 15

	// maxInterfaceNameWindows represents the maximum interface name length on Windows
	// These systems use a more complex naming structure with MAX_ADAPTER_NAME_LENGTH allowing 256 characters
	maxInterfaceNameWindows = 255
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

// ListenAll calls Listen for all addresses represented by this struct, i.e. all ports in the range.
// (If the address doesn't use ports or has 1 port only, then only 1 listener will be created.)
// It returns an error if any listener failed to bind, and closes any listeners opened up to that point.
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
// First Listen checks if a plugin can provide a listener from this address. Otherwise,
// the provided ListenConfig is used to create the listener. Its Control function,
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
// Listen synchronizes binds to unix domain sockets to avoid race conditions
// while an existing socket is unlinked.
func (na NetworkAddress) Listen(ctx context.Context, portOffset uint, config net.ListenConfig) (any, error) {
	if na.IsUnixNetwork() {
		unixSocketsMu.Lock()
		defer unixSocketsMu.Unlock()
	}

	// If this is an interface name, resolve it to an IP address and create a listener
	if na.IsInterfaceNetwork() {
		return na.listenInterface(ctx, portOffset, config)
	}

	// check to see if plugin provides listener
	if ln, err := getListenerFromPlugin(ctx, na.Network, na.Host, na.port(), portOffset, config); ln != nil || err != nil {
		return ln, err
	}

	// create (or reuse) the listener ourselves
	return na.listen(ctx, portOffset, config)
}

// listenInterface resolves an interface name to an IP address and creates a listener.
// For all binding modes, this function always returns one listener using the first resolved IP.
// For multi-address modes (ipv4, ipv6, all), the expansion to multiple listeners
// happens at the HTTP Caddyfile parser level (see addresses.go).
func (na NetworkAddress) listenInterface(ctx context.Context, portOffset uint, config net.ListenConfig) (any, error) {
	// Decode interface name and mode from Host field
	// Format: "interface_name||mode"
	var ifaceName string
	mode := InterfaceBindingAuto

	if strings.Contains(na.Host, InterfaceDelimiter) {
		parts := strings.SplitN(na.Host, InterfaceDelimiter, 2)
		if len(parts) == 2 {
			ifaceName = parts[0]
			mode = InterfaceBindingMode(parts[1])
		}
	} else {
		ifaceName = na.Host
	}

	// Resolve interface name to IP addresses with mode
	ipAddresses, err := ResolveInterfaceNameWithMode(ifaceName, mode)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve interface %s with mode %s: %v", ifaceName, mode, err)
	}

	resolvedNA := na
	resolvedNA.Host = ipAddresses[0]

	Log().Debug("resolved interface to IP",
		zap.String("interface", ifaceName),
		zap.String("mode", string(mode)),
		zap.String("selected_ip", ipAddresses[0]))

	return resolvedNA.listen(ctx, portOffset, config)
}

func (na NetworkAddress) listen(ctx context.Context, portOffset uint, config net.ListenConfig) (any, error) {
	var (
		ln           any
		err          error
		address      string
		unixFileMode fs.FileMode
	)

	// split unix socket addr early so lnKey
	// is independent of permissions bits
	if na.IsUnixNetwork() {
		address, unixFileMode, err = internal.SplitUnixSocketPermissionsBits(na.Host)
		if err != nil {
			return nil, err
		}
	} else if na.IsFdNetwork() {
		address = na.Host
	} else {
		address = na.JoinHostPort(portOffset)
	}

	if strings.HasPrefix(na.Network, "ip") {
		ln, err = config.ListenPacket(ctx, na.Network, address)
	} else {
		if na.IsUnixNetwork() {
			// if this is a unix socket, see if we already have it open
			ln, err = reuseUnixSocket(na.Network, address)
		}

		if ln == nil && err == nil {
			// otherwise, create a new listener
			lnKey := listenerKey(na.Network, address)
			ln, err = listenReusable(ctx, lnKey, na.Network, address, config)
		}
	}

	if err != nil {
		return nil, err
	}

	if ln == nil {
		return nil, fmt.Errorf("unsupported network type: %s", na.Network)
	}

	if IsUnixNetwork(na.Network) {
		isAbstractUnixSocket := strings.HasPrefix(address, "@")
		if !isAbstractUnixSocket {
			err = os.Chmod(address, unixFileMode)
			if err != nil {
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

// IsFdNetwork returns true if na.Network is
// fd or fdgram.
func (na NetworkAddress) IsFdNetwork() bool {
	return IsFdNetwork(na.Network)
}

// IsInterfaceNetwork returns true if na.Host appears to be a network interface name
// and na.Network supports interface binding (tcp/udp).
func (na NetworkAddress) IsInterfaceNetwork() bool {
	if na.Network != "tcp" && na.Network != "udp" {
		return false
	}

	// Handle encoded interface name with mode: "interface_name||mode"
	hostToCheck := na.Host
	if strings.Contains(na.Host, InterfaceDelimiter) {
		parts := strings.SplitN(na.Host, InterfaceDelimiter, 2)
		if len(parts) == 2 {
			hostToCheck = parts[0] // Extract just the interface name part
		}
	}

	return isInterfaceName(hostToCheck)
}

// JoinHostPort is like net.JoinHostPort, but where the port
// is StartPort + offset.
func (na NetworkAddress) JoinHostPort(offset uint) string {
	if na.IsUnixNetwork() || na.IsFdNetwork() {
		return na.Host
	}
	return net.JoinHostPort(na.Host, strconv.FormatUint(uint64(na.StartPort+offset), 10))
}

// Expand returns one NetworkAddress for each port in the port range.
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
	if na.IsUnixNetwork() || na.IsFdNetwork() {
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

// IsFdNetwork returns true if the netw is a fd network.
func IsFdNetwork(netw string) bool {
	return strings.HasPrefix(netw, "fd")
}

// getFdByName returns the file descriptor number for the given
// socket name from systemd's LISTEN_FDNAMES environment variable.
// Socket names are provided by systemd via socket activation.
//
// The name can optionally include an index to handle multiple sockets
// with the same name: "web:0" for first, "web:1" for second, etc.
// If no index is specified, defaults to index 0 (first occurrence).
func getFdByName(nameWithIndex string) (int, error) {
	if nameWithIndex == "" {
		return 0, fmt.Errorf("socket name cannot be empty")
	}

	fdNamesStr := os.Getenv("LISTEN_FDNAMES")
	if fdNamesStr == "" {
		return 0, fmt.Errorf("LISTEN_FDNAMES environment variable not set")
	}

	// Parse name and optional index
	parts := strings.Split(nameWithIndex, ":")
	if len(parts) > 2 {
		return 0, fmt.Errorf("invalid socket name format '%s': too many colons", nameWithIndex)
	}

	name := parts[0]
	targetIndex := 0

	if len(parts) > 1 {
		var err error
		targetIndex, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, fmt.Errorf("invalid socket index '%s': %v", parts[1], err)
		}
		if targetIndex < 0 {
			return 0, fmt.Errorf("socket index cannot be negative: %d", targetIndex)
		}
	}

	// Parse the socket names
	names := strings.Split(fdNamesStr, ":")

	// Find the Nth occurrence of the requested name
	matchCount := 0
	for i, fdName := range names {
		if fdName == name {
			if matchCount == targetIndex {
				return listenFdsStart + i, nil
			}
			matchCount++
		}
	}

	if matchCount == 0 {
		return 0, fmt.Errorf("socket name '%s' not found in LISTEN_FDNAMES", name)
	}

	return 0, fmt.Errorf("socket name '%s' found %d times, but index %d requested", name, matchCount, targetIndex)
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
	if IsFdNetwork(network) {
		fdAddr := host

		// Handle named socket activation (fdname/name, fdgramname/name)
		if strings.HasPrefix(network, "fdname") || strings.HasPrefix(network, "fdgramname") {
			fdNum, err := getFdByName(host)
			if err != nil {
				return NetworkAddress{}, fmt.Errorf("named socket activation: %v", err)
			}
			fdAddr = strconv.Itoa(fdNum)

			// Normalize network to standard fd/fdgram
			if strings.HasPrefix(network, "fdname") {
				network = "fd"
			} else {
				network = "fdgram"
			}
		}

		return NetworkAddress{
			Network: network,
			Host:    fdAddr,
		}, nil
	}

	// Check if this might be an interface name for TCP/UDP networks
	if (network == "tcp" || network == "udp") && isInterfaceName(host) {
		if port == "" {
			if defaultPort == 0 {
				return NetworkAddress{}, fmt.Errorf("interface binding requires a port")
			}
			port = strconv.FormatUint(uint64(defaultPort), 10)
		}
		return parseInterfaceAddress(network, host, port)
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
		if IsUnixNetwork(network) || IsFdNetwork(network) {
			host = a
			return network, host, port, err
		}
	}

	host, port, err = net.SplitHostPort(a)
	firstErr := err

	if err != nil {
		// in general, if there was an error, it was likely "missing port",
		// so try removing square brackets around an IPv6 host, adding a bogus
		// port to take advantage of standard library's robust parser, then
		// strip the artificial port.
		host, _, err = net.SplitHostPort(net.JoinHostPort(strings.Trim(a, "[]"), "0"))
		port = ""
	}

	if err != nil {
		err = errors.Join(firstErr, err)
	}

	return network, host, port, err
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
	if (host != "" && port == "") || IsUnixNetwork(network) || IsFdNetwork(network) {
		a += host
	} else if port != "" {
		a += net.JoinHostPort(host, port)
	}
	return a
}

// ListenQUIC returns a http3.QUICEarlyListener suitable for use in a Caddy module.
//
// The network will be transformed into a QUIC-compatible type if the same address can be used with
// different networks. Currently this just means that for tcp, udp will be used with the same
// address instead.
//
// NOTE: This API is EXPERIMENTAL and may be changed or removed.
// NOTE: user should close the returned listener twice, once to stop accepting new connections, the second time to free up the packet conn.
func (na NetworkAddress) ListenQUIC(ctx context.Context, portOffset uint, config net.ListenConfig, tlsConf *tls.Config, pcWrappers []PacketConnWrapper, allow0rttconf *bool) (http3.QUICListener, error) {
	lnKey := listenerKey("quic"+na.Network, na.JoinHostPort(portOffset))

	sharedEarlyListener, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		lnAny, err := na.Listen(ctx, portOffset, config)
		if err != nil {
			return nil, err
		}

		ln := lnAny.(net.PacketConn)

		h3ln := ln
		if len(pcWrappers) == 0 {
			for {
				// retrieve the underlying socket, so quic-go can optimize.
				if unwrapper, ok := h3ln.(interface{ Unwrap() net.PacketConn }); ok {
					h3ln = unwrapper.Unwrap()
				} else {
					break
				}
			}
		} else {
			// wrap packet conn before QUIC
			for _, pcWrapper := range pcWrappers {
				h3ln = pcWrapper.WrapPacketConn(h3ln)
			}
		}

		sqs := newSharedQUICState(tlsConf)
		// http3.ConfigureTLSConfig only uses this field and tls App sets this field as well
		//nolint:gosec
		quicTlsConfig := &tls.Config{GetConfigForClient: sqs.getConfigForClient}
		// Require clients to verify their source address when we're handling more than 1000 handshakes per second.
		// TODO: make tunable?
		limiter := rate.NewLimiter(1000, 1000)
		tr := &quic.Transport{
			Conn:                h3ln,
			VerifySourceAddress: func(addr net.Addr) bool { return !limiter.Allow() },
		}
		allow0rtt := true
		if allow0rttconf != nil {
			allow0rtt = *allow0rttconf
		}
		earlyLn, err := tr.ListenEarly(
			http3.ConfigureTLSConfig(quicTlsConfig),
			&quic.Config{
				Allow0RTT: allow0rtt,
				Tracer:    h3qlog.DefaultConnectionTracer,
			},
		)
		if err != nil {
			return nil, err
		}
		// TODO: figure out when to close the listener and the transport
		// using the original net.PacketConn to close them properly
		return &sharedQuicListener{EarlyListener: earlyLn, packetConn: ln, sqs: sqs, key: lnKey}, nil
	})
	if err != nil {
		return nil, err
	}

	sql := sharedEarlyListener.(*sharedQuicListener)
	// add current tls.Config to sqs, so GetConfigForClient will always return the latest tls.Config in case of context cancellation
	ctx, cancel := sql.sqs.addState(tlsConf)

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

// sharedQUICState manages GetConfigForClient
// see issue: https://github.com/caddyserver/caddy/pull/4849
type sharedQUICState struct {
	rmu           sync.RWMutex
	tlsConfs      map[*tls.Config]contextAndCancelFunc
	activeTlsConf *tls.Config
}

// newSharedQUICState creates a new sharedQUICState
func newSharedQUICState(tlsConfig *tls.Config) *sharedQUICState {
	sqtc := &sharedQUICState{
		tlsConfs:      make(map[*tls.Config]contextAndCancelFunc),
		activeTlsConf: tlsConfig,
	}
	sqtc.addState(tlsConfig)
	return sqtc
}

// getConfigForClient is used as tls.Config's GetConfigForClient field
func (sqs *sharedQUICState) getConfigForClient(ch *tls.ClientHelloInfo) (*tls.Config, error) {
	sqs.rmu.RLock()
	defer sqs.rmu.RUnlock()
	return sqs.activeTlsConf.GetConfigForClient(ch)
}

// addState adds tls.Config and activeRequests to the map if not present and returns the corresponding context and its cancelFunc
// so that when cancelled, the active tls.Config will change
func (sqs *sharedQUICState) addState(tlsConfig *tls.Config) (context.Context, context.CancelFunc) {
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
		if sqs.activeTlsConf == tlsConfig {
			// select another tls.Config, if there is none,
			// related sharedQuicListener will be destroyed anyway
			for tc := range sqs.tlsConfs {
				sqs.activeTlsConf = tc
				break
			}
		}
	}
	sqs.tlsConfs[tlsConfig] = contextAndCancelFunc{ctx, wrappedCancel}
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
func (fcql *fakeCloseQuicListener) Accept(_ context.Context) (*quic.Conn, error) {
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
	} else if atomic.CompareAndSwapInt32(&fcql.closed, 1, 2) {
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
		strings.HasPrefix(network, "ip:") || strings.HasPrefix(network, "ip4:") || strings.HasPrefix(network, "ip6:") ||
		network == "fd" || network == "fdgram" {
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
func getListenerFromPlugin(ctx context.Context, network, host, port string, portOffset uint, config net.ListenConfig) (any, error) {
	// get listener from plugin if network type is registered
	if getListener, ok := networkTypes[network]; ok {
		Log().Debug("getting listener from plugin", zap.String("network", network))
		return getListener(ctx, network, host, port, portOffset, config)
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
type ListenerFunc func(ctx context.Context, network, host, portRange string, portOffset uint, cfg net.ListenConfig) (any, error)

var networkTypes = map[string]ListenerFunc{}

// InterfaceBindingMode defines how to bind to interface IP addresses.
// EXPERIMENTAL: Subject to change.
type InterfaceBindingMode string

const (
	// InterfaceBindingAuto uses the first IPv4 address, fallback to first IPv6
	InterfaceBindingAuto InterfaceBindingMode = "auto"
	// InterfaceBindingFirstIPv4 binds to the first IPv4 address of the interface
	InterfaceBindingFirstIPv4 InterfaceBindingMode = "firstipv4"
	// InterfaceBindingFirstIPv6 binds to the first IPv6 address of the interface
	InterfaceBindingFirstIPv6 InterfaceBindingMode = "firstipv6"
	// InterfaceBindingIPv4 binds to all IPv4 addresses of the interface
	InterfaceBindingIPv4 InterfaceBindingMode = "ipv4"
	// InterfaceBindingIPv6 binds to all IPv6 addresses of the interface
	InterfaceBindingIPv6 InterfaceBindingMode = "ipv6"
	// InterfaceBindingAll binds to all IP addresses of the interface
	InterfaceBindingAll InterfaceBindingMode = "all"
)

// selectIPByMode selects IP addresses from the list based on the binding mode.
// Returns a slice of IP addresses: one for auto/firstipv4/firstipv6 modes, all for ipv4/ipv6/all modes.
func selectIPByMode(ipAddresses []string, mode InterfaceBindingMode) ([]string, error) {
	var ipv4Addresses []string
	var ipv6Addresses []string

	// Separate IPv4 and IPv6 addresses
	for _, ip := range ipAddresses {
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			if parsedIP.To4() != nil {
				ipv4Addresses = append(ipv4Addresses, ip)
			} else {
				ipv6Addresses = append(ipv6Addresses, ip)
			}
		}
	}

	// Select based on mode
	switch mode {
	case InterfaceBindingAuto:
		// Auto mode prefers first IPv4, fallback to first IPv6
		if len(ipv4Addresses) > 0 {
			return []string{ipv4Addresses[0]}, nil
		}
		if len(ipv6Addresses) > 0 {
			return []string{ipv6Addresses[0]}, nil
		}
	case InterfaceBindingFirstIPv4:
		// Return only the first IPv4 address
		if len(ipv4Addresses) > 0 {
			return []string{ipv4Addresses[0]}, nil
		}
		return nil, fmt.Errorf("no IPv4 addresses available for interface binding")
	case InterfaceBindingFirstIPv6:
		// Return only the first IPv6 address
		if len(ipv6Addresses) > 0 {
			return []string{ipv6Addresses[0]}, nil
		}
		return nil, fmt.Errorf("no IPv6 addresses available for interface binding")
	case InterfaceBindingIPv4:
		// Return all IPv4 addresses
		if len(ipv4Addresses) == 0 {
			return nil, fmt.Errorf("no IPv4 addresses available for interface binding")
		}
		return ipv4Addresses, nil
	case InterfaceBindingIPv6:
		// Return all IPv6 addresses
		if len(ipv6Addresses) == 0 {
			return nil, fmt.Errorf("no IPv6 addresses available for interface binding")
		}
		return ipv6Addresses, nil
	case InterfaceBindingAll:
		// All mode returns all IP addresses (IPv4 first, then IPv6)
		allIPs := append(ipv4Addresses, ipv6Addresses...)
		if len(allIPs) == 0 {
			return nil, fmt.Errorf("no addresses available for interface binding")
		}
		return allIPs, nil
	default:
		return nil, fmt.Errorf("unknown interface binding mode: %s", mode)
	}

	return nil, fmt.Errorf("no addresses available for interface binding")
}

// ResolveInterfaceNameWithMode resolves a network interface name to its IP addresses
// based on the specified binding mode.
// EXPERIMENTAL: Subject to change.
func ResolveInterfaceNameWithMode(ifaceName string, mode InterfaceBindingMode) ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %v", err)
	}

	var targetInterface *net.Interface
	for _, iface := range interfaces {
		if iface.Name == ifaceName {
			targetInterface = &iface
			break
		}
	}

	if targetInterface == nil {
		return nil, fmt.Errorf("interface %s not found", ifaceName)
	}

	// Check if interface is up
	if targetInterface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %s is down", ifaceName)
	}

	addrs, err := targetInterface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %s: %v", ifaceName, err)
	}

	// Collect all available IP addresses
	var allIPAddresses []string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			allIPAddresses = append(allIPAddresses, ipNet.IP.String())
		}
	}

	// Use selectIPByMode to choose the appropriate IP(s)
	selectedIPs, err := selectIPByMode(allIPAddresses, mode)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %v", ifaceName, err)
	}

	return selectedIPs, nil
}

// getMaxInterfaceNameLength returns the maximum allowed interface name length
// based on the operating system platform
func getMaxInterfaceNameLength() int {
	switch runtime.GOOS {
	case "windows":
		return maxInterfaceNameWindows
	default:
		// Unix-like systems
		return maxInterfaceNameUnix
	}
}

// isValidInterfaceChar checks if a character is valid for interface names across all platforms
func isValidInterfaceChar(r rune) bool {
	// Allow alphanumeric characters, hyphens, underscores, and spaces (for Windows)
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '_' ||
		(runtime.GOOS == "windows" && (r == ' ' || r == '(' || r == ')'))
}

// resolveInterfacePlaceholder resolves Caddy placeholders in interface names.
// Returns the resolved interface name and whether resolution was successful.
// Any placeholder available in the global replacer context can be used.
func resolveInterfacePlaceholder(s string) (string, bool) {
	// If no placeholders, return as-is
	if !strings.Contains(s, "{") {
		return s, true
	}

	repl := NewReplacer()
	resolved := repl.ReplaceKnown(s, "")

	// If no replacements were made or result is empty, reject it
	if resolved == s || resolved == "" {
		return "", false
	}

	return resolved, true
}

// isInterfaceName checks if a given string looks like a network interface name
func isInterfaceName(s string) bool {
	resolved, ok := resolveInterfacePlaceholder(s)
	if !ok {
		return false
	}

	s = resolved
	if s == "" {
		return false
	}

	// Don't accept already encoded interface names (containing delimiter)
	if strings.Contains(s, InterfaceDelimiter) {
		return false
	}

	// Special case: check for interface:port:mode pattern
	if strings.Contains(s, ":") {
		colonCount := strings.Count(s, ":")
		if colonCount == 2 {
			parts := strings.Split(s, ":")

			// Check if the last part is a valid binding mode
			lastPart := parts[2]
			if lastPart == string(InterfaceBindingAuto) ||
				lastPart == string(InterfaceBindingFirstIPv4) ||
				lastPart == string(InterfaceBindingFirstIPv6) ||
				lastPart == string(InterfaceBindingIPv4) ||
				lastPart == string(InterfaceBindingIPv6) ||
				lastPart == string(InterfaceBindingAll) {
				// Check if the interface part is valid
				potentialIface := parts[0]
				// Recursively check if the interface part is valid (without the port:mode)
				return isInterfaceName(potentialIface)
			}
		}
		// If not interface:port:mode pattern, reject strings with colons
		return false
	}

	// Check length is within platform limits
	if len(s) > getMaxInterfaceNameLength() {
		return false
	}

	// Check each character is valid
	for _, r := range s {
		if !isValidInterfaceChar(r) {
			return false
		}
	}

	// Check if it's a well-known hostname (not an interface)
	switch s {
	case "localhost", "local", "host":
		return false
	}

	// Check if it starts with a number (like IP addresses do)
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		return false
	}

	// Check if it looks like a file descriptor (e.g., "3", "10")
	if _, err := strconv.Atoi(s); err == nil {
		return false
	}

	return true
}

// interfaceWithMode represents parsed interface name and port with mode
type interfaceWithMode struct {
	interfaceName string
	portWithMode  string
}

// tryParseInterfaceWithModeInHost tries to parse strings like "eth0:8090:ipv4"
// that occur when SplitNetworkAddress treats them as IPv6-like addresses
func tryParseInterfaceWithModeInHost(host string) (interfaceWithMode, bool) {
	if !strings.Contains(host, ":") {
		return interfaceWithMode{}, false
	}

	parts := strings.Split(host, ":")
	if len(parts) != 3 {
		return interfaceWithMode{}, false
	}

	// Check if the last part is a valid binding mode
	if parts[2] != string(InterfaceBindingAuto) &&
		parts[2] != string(InterfaceBindingFirstIPv4) &&
		parts[2] != string(InterfaceBindingFirstIPv6) &&
		parts[2] != string(InterfaceBindingIPv4) &&
		parts[2] != string(InterfaceBindingIPv6) &&
		parts[2] != string(InterfaceBindingAll) {
		return interfaceWithMode{}, false
	}

	if !isInterfaceName(parts[0]) {
		return interfaceWithMode{}, false
	}

	return interfaceWithMode{
		interfaceName: parts[0],
		portWithMode:  parts[1] + ":" + parts[2],
	}, true
}

// parseInterfaceAddress handles parsing network addresses that might contain interface names.
// It supports extended syntax: interface:port:mode where mode can be auto, ipv4, or ipv6.
// It returns a NetworkAddress with the interface name preserved in the Host field for later resolution.
func parseInterfaceAddress(network, host, port string) (NetworkAddress, error) {
	// Special case: if host contains multiple colons, it might be interface:port:mode format
	if strings.Count(host, ":") >= 2 {
		if interfaceAddr, ok := tryParseInterfaceWithModeInHost(host); ok {
			// Recursively call parseInterfaceAddress with extracted interface and port:mode
			return parseInterfaceAddress(network, interfaceAddr.interfaceName, interfaceAddr.portWithMode)
		}
	}

	if !isInterfaceName(host) {
		return NetworkAddress{}, fmt.Errorf("host %s is not a valid interface name", host)
	}

	// Parse port and optional mode: "80" or "443:ipv4"
	var portStr string
	mode := InterfaceBindingAuto // default mode

	if port == "" {
		return NetworkAddress{}, fmt.Errorf("interface binding requires a port")
	}

	// Check for mode suffix
	if strings.Contains(port, ":") {
		parts := strings.SplitN(port, ":", 2)
		if len(parts) == 2 {
			portStr = parts[0]
			modeStr := parts[1]
			switch modeStr {
			case "auto":
				mode = InterfaceBindingAuto
			case "firstipv4":
				mode = InterfaceBindingFirstIPv4
			case "firstipv6":
				mode = InterfaceBindingFirstIPv6
			case "ipv4":
				mode = InterfaceBindingIPv4
			case "ipv6":
				mode = InterfaceBindingIPv6
			case "all":
				mode = InterfaceBindingAll
			default:
				return NetworkAddress{}, fmt.Errorf("unknown interface binding mode: %s (supported: auto, firstipv4, firstipv6, ipv4, ipv6, all)", modeStr)
			}
		}
	} else {
		portStr = port
	}

	var start, end uint64
	var err error

	before, after, found := strings.Cut(portStr, "-")
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

	// Encode the interface name and mode in the Host field
	// Format: "interface_name||mode" so we can decode it later in listenInterface
	hostWithMode := fmt.Sprintf("%s%s%s", host, InterfaceDelimiter, string(mode))

	return NetworkAddress{
		Network:   network,
		Host:      hostWithMode,
		StartPort: uint(start),
		EndPort:   uint(end),
	}, nil
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

// PacketConnWrapper is a type that wraps a packet conn
// so it can modify the input packet conn methods.
// Modules that implement this interface are found
// in the caddy.packetconns namespace. Usually, to
// wrap a packet conn, you will define your own struct
// type that embeds the input packet conn, then
// implement your own methods that you want to wrap,
// calling the underlying packet conn methods where
// appropriate.
type PacketConnWrapper interface {
	WrapPacketConn(net.PacketConn) net.PacketConn
}

// listenerPool stores and allows reuse of active listeners.
var listenerPool = NewUsagePool()

const maxPortSpan = 65535
