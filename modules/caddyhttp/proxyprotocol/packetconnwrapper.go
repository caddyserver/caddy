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

package proxyprotocol

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	goproxy "github.com/pires/go-proxyproto"

	"github.com/caddyserver/caddy/v2"
)

// PacketConnWrapper provides PROXY protocol support to Caddy's UDP
// listeners (HTTP/3) by implementing the caddy.PacketConnWrapper
// interface. Over UDP every datagram carries its own PROXY header, so
// the header is read and stripped from each one. The datagram is then
// reported as coming from the client address in the header, and replies
// to that address are sent back to the proxy that relayed it.
//
// Datagrams that a policy rejects, or whose header is malformed, are
// dropped.
type PacketConnWrapper struct {
	// Allow is an optional list of CIDR ranges of proxies
	// whose PROXY headers are used (policy USE).
	Allow []string `json:"allow,omitempty"`
	allow []netip.Prefix

	// Deny is an optional list of CIDR ranges to
	// deny PROXY headers from.
	Deny []string `json:"deny,omitempty"`
	deny []netip.Prefix

	// FallbackPolicy specifies the policy to use if the downstream
	// IP address is not in the Allow list nor is in the Deny list.
	// The values are the same as for the proxy_protocol listener
	// wrapper, applied to each datagram:
	//
	// - IGNORE: strip the PROXY header, keep the proxy's address
	//
	// - USE: use the address from the PROXY header, if there is one
	//
	// - REJECT: drop datagrams that carry a PROXY header
	//
	// - REQUIRE: drop datagrams without a PROXY header
	//
	// - SKIP: pass datagrams through without looking for a header
	//
	// Default: IGNORE
	FallbackPolicy Policy `json:"fallback_policy,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (PacketConnWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.packetconns.proxy_protocol",
		New: func() caddy.Module { return new(PacketConnWrapper) },
	}
}

// Provision sets up the packet conn wrapper.
func (pp *PacketConnWrapper) Provision(ctx caddy.Context) error {
	for _, cidr := range pp.Allow {
		ipnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			return err
		}
		pp.allow = append(pp.allow, ipnet)
	}
	for _, cidr := range pp.Deny {
		ipnet, err := netip.ParsePrefix(cidr)
		if err != nil {
			return err
		}
		pp.deny = append(pp.deny, ipnet)
	}
	return nil
}

// WrapPacketConn adds PROXY protocol support to the packet conn.
func (pp *PacketConnWrapper) WrapPacketConn(pc net.PacketConn) net.PacketConn {
	return &packetConn{
		PacketConn: pc,
		wrapper:    pp,
		peers:      make(map[netip.AddrPort]proxiedPeer),
	}
}

const (
	// proxiedPeerTTL is how long a client address keeps routing replies
	// to the proxy it was last seen through. Each datagram refreshes it.
	proxiedPeerTTL = 5 * time.Minute

	// maxProxiedPeers bounds the client addresses remembered at once, so
	// datagrams with forged source addresses cannot grow the map forever.
	maxProxiedPeers = 1 << 16
)

type proxiedPeer struct {
	proxy    net.Addr
	lastSeen time.Time
}

type packetConn struct {
	net.PacketConn
	wrapper *PacketConnWrapper

	mu        sync.Mutex
	peers     map[netip.AddrPort]proxiedPeer
	lastPrune time.Time
}

// ReadFrom reads the next datagram that passes the policy, with its
// PROXY header removed.
func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		n, src, ok := c.process(p[:n], addr)
		if ok {
			return n, src, nil
		}
	}
}

// process strips the PROXY header from the datagram in p and returns the
// payload length and the address to report, or ok=false to drop it.
func (c *packetConn) process(p []byte, upstream net.Addr) (n int, src net.Addr, ok bool) {
	// an unbound unixgram sender has no address to apply a policy to
	if upstream == nil {
		return len(p), upstream, true
	}
	policy, err := upstreamPolicy(upstream, c.wrapper.allow, c.wrapper.deny, c.wrapper.FallbackPolicy)
	if err != nil {
		return 0, nil, false
	}
	if policy == goproxy.SKIP {
		return len(p), upstream, true
	}

	header, payload, err := goproxy.ParseUDPDatagram(p)
	if errors.Is(err, goproxy.ErrNoProxyProtocol) {
		if policy == goproxy.REQUIRE {
			return 0, nil, false
		}
		return len(p), upstream, true
	}
	if err != nil || policy == goproxy.REJECT {
		return 0, nil, false
	}

	n = copy(p, payload)
	if policy == goproxy.IGNORE || header.Command.IsLocal() {
		return n, upstream, true
	}
	var client *net.UDPAddr
	switch addr := header.SourceAddr.(type) {
	case *net.UDPAddr:
		client = addr
	case *net.TCPAddr:
		client = &net.UDPAddr{IP: addr.IP, Port: addr.Port, Zone: addr.Zone}
	default:
		return n, upstream, true
	}
	c.remember(client, upstream)
	return n, client, true
}

func peerKey(addr *net.UDPAddr) netip.AddrPort {
	ap := addr.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func (c *packetConn) remember(client *net.UDPAddr, proxy net.Addr) {
	key := peerKey(client)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	_, known := c.peers[key]
	if !known && len(c.peers) >= maxProxiedPeers || now.Sub(c.lastPrune) >= proxiedPeerTTL {
		for k, peer := range c.peers {
			if now.Sub(peer.lastSeen) > proxiedPeerTTL {
				delete(c.peers, k)
			}
		}
		c.lastPrune = now
	}
	if !known && len(c.peers) >= maxProxiedPeers {
		return
	}
	c.peers[key] = proxiedPeer{proxy: proxy, lastSeen: now}
}

// WriteTo sends replies for a proxied client to the proxy it came through.
func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		c.mu.Lock()
		peer, ok := c.peers[peerKey(udpAddr)]
		c.mu.Unlock()
		if ok {
			addr = peer.proxy
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}

// SetReadBuffer and SetWriteBuffer let quic-go size the socket buffers
// of the underlying socket, as it does when no wrapper is configured.
func (c *packetConn) SetReadBuffer(bytes int) error {
	if conn, ok := underlying[interface{ SetReadBuffer(int) error }](c.PacketConn); ok {
		return conn.SetReadBuffer(bytes)
	}
	return errors.ErrUnsupported
}

func (c *packetConn) SetWriteBuffer(bytes int) error {
	if conn, ok := underlying[interface{ SetWriteBuffer(int) error }](c.PacketConn); ok {
		return conn.SetWriteBuffer(bytes)
	}
	return errors.ErrUnsupported
}

// underlying returns the first conn in the Unwrap chain that implements T.
func underlying[T any](pc net.PacketConn) (T, bool) {
	for {
		if conn, ok := pc.(T); ok {
			return conn, true
		}
		unwrapper, ok := pc.(interface{ Unwrap() net.PacketConn })
		if !ok {
			var zero T
			return zero, false
		}
		pc = unwrapper.Unwrap()
	}
}

// Interface guards
var (
	_ caddy.Provisioner       = (*PacketConnWrapper)(nil)
	_ caddy.Module            = (*PacketConnWrapper)(nil)
	_ caddy.PacketConnWrapper = (*PacketConnWrapper)(nil)
)
