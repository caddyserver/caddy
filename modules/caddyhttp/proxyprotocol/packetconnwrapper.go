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

	peerTables []*peerTable // guarded by peerTablesMu
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
	peerTablesMu.Lock()
	defer peerTablesMu.Unlock()
	peers := acquirePeerTable(socket(pc))
	pp.peerTables = append(pp.peerTables, peers)
	return &packetConn{
		PacketConn: pc,
		wrapper:    pp,
		peers:      peers,
	}
}

// Cleanup releases the client addresses remembered for this config.
func (pp *PacketConnWrapper) Cleanup() error {
	peerTablesMu.Lock()
	defer peerTablesMu.Unlock()
	for _, peers := range pp.peerTables {
		peers.release()
	}
	pp.peerTables = nil
	return nil
}

const (
	// proxiedPeerTTL is how long a client address keeps routing replies
	// to the proxy it was last seen through. Each datagram refreshes it.
	proxiedPeerTTL = 5 * time.Minute

	// maxProxiedPeers bounds the client addresses remembered at once, so
	// datagrams with forged source addresses cannot grow the map forever.
	maxProxiedPeers = 1 << 16

	// maxDatagramSize fits any UDP datagram, so a full-size QUIC packet
	// and its PROXY header are read whole before the header is stripped.
	maxDatagramSize = 1<<16 - 1
)

var datagramPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxDatagramSize)
		return &b
	},
}

type proxiedPeer struct {
	proxy    net.Addr
	lastSeen time.Time
}

// peerTable remembers which proxy each client address came through. The
// wrappers of every config loaded on the same socket share it, so after
// a reload replies to clients that are already connected still go back
// through their proxy.
type peerTable struct {
	socket net.PacketConn
	refs   int

	mu        sync.Mutex
	peers     map[netip.AddrPort]proxiedPeer
	lastPrune time.Time
}

// peerTables holds the table of each socket, and peerTablesMu guards it
// along with the refs of every table.
var (
	peerTables   = make(map[net.PacketConn]*peerTable)
	peerTablesMu sync.Mutex
)

func acquirePeerTable(socket net.PacketConn) *peerTable {
	t, ok := peerTables[socket]
	if !ok {
		t = &peerTable{socket: socket, peers: make(map[netip.AddrPort]proxiedPeer)}
		peerTables[socket] = t
	}
	t.refs++
	return t
}

func (t *peerTable) release() {
	t.refs--
	if t.refs == 0 {
		delete(peerTables, t.socket)
	}
}

type packetConn struct {
	net.PacketConn
	wrapper *PacketConnWrapper
	peers   *peerTable
}

// ReadFrom reads the next datagram that passes the policy, with its
// PROXY header removed.
func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := datagramPool.Get().(*[]byte)
	defer datagramPool.Put(buf)
	for {
		n, addr, err := c.PacketConn.ReadFrom(*buf)
		if err != nil {
			return 0, addr, err
		}
		payload, src, ok := c.process((*buf)[:n], addr)
		if ok {
			return copy(p, payload), src, nil
		}
	}
}

// process strips the PROXY header from the datagram and returns the
// payload and the address to report, or ok=false to drop it.
func (c *packetConn) process(datagram []byte, upstream net.Addr) (payload []byte, src net.Addr, ok bool) {
	// an unbound unixgram sender has no address to apply a policy to
	if upstream == nil {
		return datagram, upstream, true
	}
	policy, err := upstreamPolicy(upstream, c.wrapper.allow, c.wrapper.deny, c.wrapper.FallbackPolicy)
	if err != nil {
		return nil, nil, false
	}
	if policy == goproxy.SKIP {
		return datagram, upstream, true
	}

	header, payload, err := goproxy.ParseUDPDatagram(datagram)
	if errors.Is(err, goproxy.ErrNoProxyProtocol) {
		if policy == goproxy.REQUIRE {
			return nil, nil, false
		}
		return datagram, upstream, true
	}
	if err != nil || policy == goproxy.REJECT {
		return nil, nil, false
	}
	if header.Command.IsLocal() {
		return payload, upstream, true
	}
	// a PROXY command on a UDP listener must describe a UDP client
	client, _, ok := header.UDPAddrs()
	if !ok {
		return nil, nil, false
	}
	if policy == goproxy.IGNORE {
		return payload, upstream, true
	}
	if !c.peers.remember(client, upstream) {
		return nil, nil, false
	}
	return payload, client, true
}

func peerKey(addr *net.UDPAddr) netip.AddrPort {
	ap := addr.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// remember stores the proxy that replies to client go through. It
// reports false if the table is full and client is not in it.
func (t *peerTable) remember(client *net.UDPAddr, proxy net.Addr) bool {
	key := peerKey(client)
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	_, known := t.peers[key]
	// TODO: this doesn't cap concurrent active clients, since peers are only
	// dropped after proxiedPeerTTL, and a full map checks every peer. An LRU
	// would enforce it, but could drop replies on a busy server; see how this
	// behaves under real load first.
	if !known && len(t.peers) >= maxProxiedPeers || now.Sub(t.lastPrune) >= proxiedPeerTTL {
		for k, peer := range t.peers {
			if now.Sub(peer.lastSeen) > proxiedPeerTTL {
				delete(t.peers, k)
			}
		}
		t.lastPrune = now
	}
	if !known && len(t.peers) >= maxProxiedPeers {
		return false
	}
	t.peers[key] = proxiedPeer{proxy: proxy, lastSeen: now}
	return true
}

func (t *peerTable) proxy(client *net.UDPAddr) (net.Addr, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	peer, ok := t.peers[peerKey(client)]
	return peer.proxy, ok
}

// WriteTo sends replies for a proxied client to the proxy it came through.
func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if proxy, ok := c.peers.proxy(udpAddr); ok {
			addr = proxy
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}

// socket returns the underlying socket of pc.
func socket(pc net.PacketConn) net.PacketConn {
	for {
		unwrapper, ok := pc.(interface{ Unwrap() net.PacketConn })
		if !ok {
			return pc
		}
		pc = unwrapper.Unwrap()
	}
}

// Interface guards
var (
	_ caddy.CleanerUpper      = (*PacketConnWrapper)(nil)
	_ caddy.Provisioner       = (*PacketConnWrapper)(nil)
	_ caddy.Module            = (*PacketConnWrapper)(nil)
	_ caddy.PacketConnWrapper = (*PacketConnWrapper)(nil)
)
