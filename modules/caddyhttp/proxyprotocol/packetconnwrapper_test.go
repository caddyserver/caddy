package proxyprotocol

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"

	goproxy "github.com/pires/go-proxyproto"
)

type datagram struct {
	data []byte
	addr net.Addr
}

// fakePacketConn hands out queued datagrams and records writes.
type fakePacketConn struct {
	net.PacketConn
	in  []datagram
	out []datagram
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(f.in) == 0 {
		return 0, nil, io.EOF
	}
	d := f.in[0]
	f.in = f.in[1:]
	return copy(p, d.data), d.addr, nil
}

func (f *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.out = append(f.out, datagram{append([]byte(nil), p...), addr})
	return len(p), nil
}

var (
	testProxy  = &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 40000}
	testClient = &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4433}
	testServer = &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 443}
)

func proxied(t *testing.T, command goproxy.ProtocolVersionAndCommand, payload string) []byte {
	t.Helper()
	return formatDatagram(t, &goproxy.Header{
		Version:           2,
		Command:           command,
		TransportProtocol: goproxy.UDPv4,
		SourceAddr:        testClient,
		DestinationAddr:   testServer,
	}, []byte(payload))
}

func formatDatagram(t *testing.T, header *goproxy.Header, payload []byte) []byte {
	t.Helper()
	b, err := header.FormatUDPDatagram(payload)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func provisionForTest(t *testing.T, w *PacketConnWrapper) {
	t.Helper()
	for _, cidr := range w.Allow {
		w.allow = append(w.allow, netip.MustParsePrefix(cidr))
	}
	for _, cidr := range w.Deny {
		w.deny = append(w.deny, netip.MustParsePrefix(cidr))
	}
	t.Cleanup(func() { _ = w.Cleanup() })
}

func wrapForTest(t *testing.T, w *PacketConnWrapper, in ...datagram) (net.PacketConn, *fakePacketConn) {
	t.Helper()
	provisionForTest(t, w)
	fake := &fakePacketConn{in: in}
	return w.WrapPacketConn(fake), fake
}

// readAll returns every datagram the wrapper lets through.
func readAll(t *testing.T, pc net.PacketConn) []datagram {
	t.Helper()
	var got []datagram
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err == io.EOF {
			return got
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, datagram{append([]byte(nil), buf[:n]...), addr})
	}
}

func TestPacketConnWrapperPolicies(t *testing.T) {
	plain := datagram{[]byte("plain"), testProxy}
	withHeader := datagram{proxied(t, goproxy.PROXY, "quic"), testProxy}
	local := datagram{proxied(t, goproxy.LOCAL, "health"), testProxy}
	malformed := datagram{append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x99), testProxy}
	tcpHeader := datagram{formatDatagram(t, &goproxy.Header{
		Version:           2,
		Command:           goproxy.PROXY,
		TransportProtocol: goproxy.TCPv4,
		SourceAddr:        &net.TCPAddr{IP: testClient.IP, Port: testClient.Port},
		DestinationAddr:   &net.TCPAddr{IP: testServer.IP, Port: testServer.Port},
	}, []byte("tcp")), testProxy}
	v1Header := datagram{append([]byte("PROXY TCP4 203.0.113.7 10.0.0.2 4433 443\r\n"), "v1"...), testProxy}

	tests := []struct {
		name    string
		wrapper PacketConnWrapper
		in      []datagram
		want    []string // "payload from address"
	}{
		{
			name:    "allowed upstream: client address from the header",
			wrapper: PacketConnWrapper{Allow: []string{"10.0.0.0/8"}},
			in:      []datagram{withHeader, plain},
			want:    []string{"quic from 203.0.113.7:4433", "plain from 10.0.0.1:40000"},
		},
		{
			name:    "default IGNORE: header stripped, proxy address kept",
			wrapper: PacketConnWrapper{},
			in:      []datagram{withHeader},
			want:    []string{"quic from 10.0.0.1:40000"},
		},
		{
			name:    "REQUIRE drops datagrams without a header",
			wrapper: PacketConnWrapper{FallbackPolicy: PolicyREQUIRE},
			in:      []datagram{plain, withHeader},
			want:    []string{"quic from 203.0.113.7:4433"},
		},
		{
			name:    "denied upstream: datagrams with a header are dropped",
			wrapper: PacketConnWrapper{Deny: []string{"10.0.0.0/8"}},
			in:      []datagram{withHeader, plain},
			want:    []string{"plain from 10.0.0.1:40000"},
		},
		{
			name:    "SKIP passes datagrams through untouched",
			wrapper: PacketConnWrapper{FallbackPolicy: PolicySKIP},
			in:      []datagram{plain},
			want:    []string{"plain from 10.0.0.1:40000"},
		},
		{
			name:    "malformed header is dropped",
			wrapper: PacketConnWrapper{Allow: []string{"10.0.0.0/8"}},
			in:      []datagram{malformed, plain},
			want:    []string{"plain from 10.0.0.1:40000"},
		},
		{
			name:    "LOCAL command keeps the proxy address",
			wrapper: PacketConnWrapper{Allow: []string{"10.0.0.0/8"}},
			in:      []datagram{local},
			want:    []string{"health from 10.0.0.1:40000"},
		},
		{
			name:    "header for a TCP client is dropped",
			wrapper: PacketConnWrapper{Allow: []string{"10.0.0.0/8"}},
			in:      []datagram{tcpHeader, v1Header, plain},
			want:    []string{"plain from 10.0.0.1:40000"},
		},
		{
			name:    "header for a TCP client is dropped under IGNORE",
			wrapper: PacketConnWrapper{},
			in:      []datagram{tcpHeader, v1Header, plain},
			want:    []string{"plain from 10.0.0.1:40000"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pc, _ := wrapForTest(t, &tt.wrapper, tt.in...)
			var got []string
			for _, d := range readAll(t, pc) {
				got = append(got, string(d.data)+" from "+d.addr.String())
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %q, want %q", got, tt.want)
				}
			}
		})
	}
}

func TestPacketConnWrapperRepliesGoToTheProxy(t *testing.T) {
	pc, fake := wrapForTest(t, &PacketConnWrapper{Allow: []string{"10.0.0.0/8"}},
		datagram{proxied(t, goproxy.PROXY, "quic"), testProxy})
	got := readAll(t, pc)
	if len(got) != 1 {
		t.Fatalf("got %d datagrams, want 1", len(got))
	}
	if _, err := pc.WriteTo([]byte("reply"), got[0].addr); err != nil {
		t.Fatal(err)
	}
	other := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53}
	if _, err := pc.WriteTo([]byte("direct"), other); err != nil {
		t.Fatal(err)
	}
	if len(fake.out) != 2 || fake.out[0].addr.String() != testProxy.String() || fake.out[1].addr.String() != other.String() {
		t.Fatalf("writes went to %v, want %v then %v", fake.out, testProxy, other)
	}
}

func TestPacketConnWrapperPassesDatagramsWithoutSender(t *testing.T) {
	// an unbound unixgram sender has a nil address
	pc, _ := wrapForTest(t, &PacketConnWrapper{FallbackPolicy: PolicyREQUIRE}, datagram{[]byte("plain"), nil})
	got := readAll(t, pc)
	if len(got) != 1 || string(got[0].data) != "plain" || got[0].addr != nil {
		t.Fatalf("got %v, want the datagram unchanged", got)
	}
}

func TestPacketConnWrapperReadsFullSizeDatagrams(t *testing.T) {
	// quic-go reads into a buffer of its maximum packet size
	const quicBufferSize = 1452
	payload := bytes.Repeat([]byte{0xAB}, quicBufferSize)
	v6Client := &net.UDPAddr{IP: net.ParseIP("2001:db8::7"), Port: 4433}
	v6Server := &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}
	for name, header := range map[string]*goproxy.Header{
		"IPv4": {Version: 2, Command: goproxy.PROXY, TransportProtocol: goproxy.UDPv4, SourceAddr: testClient, DestinationAddr: testServer},
		"IPv6": {Version: 2, Command: goproxy.PROXY, TransportProtocol: goproxy.UDPv6, SourceAddr: v6Client, DestinationAddr: v6Server},
	} {
		t.Run(name, func(t *testing.T) {
			pc, _ := wrapForTest(t, &PacketConnWrapper{Allow: []string{"10.0.0.0/8"}},
				datagram{formatDatagram(t, header, payload), testProxy})
			buf := make([]byte, quicBufferSize)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], payload) {
				t.Fatalf("read %d bytes, want the %d-byte payload intact", n, len(payload))
			}
			if addr.String() != header.SourceAddr.String() {
				t.Fatalf("reported %v, want %v", addr, header.SourceAddr)
			}
		})
	}
}

func TestPacketConnWrapperBoundsRememberedClients(t *testing.T) {
	pc, fake := wrapForTest(t, &PacketConnWrapper{Allow: []string{"10.0.0.0/8"}})
	conn := pc.(*packetConn)
	for i := 0; i < maxProxiedPeers; i++ {
		if !conn.peers.remember(&net.UDPAddr{IP: net.IPv4(198, 18, byte(i>>8), byte(i)), Port: 1}, testProxy) {
			t.Fatalf("client %d was not remembered", i)
		}
	}

	// a new client cannot be remembered, so its datagram is dropped
	// instead of being reported with a reply path that goes nowhere
	fake.in = []datagram{{proxied(t, goproxy.PROXY, "quic"), testProxy}}
	if got := readAll(t, pc); len(got) != 0 {
		t.Fatalf("got %v, want the datagram dropped", got)
	}
	if len(conn.peers.peers) != maxProxiedPeers {
		t.Fatalf("remembered %d clients, want at most %d", len(conn.peers.peers), maxProxiedPeers)
	}
	if _, err := pc.WriteTo([]byte("reply"), testClient); err != nil {
		t.Fatal(err)
	}
	if fake.out[0].addr.String() != testClient.String() {
		t.Fatalf("reply to an unremembered client went to %v", fake.out[0].addr)
	}
}

func TestPacketConnWrapperReloadKeepsRememberedClients(t *testing.T) {
	old := &PacketConnWrapper{Allow: []string{"10.0.0.0/8"}}
	oldConn, fake := wrapForTest(t, old, datagram{proxied(t, goproxy.PROXY, "quic"), testProxy})
	if got := readAll(t, oldConn); len(got) != 1 {
		t.Fatalf("got %d datagrams, want 1", len(got))
	}

	// the reloaded config wraps the same socket and denies the proxy
	reloaded := &PacketConnWrapper{Deny: []string{"10.0.0.0/8"}}
	provisionForTest(t, reloaded)
	newConn := reloaded.WrapPacketConn(fake)
	_ = old.Cleanup()

	if _, err := newConn.WriteTo([]byte("reply"), testClient); err != nil {
		t.Fatal(err)
	}
	if fake.out[0].addr.String() != testProxy.String() {
		t.Fatalf("reply after reload went to %v, want %v", fake.out[0].addr, testProxy)
	}
	fake.in = []datagram{{proxied(t, goproxy.PROXY, "quic"), testProxy}}
	if got := readAll(t, newConn); len(got) != 0 {
		t.Fatalf("got %v, want the reloaded deny list to drop it", got)
	}

	_ = reloaded.Cleanup()
	peerTablesMu.Lock()
	defer peerTablesMu.Unlock()
	if _, ok := peerTables[net.PacketConn(fake)]; ok {
		t.Fatal("remembered clients were kept after every config was cleaned up")
	}
}
