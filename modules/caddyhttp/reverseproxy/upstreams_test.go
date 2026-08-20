package reverseproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestResolveIpVersion(t *testing.T) {
	falseBool := false
	trueBool := true
	tests := []struct {
		Versions          *IPVersions
		expectedIpVersion string
	}{
		{
			Versions:          &IPVersions{IPv4: &trueBool},
			expectedIpVersion: "ip4",
		},
		{
			Versions:          &IPVersions{IPv4: &falseBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &trueBool, IPv6: &falseBool},
			expectedIpVersion: "ip4",
		},
		{
			Versions:          &IPVersions{IPv6: &trueBool},
			expectedIpVersion: "ip6",
		},
		{
			Versions:          &IPVersions{IPv6: &falseBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv6: &trueBool, IPv4: &falseBool},
			expectedIpVersion: "ip6",
		},
		{
			Versions:          &IPVersions{},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &trueBool, IPv6: &trueBool},
			expectedIpVersion: "ip",
		},
		{
			Versions:          &IPVersions{IPv4: &falseBool, IPv6: &falseBool},
			expectedIpVersion: "ip",
		},
	}
	for _, test := range tests {
		ipVersion := resolveIpVersion(test.Versions)
		if ipVersion != test.expectedIpVersion {
			t.Errorf("resolveIpVersion(): Expected %s got %s", test.expectedIpVersion, ipVersion)
		}
	}
}

// fakeSRVResolver implements srvResolver so tests can control the timing and
// results of SRV lookups without a real DNS server.
type fakeSRVResolver struct {
	lookupSRV func(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

func (f *fakeSRVResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	return f.lookupSRV(ctx, service, proto, name)
}

// newTestRequest returns an HTTP request carrying the replacer that
// GetUpstreams relies on.
func newTestRequest() *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	return req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
}

// TestSRVUpstreamsSlowLookupDoesNotBlockOtherKeys is a regression test for the
// case where a slow SRV lookup for one key held the global cache lock across
// the DNS call, blocking lookups for every unrelated key. The slow lookup is
// held open on a channel while a second, independent key is looked up; the
// second lookup must complete quickly rather than waiting for the slow one.
func TestSRVUpstreamsSlowLookupDoesNotBlockOtherKeys(t *testing.T) {
	release := make(chan struct{})
	blockedEntered := make(chan struct{})

	resolver := &fakeSRVResolver{
		lookupSRV: func(_ context.Context, _, _, name string) (string, []*net.SRV, error) {
			switch name {
			case "slow.example.com":
				close(blockedEntered)
				<-release
				return "", []*net.SRV{{Target: "10.0.0.1", Port: 80}}, nil
			case "fast.example.com":
				return "", []*net.SRV{{Target: "10.0.0.2", Port: 80}}, nil
			default:
				return "", nil, fmt.Errorf("unexpected SRV lookup for %q", name)
			}
		},
	}

	slow := &SRVUpstreams{
		Name:     "slow.example.com",
		Refresh:  caddy.Duration(time.Minute),
		resolver: resolver,
		logger:   zap.NewNop(),
	}
	fast := &SRVUpstreams{
		Name:     "fast.example.com",
		Refresh:  caddy.Duration(time.Minute),
		resolver: resolver,
		logger:   zap.NewNop(),
	}

	// start from a clean cache so both keys are guaranteed to be a miss
	slow.ResetCache(nil)
	fast.ResetCache(nil)

	slowErr := make(chan error, 1)
	go func() {
		_, err := slow.GetUpstreams(newTestRequest())
		slowErr <- err
	}()

	// wait until the slow lookup is actually in flight before racing the fast one
	<-blockedEntered

	fastStart := time.Now()
	fastRes := make(chan struct {
		ups []*Upstream
		err error
	}, 1)
	go func() {
		ups, err := fast.GetUpstreams(newTestRequest())
		fastRes <- struct {
			ups []*Upstream
			err error
		}{ups, err}
	}()

	select {
	case res := <-fastRes:
		if res.err != nil {
			t.Fatalf("fast lookup errored: %v", res.err)
		}
		if len(res.ups) != 1 || res.ups[0].Dial != "10.0.0.2:80" {
			t.Fatalf("unexpected fast lookup result: %+v", res.ups)
		}
		if elapsed := time.Since(fastStart); elapsed > 500*time.Millisecond {
			t.Fatalf("fast lookup took %v; it should not be blocked by the slow lookup", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("fast lookup was blocked behind the slow lookup")
	}

	// release the slow lookup and make sure it completes successfully
	close(release)
	if err := <-slowErr; err != nil {
		t.Fatalf("slow lookup errored: %v", err)
	}
}

// TestSRVUpstreamsResetCacheDuringLookup verifies that a lookup that is still
// in flight when ResetCache runs does not repopulate the cache afterwards
// (which would silently undo the reset).
func TestSRVUpstreamsResetCacheDuringLookup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reset func(su *SRVUpstreams, req *http.Request) error
	}{
		{
			name: "full reset",
			reset: func(su *SRVUpstreams, _ *http.Request) error {
				return su.ResetCache(nil)
			},
		},
		{
			name: "targeted reset",
			reset: func(su *SRVUpstreams, req *http.Request) error {
				return su.ResetCache(req)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			entered := make(chan struct{})
			resolver := &fakeSRVResolver{
				lookupSRV: func(_ context.Context, _, _, _ string) (string, []*net.SRV, error) {
					close(entered)
					<-release
					return "", []*net.SRV{{Target: "10.0.0.1", Port: 80}}, nil
				},
			}
			su := &SRVUpstreams{
				Name:     "reset.example.com",
				Refresh:  caddy.Duration(time.Minute),
				resolver: resolver,
				logger:   zap.NewNop(),
			}
			su.ResetCache(nil)

			req := newTestRequest()
			done := make(chan error, 1)
			go func() {
				_, err := su.GetUpstreams(req)
				done <- err
			}()

			<-entered
			if err := tc.reset(su, req); err != nil {
				t.Fatalf("ResetCache: %v", err)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatalf("GetUpstreams: %v", err)
			}

			srvsMu.RLock()
			_, ok := srvs["reset.example.com"]
			srvsMu.RUnlock()
			if ok {
				t.Fatal("stale in-flight lookup repopulated the cache after reset")
			}
		})
	}
}

// TestAUpstreamsSlowLookupDoesNotBlockOtherKeys is the A/AAAA equivalent of
// TestSRVUpstreamsSlowLookupDoesNotBlockOtherKeys.
func TestAUpstreamsSlowLookupDoesNotBlockOtherKeys(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})

	ipv4, ipv6 := true, false
	versions := &IPVersions{IPv4: &ipv4, IPv6: &ipv6}

	slow := &AUpstreams{
		Name:     "slow.example.com",
		Port:     "80",
		Refresh:  caddy.Duration(time.Minute),
		Versions: versions,
		resolver: fakeAResolver(net.IPv4(10, 0, 0, 1), entered, release),
		logger:   zap.NewNop(),
	}
	fast := &AUpstreams{
		Name:     "fast.example.com",
		Port:     "80",
		Refresh:  caddy.Duration(time.Minute),
		Versions: versions,
		resolver: fakeAResolver(net.IPv4(10, 0, 0, 2), nil, nil),
		logger:   zap.NewNop(),
	}

	slow.ResetCache(nil)
	fast.ResetCache(nil)

	slowErr := make(chan error, 1)
	go func() {
		_, err := slow.GetUpstreams(newTestRequest())
		slowErr <- err
	}()

	<-entered

	fastStart := time.Now()
	fastRes := make(chan struct {
		ups []*Upstream
		err error
	}, 1)
	go func() {
		ups, err := fast.GetUpstreams(newTestRequest())
		fastRes <- struct {
			ups []*Upstream
			err error
		}{ups, err}
	}()

	select {
	case res := <-fastRes:
		if res.err != nil {
			t.Fatalf("fast lookup errored: %v", res.err)
		}
		if len(res.ups) != 1 || res.ups[0].Dial != "10.0.0.2:80" {
			t.Fatalf("unexpected fast lookup result: %+v", res.ups)
		}
		if elapsed := time.Since(fastStart); elapsed > 500*time.Millisecond {
			t.Fatalf("fast lookup took %v; it should not be blocked by the slow lookup", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("fast lookup was blocked behind the slow lookup")
	}

	close(release)
	if err := <-slowErr; err != nil {
		t.Fatalf("slow lookup errored: %v", err)
	}
}

// TestAUpstreamsResetCacheDuringLookup verifies the A/AAAA equivalent of the
// SRV reset-during-lookup behavior.
func TestAUpstreamsResetCacheDuringLookup(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reset func(au *AUpstreams, req *http.Request) error
	}{
		{
			name: "full reset",
			reset: func(au *AUpstreams, _ *http.Request) error {
				return au.ResetCache(nil)
			},
		},
		{
			name: "targeted reset",
			reset: func(au *AUpstreams, req *http.Request) error {
				return au.ResetCache(req)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			entered := make(chan struct{})

			ipv4, ipv6 := true, false
			au := &AUpstreams{
				Name:     "reset.example.com",
				Port:     "80",
				Refresh:  caddy.Duration(time.Minute),
				Versions: &IPVersions{IPv4: &ipv4, IPv6: &ipv6},
				resolver: fakeAResolver(net.IPv4(10, 0, 0, 1), entered, release),
				logger:   zap.NewNop(),
			}
			au.ResetCache(nil)

			req := newTestRequest()
			done := make(chan error, 1)
			go func() {
				_, err := au.GetUpstreams(req)
				done <- err
			}()

			<-entered
			if err := tc.reset(au, req); err != nil {
				t.Fatalf("ResetCache: %v", err)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatalf("GetUpstreams: %v", err)
			}

			key := au.String() + resolveIpVersion(au.Versions)
			aAaaaMu.RLock()
			_, ok := aAaaa[key]
			aAaaaMu.RUnlock()
			if ok {
				t.Fatal("stale in-flight lookup repopulated the cache after reset")
			}
		})
	}
}

// fakeAResolver starts a single-flight DNS responder over a net.Pipe and
// returns a *net.Resolver that talks to it. Once the query arrives, entered
// (if non-nil) is closed and, if block is non-nil, the responder waits for
// block to close before answering with a single A record for ip.
func fakeAResolver(ip net.IP, entered, block chan struct{}) *net.Resolver {
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 512)
		n, err := server.Read(buf)
		if err != nil {
			return
		}
		if entered != nil {
			close(entered)
		}
		if block != nil {
			<-block
		}
		_, _ = server.Write(buildARecordResponse(buf[:n], ip))
	}()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return client, nil
		},
	}
}

// buildARecordResponse builds a valid DNS response to the given A-record
// query, answering with a single A record for ip. Since the fake resolver
// uses a stream (net.Pipe) connection, both the query and the response use
// TCP framing: a two-byte big-endian length prefix followed by the DNS
// message.
func buildARecordResponse(query []byte, ip net.IP) []byte {
	if len(query) < 14 { // 2-byte length prefix + 12-byte header
		return nil
	}
	dnsMsg := query[2:] // strip the length prefix

	// skip past the question name to find QTYPE/QCLASS
	off := 12
	for off < len(dnsMsg) {
		l := int(dnsMsg[off])
		off++
		if l == 0 {
			break
		}
		off += l
	}
	qEnd := off + 4 // qtype (2) + qclass (2)
	if qEnd > len(dnsMsg) {
		return nil
	}

	ip4 := ip.To4()
	msg := make([]byte, 0, qEnd+16)
	msg = append(msg, dnsMsg[0], dnsMsg[1])   // copy transaction ID
	msg = append(msg, 0x81, 0x80)             // QR=1, RD=1, RA=1
	msg = append(msg, 0x00, 0x01)             // QDCOUNT=1
	msg = append(msg, 0x00, 0x01)             // ANCOUNT=1
	msg = append(msg, 0x00, 0x00, 0x00, 0x00) // NSCOUNT=0, ARCOUNT=0
	msg = append(msg, dnsMsg[12:qEnd]...)     // echo question
	msg = append(msg, 0xC0, 0x0C)             // answer name: pointer to offset 12
	msg = append(msg, 0x00, 0x01)             // TYPE=A
	msg = append(msg, 0x00, 0x01)             // CLASS=IN
	msg = append(msg, 0x00, 0x00, 0x00, 0x3C) // TTL=60
	msg = append(msg, 0x00, 0x04)             // RDLENGTH=4
	msg = append(msg, ip4...)                 // RDATA

	resp := make([]byte, 0, len(msg)+2)
	resp = append(resp, byte(len(msg)>>8), byte(len(msg))) // length prefix
	resp = append(resp, msg...)
	return resp
}
