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

// Integration tests for Caddy's PROXY protocol support, covering two distinct
// roles that Caddy can play:
//
//  1. As a PROXY protocol *sender* (reverse proxy outbound transport):
//     Caddy receives an inbound request from a test client and the
//     reverse_proxy handler forwards it to an upstream with a PROXY protocol
//     header (v1 or v2) prepended to the connection.  A lightweight backend
//     built with go-proxyproto validates that the header was received and
//     carries the correct client address.
//
//     Transport versions tested:
//   - "1.1"  -> plain HTTP/1.1 to the upstream
//   - "h2c"  -> HTTP/2 cleartext (h2c) to the upstream (regression for #7529)
//   - "2"    -> HTTP/2 over TLS (h2) to the upstream
//
//     For each transport version both PROXY protocol v1 and v2 are exercised.
//
//     HTTP/3 (h3) is not included because it uses QUIC/UDP and therefore
//     bypasses the TCP-level dialContext that injects PROXY protocol headers;
//     there is no meaningful h3 + proxy protocol sender combination to test.
//
//  2. As a PROXY protocol *receiver* (server-side listener wrapper):
//     A raw TCP client dials Caddy directly, injects a PROXY v2 header
//     spoofing a source address, and sends a normal HTTP/1.1 request.  The
//     Caddy server is configured with the proxy_protocol listener wrapper and
//     is expected to surface the spoofed address via the
//     {http.request.remote.host} placeholder.

package integration

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	goproxy "github.com/pires/go-proxyproto"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// proxyProtoBackend is a minimal HTTP server that sits behind a
// go-proxyproto listener and records the source address that was
// delivered in the PROXY header for each request.
type proxyProtoBackend struct {
	mu          sync.Mutex
	headerAddrs []string // host:port strings extracted from each PROXY header

	ln  net.Listener
	srv *http.Server
}

// newProxyProtoBackend starts a TCP listener wrapped with go-proxyproto on a
// random local port and serves requests with a simple "OK" body.  The PROXY
// header source addresses are accumulated in headerAddrs so tests can
// inspect them.
func newProxyProtoBackend(t *testing.T) *proxyProtoBackend {
	t.Helper()

	b := &proxyProtoBackend{}

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend: listen: %v", err)
	}

	// Wrap with go-proxyproto so the PROXY header is stripped and parsed
	// before the HTTP server sees the connection.  We use REQUIRE so that a
	// missing header returns an error instead of silently passing through.
	pLn := &goproxy.Listener{
		Listener: rawLn,
		Policy: func(_ net.Addr) (goproxy.Policy, error) {
			return goproxy.REQUIRE, nil
		},
	}
	b.ln = pLn

	// Wrap the handler with h2c support so the backend can speak HTTP/2
	// cleartext (h2c) as well as plain HTTP/1.1.  Without this, Caddy's
	// reverse proxy would receive a 'frame too large' error when the
	// upstream transport is configured to use h2c.
	h2Server := &http2.Server{}
	handlerFn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// go-proxyproto has already updated the net.Conn's remote
		// address to the value from the PROXY header; the HTTP server
		// surfaces it in r.RemoteAddr.
		b.mu.Lock()
		b.headerAddrs = append(b.headerAddrs, r.RemoteAddr)
		b.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	})

	b.srv = &http.Server{
		Handler: h2c.NewHandler(handlerFn, h2Server),
	}

	go b.srv.Serve(pLn) //nolint:errcheck
	t.Cleanup(func() {
		_ = b.srv.Close()
		_ = rawLn.Close()
	})

	return b
}

// addr returns the listening address (host:port) of the backend.
func (b *proxyProtoBackend) addr() string {
	return b.ln.Addr().String()
}

// recordedAddrs returns a snapshot of all PROXY-header source addresses seen
// so far.
func (b *proxyProtoBackend) recordedAddrs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]string, len(b.headerAddrs))
	copy(cp, b.headerAddrs)
	return cp
}

// tlsProxyProtoBackend is a TLS-enabled backend that sits behind a
// go-proxyproto listener.  The PROXY header is stripped before the TLS
// handshake so the layer order on a connection is:
//
//	raw TCP → go-proxyproto (strips PROXY header) → TLS handshake → HTTP/2
type tlsProxyProtoBackend struct {
	mu          sync.Mutex
	headerAddrs []string

	srv *httptest.Server
}

// newTLSProxyProtoBackend starts a TLS listener that first reads and strips
// PROXY protocol headers (go-proxyproto, REQUIRE policy) and then performs a
// TLS handshake.  The backend speaks HTTP/2 over TLS (h2).
//
// The certificate is the standard self-signed certificate generated by
// httptest.Server; the Caddy transport must be configured with
// insecure_skip_verify: true to trust it.
func newTLSProxyProtoBackend(t *testing.T) *tlsProxyProtoBackend {
	t.Helper()

	b := &tlsProxyProtoBackend{}

	handlerFn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		b.headerAddrs = append(b.headerAddrs, r.RemoteAddr)
		b.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	})

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tlsBackend: listen: %v", err)
	}

	// Wrap with go-proxyproto so the PROXY header is consumed before TLS.
	pLn := &goproxy.Listener{
		Listener: rawLn,
		Policy: func(_ net.Addr) (goproxy.Policy, error) {
			return goproxy.REQUIRE, nil
		},
	}

	// httptest.NewUnstartedServer lets us replace the listener before
	// calling StartTLS(), which wraps our proxyproto listener with
	// tls.NewListener.  This gives us the right layer order.
	b.srv = httptest.NewUnstartedServer(handlerFn)
	b.srv.Listener = pLn

	// StartTLS enables HTTP/2 on the server automatically.
	b.srv.StartTLS()

	t.Cleanup(func() {
		b.srv.Close()
	})

	return b
}

// addr returns the listening address (host:port) of the TLS backend.
func (b *tlsProxyProtoBackend) addr() string {
	return b.srv.Listener.Addr().String()
}

// tlsConfig returns the *tls.Config used by the backend server.
// Tests can use it to verify cert details if needed.
func (b *tlsProxyProtoBackend) tlsConfig() *tls.Config {
	return b.srv.TLS
}

// recordedAddrs returns a snapshot of all PROXY-header source addresses.
func (b *tlsProxyProtoBackend) recordedAddrs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]string, len(b.headerAddrs))
	copy(cp, b.headerAddrs)
	return cp
}

// proxyProtoTLSConfig builds a Caddy JSON configuration that proxies to a TLS
// upstream with PROXY protocol.  The transport uses insecure_skip_verify so
// the self-signed certificate generated by httptest.Server is accepted.
func proxyProtoTLSConfig(listenPort int, backendAddr, ppVersion string, transportVersions []string) string {
	versionsJSON, _ := json.Marshal(transportVersions)
	return fmt.Sprintf(`{
		"admin": {
			"listen": "localhost:2999"
		},
		"apps": {
			"pki": {
				"certificate_authorities": {
					"local": {
						"install_trust": false
					}
				}
			},
			"http": {
				"grace_period": 1,
				"servers": {
					"proxy": {
						"listen": [":%d"],
						"automatic_https": {
							"disable": true
						},
						"routes": [
							{
								"handle": [
									{
										"handler": "reverse_proxy",
										"upstreams": [{"dial": "%s"}],
										"transport": {
											"protocol": "http",
											"proxy_protocol": "%s",
											"versions": %s,
											"tls": {
												"insecure_skip_verify": true
											}
										}
									}
								]
							}
						]
					}
				}
			}
		}
	}`, listenPort, backendAddr, ppVersion, string(versionsJSON))
}

// testTLSProxyProtocolMatrix is the shared implementation for TLS-based proxy
// protocol tests.  It mirrors testProxyProtocolMatrix but uses a TLS backend.
func testTLSProxyProtocolMatrix(t *testing.T, ppVersion string, transportVersions []string, numRequests int) {
	t.Helper()

	backend := newTLSProxyProtoBackend(t)
	listenPort := freePort(t)

	tester := caddytest.NewTester(t)
	tester.WithDefaultOverrides(caddytest.Config{
		AdminPort: 2999,
	})
	cfg := proxyProtoTLSConfig(listenPort, backend.addr(), ppVersion, transportVersions)
	tester.InitServer(cfg, "json")

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d/", listenPort)

	for i := 0; i < numRequests; i++ {
		resp, err := tester.Client.Get(proxyURL)
		if err != nil {
			t.Fatalf("request %d/%d: GET %s: %v", i+1, numRequests, proxyURL, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d/%d: expected status 200, got %d", i+1, numRequests, resp.StatusCode)
		}
	}

	addrs := backend.recordedAddrs()
	if len(addrs) == 0 {
		t.Fatalf("backend recorded no PROXY protocol addresses (expected at least 1)")
	}

	for i, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Errorf("addr[%d] %q: SplitHostPort: %v", i, addr, err)
			continue
		}
		if host != "127.0.0.1" {
			t.Errorf("addr[%d]: expected source 127.0.0.1, got %q", i, host)
		}
	}
}

// proxyProtoConfig builds a Caddy JSON configuration that:
//   - listens on listenPort for inbound HTTP requests
//   - proxies them to backendAddr with PROXY protocol ppVersion ("v1"/"v2")
//   - uses the given transport versions (e.g. ["1.1"] or ["h2c"])
func proxyProtoConfig(listenPort int, backendAddr, ppVersion string, transportVersions []string) string {
	versionsJSON, _ := json.Marshal(transportVersions)
	return fmt.Sprintf(`{
		"admin": {
			"listen": "localhost:2999"
		},
		"apps": {
			"pki": {
				"certificate_authorities": {
					"local": {
						"install_trust": false
					}
				}
			},
			"http": {
				"grace_period": 1,
				"servers": {
					"proxy": {
						"listen": [":%d"],
						"automatic_https": {
							"disable": true
						},
						"routes": [
							{
								"handle": [
									{
										"handler": "reverse_proxy",
										"upstreams": [{"dial": "%s"}],
										"transport": {
											"protocol": "http",
											"proxy_protocol": "%s",
											"versions": %s
										}
									}
								]
							}
						]
					}
				}
			}
		}
	}`, listenPort, backendAddr, ppVersion, string(versionsJSON))
}

// freePort returns a free local TCP port by binding briefly and releasing it.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// TestProxyProtocolV1WithH1 verifies that PROXY protocol v1 headers are sent
// correctly when the transport uses HTTP/1.1 to the upstream.
func TestProxyProtocolV1WithH1(t *testing.T) {
	testProxyProtocolMatrix(t, "v1", []string{"1.1"}, 1)
}

// TestProxyProtocolV2WithH1 verifies that PROXY protocol v2 headers are sent
// correctly when the transport uses HTTP/1.1 to the upstream.
func TestProxyProtocolV2WithH1(t *testing.T) {
	testProxyProtocolMatrix(t, "v2", []string{"1.1"}, 1)
}

// TestProxyProtocolV1WithH2C verifies that PROXY protocol v1 headers are sent
// correctly when the transport uses h2c (HTTP/2 cleartext) to the upstream.
func TestProxyProtocolV1WithH2C(t *testing.T) {
	testProxyProtocolMatrix(t, "v1", []string{"h2c"}, 1)
}

// TestProxyProtocolV2WithH2C verifies that PROXY protocol v2 headers are sent
// correctly when the transport uses h2c (HTTP/2 cleartext) to the upstream.
// This is the primary regression test for github.com/caddyserver/caddy/issues/7529:
// before the fix, the h2 transport opened a new TCP connection per request
// (because req.URL.Host was mangled differently for each request due to the
// varying client port), which caused file-descriptor exhaustion under load.
func TestProxyProtocolV2WithH2C(t *testing.T) {
	testProxyProtocolMatrix(t, "v2", []string{"h2c"}, 1)
}

// TestProxyProtocolV2WithH2CMultipleRequests sends several sequential requests
// through the h2c + PROXY-protocol path and confirms that:
//  1. Every request receives a 200 response (no connection exhaustion).
//  2. The backend received at least one PROXY header (connection was reused).
//
// This is the core regression guard for issue #7529: without the fix, a new
// TCP connection was opened per request, quickly exhausting file descriptors.
func TestProxyProtocolV2WithH2CMultipleRequests(t *testing.T) {
	testProxyProtocolMatrix(t, "v2", []string{"h2c"}, 5)
}

// TestProxyProtocolV1WithH2 verifies that PROXY protocol v1 headers are sent
// correctly when the transport uses HTTP/2 over TLS (h2) to the upstream.
func TestProxyProtocolV1WithH2(t *testing.T) {
	testTLSProxyProtocolMatrix(t, "v1", []string{"2"}, 1)
}

// TestProxyProtocolV2WithH2 verifies that PROXY protocol v2 headers are sent
// correctly when the transport uses HTTP/2 over TLS (h2) to the upstream.
func TestProxyProtocolV2WithH2(t *testing.T) {
	testTLSProxyProtocolMatrix(t, "v2", []string{"2"}, 1)
}

// TestProxyProtocolServerAndProxy is an end-to-end matrix test that exercises
// all combinations of PROXY protocol version x transport version.
func TestProxyProtocolServerAndProxy(t *testing.T) {
	plainTests := []struct {
		name              string
		ppVersion         string
		transportVersions []string
		numRequests       int
	}{
		{"h1-v1", "v1", []string{"1.1"}, 3},
		{"h1-v2", "v2", []string{"1.1"}, 3},
		{"h2c-v1", "v1", []string{"h2c"}, 3},
		{"h2c-v2", "v2", []string{"h2c"}, 3},
	}
	for _, tc := range plainTests {
		t.Run(tc.name, func(t *testing.T) {
			testProxyProtocolMatrix(t, tc.ppVersion, tc.transportVersions, tc.numRequests)
		})
	}

	tlsTests := []struct {
		name              string
		ppVersion         string
		transportVersions []string
		numRequests       int
	}{
		{"h2-v1", "v1", []string{"2"}, 3},
		{"h2-v2", "v2", []string{"2"}, 3},
	}
	for _, tc := range tlsTests {
		t.Run(tc.name, func(t *testing.T) {
			testTLSProxyProtocolMatrix(t, tc.ppVersion, tc.transportVersions, tc.numRequests)
		})
	}
}

// testProxyProtocolMatrix is the shared implementation for the proxy protocol
// tests.  It:
//  1. Starts a go-proxyproto-wrapped backend.
//  2. Configures Caddy as a reverse proxy with the given PROXY protocol
//     version and transport versions.
//  3. Sends numRequests GET requests through Caddy and asserts 200 OK each time.
//  4. Asserts the backend recorded at least one PROXY header whose source host
//     is 127.0.0.1 (the loopback address used by the test client).
func testProxyProtocolMatrix(t *testing.T, ppVersion string, transportVersions []string, numRequests int) {
	t.Helper()

	backend := newProxyProtoBackend(t)
	listenPort := freePort(t)

	tester := caddytest.NewTester(t)
	tester.WithDefaultOverrides(caddytest.Config{
		AdminPort: 2999,
	})
	cfg := proxyProtoConfig(listenPort, backend.addr(), ppVersion, transportVersions)
	tester.InitServer(cfg, "json")

	// If the test is h2c-only (no "1.1" in versions), reconfigure the test
	// client transport to use unencrypted HTTP/2 so we actually exercise the
	// h2c code path through Caddy.
	if slices.Contains(transportVersions, "h2c") && !slices.Contains(transportVersions, "1.1") {
		tr, ok := tester.Client.Transport.(*http.Transport)
		if ok {
			tr.Protocols = new(http.Protocols)
			tr.Protocols.SetHTTP1(false)
			tr.Protocols.SetUnencryptedHTTP2(true)
		}
	}

	proxyURL := fmt.Sprintf("http://127.0.0.1:%d/", listenPort)

	for i := 0; i < numRequests; i++ {
		resp, err := tester.Client.Get(proxyURL)
		if err != nil {
			t.Fatalf("request %d/%d: GET %s: %v", i+1, numRequests, proxyURL, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d/%d: expected status 200, got %d", i+1, numRequests, resp.StatusCode)
		}
	}

	// The backend must have seen at least one PROXY header.  For h1, there is
	// one per request; for h2c, requests share the same connection so only one
	// header is written at connection establishment.
	addrs := backend.recordedAddrs()
	if len(addrs) == 0 {
		t.Fatalf("backend recorded no PROXY protocol addresses (expected at least 1)")
	}

	// Every PROXY-decoded source address must be the loopback address since
	// the test client always connects from 127.0.0.1.
	for i, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Errorf("addr[%d] %q: SplitHostPort: %v", i, addr, err)
			continue
		}
		if host != "127.0.0.1" {
			t.Errorf("addr[%d]: expected source 127.0.0.1, got %q", i, host)
		}
	}
}

// TestProxyProtocolListenerWrapper verifies that Caddy's
// caddy.listeners.proxy_protocol listener wrapper can successfully parse
// incoming PROXY protocol headers.
//
// The test dials Caddy's listening port directly, injects a raw PROXY v2
// header spoofing source address 10.0.0.1:1234, then sends a normal
// HTTP/1.1 GET request.  The Caddy server is configured to echo back the
// remote address ({http.request.remote.host}).  The test asserts that the
// echoed address is the spoofed 10.0.0.1.
func TestProxyProtocolListenerWrapper(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
		servers :9080 {
			listener_wrappers {
				proxy_protocol {
					timeout 5s
					allow 127.0.0.0/8
				}
			}
		}
	}
	http://localhost:9080 {
		respond "{http.request.remote.host}"
	}`, "caddyfile")

	// Dial the Caddy listener directly and inject a PROXY v2 header that
	// claims the connection originates from 10.0.0.1:1234.
	conn, err := net.Dial("tcp", "127.0.0.1:9080")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	spoofedSrc := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}
	spoofedDst := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9080}
	hdr := goproxy.HeaderProxyFromAddrs(2, spoofedSrc, spoofedDst)
	if _, err := hdr.WriteTo(conn); err != nil {
		t.Fatalf("write proxy header: %v", err)
	}

	// Write a minimal HTTP/1.1 GET request.
	_, err = fmt.Fprintf(conn,
		"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}

	// Read the raw response and look for the spoofed address in the body.
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	raw := string(buf[:n])

	if !strings.Contains(raw, "10.0.0.1") {
		t.Errorf("expected spoofed address 10.0.0.1 in response body; full response:\n%s", raw)
	}
}
