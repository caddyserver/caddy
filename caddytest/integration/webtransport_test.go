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

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"

	"github.com/caddyserver/caddy/v2/caddytest"
)

const wtProxyListen = "https://127.0.0.1:9443/"

// TestWebTransport_EchoHandlerBidi spins up Caddy with an HTTP/3 listener
// that terminates a WebTransport session via the http.handlers.webtransport
// echo handler, then dials it with a real webtransport.Dialer and asserts
// an end-to-end bidirectional-stream round-trip. This exercises the
// serveH3AcceptLoop path (webtransport.Server.ServeQUICConn instead of
// http3.Server.ServeListener) and the UnwrapResponseWriterAs helper.
func TestWebTransport_EchoHandlerBidi(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	caddytest.NewTester(t).InitServer(wtJSON(`"srv0": `+wtH3Server(":9443", `{"handler": "webtransport"}`)), "json")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rsp, sess := dialWT(t, ctx, nil, nil)
	defer sess.CloseWithError(0, "")
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", rsp.StatusCode)
	}
	echoBidi(t, ctx, sess, "hello webtransport")
}

// TestWebTransport_ReverseProxyEndToEnd spins up a single Caddy instance
// running two HTTP/3 servers: one on :9443 acting as the WebTransport
// reverse proxy, and one on :9444 acting as the terminating echo
// upstream. A real webtransport.Dialer dials the proxy; the pump should
// bridge to the upstream so bytes written on a bidi stream are echoed.
func TestWebTransport_ReverseProxyEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	caddytest.NewTester(t).InitServer(wtJSON(
		`"proxy": `+wtH3Server(":9443", wtReverseProxyHandler(`"upstreams": [{"dial": "127.0.0.1:9444"}]`))+
			`, "upstream": `+wtH3Server(":9444", `{"handler": "webtransport"}`),
	), "json")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rsp, sess := dialWT(t, ctx, nil, nil)
	defer sess.CloseWithError(0, "")
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", rsp.StatusCode)
	}
	echoBidi(t, ctx, sess, "reverse-proxied via the pump")
}

// TestWebTransport_ReverseProxyForwardsHeaders proves that the WebTransport
// proxy path applies the same request-preparation pipeline as the normal
// reverse_proxy path: `headers.request.set` lands on the upstream CONNECT,
// X-Forwarded-For is added, and a Via header is appended. The upstream here
// is a standalone webtransport.Server (not another Caddy) so we can observe
// the raw headers of the Extended CONNECT that Caddy forwarded.
func TestWebTransport_ReverseProxyForwardsHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	gotHeaders := make(chan http.Header, 1)
	upstreamAddr, stopUpstream := startStandaloneWebTransport(t, func(sess *webtransport.Session, r *http.Request) {
		select {
		case gotHeaders <- r.Header.Clone():
		default:
		}
		_ = sess.CloseWithError(0, "")
	})
	t.Cleanup(stopUpstream)

	startWTProxy(t, wtReverseProxyHandler(fmt.Sprintf(`
		"headers": {"request": {"set": {"X-Caddy-Test": ["caddy-wt-hdr"]}}},
		"upstreams": [{"dial": "127.0.0.1:%d"}]`, upstreamAddr.Port)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, sess := dialWT(t, ctx, nil, nil)
	defer sess.CloseWithError(0, "")

	select {
	case hdr := <-gotHeaders:
		if got := hdr.Get("X-Caddy-Test"); got != "caddy-wt-hdr" {
			t.Errorf("upstream did not receive `headers.request.set` value; got X-Caddy-Test=%q", got)
		}
		if got := hdr.Get("X-Forwarded-For"); !strings.Contains(got, "127.0.0.1") {
			t.Errorf("upstream did not receive X-Forwarded-For=127.0.0.1; got %q", got)
		}
		if got := hdr.Get("Via"); got == "" {
			t.Errorf("upstream did not receive Via header")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not observe forwarded CONNECT headers in time")
	}
}

// TestWebTransport_ReverseProxyUpgradeUsesDownstreamRequest proves that
// the client-facing Upgrade uses origReq, not the upstream-directed clone.
// header_up rewrites Host to the upstream address while the client sends
// Origin matching the downstream Host; CheckOrigin would fail if Upgrade
// saw the rewritten Host.
func TestWebTransport_ReverseProxyUpgradeUsesDownstreamRequest(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	upgraded := make(chan struct{}, 1)
	upstreamAddr, stopUpstream := startStandaloneWebTransport(t, func(sess *webtransport.Session, _ *http.Request) {
		select {
		case upgraded <- struct{}{}:
		default:
		}
		_ = sess.CloseWithError(0, "")
	})
	t.Cleanup(stopUpstream)

	startWTProxy(t, wtReverseProxyHandler(fmt.Sprintf(`
		"headers": {"request": {"set": {"Host": ["127.0.0.1:%d"]}}},
		"upstreams": [{"dial": "127.0.0.1:%d"}]`, upstreamAddr.Port, upstreamAddr.Port)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, sess := dialWT(t, ctx, http.Header{"Origin": []string{"https://127.0.0.1:9443"}}, nil)
	defer sess.CloseWithError(0, "")

	select {
	case <-upgraded:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not observe a WebTransport session in time")
	}
}

// TestWebTransport_ReverseProxyNegotiatesApplicationProtocol proves the
// proxy relays WT-Available-Protocols to the upstream and copies the
// upstream's WT-Protocol choice back to the client (draft-ietf-webtrans-http3
// §3.3). Without this, a MOQ client such as MediaMTX closes with WT_ALPN_ERROR.
func TestWebTransport_ReverseProxyNegotiatesApplicationProtocol(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	gotHeaders := make(chan http.Header, 1)
	upstreamAddr, stopUpstream := startStandaloneWebTransport(t, func(sess *webtransport.Session, r *http.Request) {
		select {
		case gotHeaders <- r.Header.Clone():
		default:
		}
		_ = sess.CloseWithError(0, "")
	}, "moqt-19")
	t.Cleanup(stopUpstream)

	startWTProxy(t, wtReverseProxyHandler(fmt.Sprintf(`"upstreams": [{"dial": "127.0.0.1:%d"}]`, upstreamAddr.Port)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rsp, sess := dialWT(t, ctx, nil, []string{"moqt-19"})
	defer sess.CloseWithError(0, "")
	if rsp != nil {
		defer rsp.Body.Close()
	}

	if got := sess.SessionState().ApplicationProtocol; got != "moqt-19" {
		t.Errorf("client ApplicationProtocol = %q, want moqt-19", got)
	}
	if got := rsp.Header.Get("WT-Protocol"); got == "" {
		t.Error("client response missing WT-Protocol")
	}

	select {
	case hdr := <-gotHeaders:
		if got := hdr.Get("WT-Available-Protocols"); !strings.Contains(got, "moqt-19") {
			t.Errorf("upstream WT-Available-Protocols = %q, want to contain moqt-19", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not observe a WebTransport session in time")
	}
}

// TestWebTransport_ReverseProxyExpandsSNIPlaceholder proves that a
// placeholder in the transport's tls_server_name (here driven off a request
// header) is expanded per session before the WebTransport upstream dial, so
// the upstream observes the resolved SNI rather than the literal "{...}"
// string. The normal HTTP/3 path handles this via a custom h3Transport.Dial
// hook (#7737); the WebTransport path dials through its own Dialer and so
// must expand the placeholder itself.
func TestWebTransport_ReverseProxyExpandsSNIPlaceholder(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	gotSNI := make(chan string, 1)
	upstreamAddr, stopUpstream := startStandaloneWebTransport(t, func(sess *webtransport.Session, r *http.Request) {
		sni := ""
		if r.TLS != nil {
			sni = r.TLS.ServerName
		}
		select {
		case gotSNI <- sni:
		default:
		}
		_ = sess.CloseWithError(0, "")
	})
	t.Cleanup(stopUpstream)

	startWTProxy(t, wtReverseProxyHandler(
		fmt.Sprintf(`"upstreams": [{"dial": "127.0.0.1:%d"}]`, upstreamAddr.Port),
		`"insecure_skip_verify": true, "server_name": "{http.request.header.X-SNI}"`,
	))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, sess := dialWT(t, ctx, http.Header{"X-Sni": []string{"sni.example.com"}}, nil)
	defer sess.CloseWithError(0, "")

	select {
	case got := <-gotSNI:
		if got != "sni.example.com" {
			t.Errorf("upstream observed SNI %q; want the expanded placeholder value \"sni.example.com\"", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not observe a WebTransport session in time")
	}
}

// TestWebTransport_UpstreamDialFailureSurfaces5xx proves the WT path dials
// the upstream BEFORE upgrading the client, so an unreachable upstream
// returns a proper 5xx on the client's Dial call (webtransport-go surfaces
// it via RequirementsNotMetError or similar with the response attached) —
// not a successful Dial followed by an opaque session close.
func TestWebTransport_UpstreamDialFailureSurfaces5xx(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()

	startWTProxy(t, wtReverseProxyHandler(fmt.Sprintf(`"upstreams": [{"dial": "127.0.0.1:%d"}]`, deadPort)))

	outer, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	var (
		rsp     *http.Response
		dialErr error
		sess    *webtransport.Session
	)
	deadline := time.Now().Add(3 * time.Second)
	for {
		ctx, c := context.WithTimeout(outer, 2*time.Second)
		rsp, sess, dialErr = newWTDialer(nil).Dial(ctx, wtProxyListen, nil)
		c()
		if dialErr != nil {
			break
		}
		// Happy path dial isn't allowed here — the upstream is dead.
		sess.CloseWithError(0, "")
		if time.Now().After(deadline) {
			t.Fatal("expected Dial to fail against unreachable upstream, got success")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The exact error type varies with webtransport-go versions, but the
	// response (if attached) should carry a 5xx status — proving the
	// proxy returned an error status instead of upgrading + closing.
	t.Logf("observed dial error: %v", dialErr)
	if rsp != nil && rsp.StatusCode < 500 {
		t.Errorf("expected 5xx status from proxy on upstream failure; got %d", rsp.StatusCode)
	}
}

// TestWebTransport_InFlightRequestsTracked proves the WT proxy path
// increments upstream.Host.NumRequests for the session's lifetime and
// decrements after it ends, so MaxRequests gating, LeastConn/FirstAvailable
// LB, and the admin /reverse_proxy/upstreams endpoint reflect WT load.
func TestWebTransport_InFlightRequestsTracked(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	// Upstream blocks on a release channel until the test finishes probing
	// the admin API; this keeps the session alive long enough to observe
	// num_requests > 0.
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	upstreamAddr, stopUpstream := startStandaloneWebTransport(t, func(sess *webtransport.Session, r *http.Request) {
		<-release
		_ = sess.CloseWithError(0, "")
	})
	t.Cleanup(stopUpstream)

	upstreamDial := fmt.Sprintf("127.0.0.1:%d", upstreamAddr.Port)
	startWTProxy(t, wtReverseProxyHandler(fmt.Sprintf(`"upstreams": [{"dial": "%s"}]`, upstreamDial)))

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, sess := dialWT(t, ctx, nil, nil)

	if !waitForUpstreamRequests(t, upstreamDial, 1, 2*time.Second) {
		t.Fatal("upstream num_requests never reached >= 1 while session was active")
	}

	_ = sess.CloseWithError(0, "")
	close(release)

	if !waitForUpstreamRequests(t, upstreamDial, 0, 2*time.Second) {
		t.Fatal("upstream num_requests did not drop to 0 after session closed")
	}
}

func startWTProxy(t *testing.T, handlerJSON string) {
	t.Helper()
	caddytest.NewTester(t).InitServer(wtJSON(`"proxy": `+wtH3Server(":9443", handlerJSON)), "json")
}

func wtJSON(serversJSON string) string {
	return fmt.Sprintf(`{
  "admin": {"listen": "localhost:2999"},
  "apps": {
    "http": {
      "http_port": 9080,
      "https_port": 9443,
      "grace_period": 1,
      "servers": { %s }
    },
    "tls": {
      "certificates": {
        "load_files": [
          {
            "certificate": "/a.caddy.localhost.crt",
            "key": "/a.caddy.localhost.key",
            "tags": ["cert0"]
          }
        ]
      }
    },
    "pki": {"certificate_authorities": {"local": {"install_trust": false}}}
  }
}`, serversJSON)
}

func wtH3Server(listen, handlerJSON string) string {
	return fmt.Sprintf(`{
  "listen": [%q],
  "protocols": ["h3"],
  "webtransport": {},
  "routes": [{"handle": [%s]}],
  "tls_connection_policies": [
    {
      "certificate_selection": {"any_tag": ["cert0"]},
      "default_sni": "a.caddy.localhost"
    }
  ]
}`, listen, handlerJSON)
}

func wtReverseProxyHandler(extraJSON string, tlsExtra ...string) string {
	tls := `"insecure_skip_verify": true`
	if len(tlsExtra) > 0 && tlsExtra[0] != "" {
		tls = tlsExtra[0]
	}
	body := fmt.Sprintf(`"handler": "reverse_proxy",
  "transport": {
    "protocol": "http",
    "versions": ["3"],
    "tls": {%s}
  }`, tls)
	if extraJSON != "" {
		body += ",\n  " + extraJSON
	}
	return "{" + body + "}"
}

func newWTDialer(protocols []string) *webtransport.Dialer {
	return &webtransport.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // local CA
			ServerName:         "a.caddy.localhost",
			NextProtos:         []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
		ApplicationProtocols: protocols,
	}
}

func dialWT(t *testing.T, ctx context.Context, hdr http.Header, protocols []string) (*http.Response, *webtransport.Session) {
	t.Helper()
	dialer := newWTDialer(protocols)
	deadline := time.Now().Add(3 * time.Second)
	for {
		rsp, sess, err := dialer.Dial(ctx, wtProxyListen, hdr)
		if err == nil {
			return rsp, sess
		}
		if time.Now().After(deadline) {
			t.Fatalf("webtransport dial failed after retries: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func echoBidi(t *testing.T, ctx context.Context, sess *webtransport.Session, payload string) {
	t.Helper()
	str, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := io.WriteString(str, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := str.Close(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	got, err := io.ReadAll(str)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echo mismatch:\n  got:  %q\n  want: %q", strings.TrimSpace(string(got)), payload)
	}
}

// waitForUpstreamRequests polls the admin /reverse_proxy/upstreams endpoint
// until the entry for dial has exactly wantRequests in-flight, or timeout.
// Returns true on match.
func waitForUpstreamRequests(t *testing.T, dial string, wantRequests int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rsp, err := http.Get("http://localhost:2999/reverse_proxy/upstreams")
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		var entries []struct {
			Address     string `json:"address"`
			NumRequests int    `json:"num_requests"`
		}
		err = json.NewDecoder(rsp.Body).Decode(&entries)
		_ = rsp.Body.Close()
		if err != nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		for _, e := range entries {
			if e.Address == dial && e.NumRequests == wantRequests {
				return true
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// startStandaloneWebTransport starts a webtransport.Server on a random UDP
// port with a self-signed cert. handler runs after a successful Upgrade.
// Returns the listener addr and a shutdown func.
func startStandaloneWebTransport(t *testing.T, handler func(s *webtransport.Session, r *http.Request), protocols ...string) (*net.UDPAddr, func()) {
	t.Helper()
	tlsCfg := newSelfSignedTLSConfig(t, "localhost")

	mux := http.NewServeMux()
	h3 := &http3.Server{
		TLSConfig: tlsCfg,
		Handler:   mux,
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}
	webtransport.ConfigureHTTP3Server(h3)
	wtServer := &webtransport.Server{
		H3:                   h3,
		ApplicationProtocols: protocols,
		// Test backends are not browsers; skip same-origin checks so
		// header_up Host rewrites used by proxy tests do not 400 the
		// upstream Upgrade.
		CheckOrigin: func(*http.Request) bool { return true },
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sess, err := wtServer.Upgrade(w, r)
		if err != nil {
			t.Logf("standalone WebTransport upgrade failed: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		handler(sess, r)
	})

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	servErr := make(chan error, 1)
	go func() { servErr <- wtServer.Serve(conn) }()
	shutdown := func() {
		_ = wtServer.Close()
		<-servErr
		_ = conn.Close()
	}
	return conn.LocalAddr().(*net.UDPAddr), shutdown
}

// newSelfSignedTLSConfig produces a self-signed TLS config suitable for
// 127.0.0.1 and the given common name, with the H3 ALPN advertised.
func newSelfSignedTLSConfig(t *testing.T, cn string) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: cert}},
		NextProtos:   []string{http3.NextProtoH3},
	}
}
