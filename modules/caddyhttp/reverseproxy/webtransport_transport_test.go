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

package reverseproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
)

// startTestWebTransportServer starts an in-process WebTransport server on a
// random UDP port with a freshly minted self-signed certificate. handler is
// invoked once the CONNECT request has been upgraded to a session.
//
// Returns the UDP addr and a shutdown func. Tests should call the shutdown
// func via t.Cleanup (or explicitly with defer).
func startTestWebTransportServer(t *testing.T, handler func(s *webtransport.Session, r *http.Request), protocols ...string) (addr *net.UDPAddr, trustRoot *x509.Certificate, shutdown func()) {
	t.Helper()

	trustRoot, tlsCfg := generateSelfSignedTLS(t, "localhost")

	mux := http.NewServeMux()
	h3 := &http3.Server{
		TLSConfig: tlsCfg,
		Handler:   mux,
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}
	// Advertise WebTransport in SETTINGS so the client's requirement
	// checks pass. (This is what caddyhttp.Server.buildHTTP3Server does
	// internally for the real server.)
	webtransport.ConfigureHTTP3Server(h3)

	wtServer := &webtransport.Server{H3: h3, ApplicationProtocols: protocols}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		sess, err := wtServer.Upgrade(w, r)
		if err != nil {
			t.Logf("test server upgrade failed: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		handler(sess, r)
	})

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}

	servErr := make(chan error, 1)
	go func() {
		servErr <- wtServer.Serve(udpConn)
	}()

	shutdown = func() {
		_ = wtServer.Close()
		<-servErr
		_ = udpConn.Close()
	}
	return udpConn.LocalAddr().(*net.UDPAddr), trustRoot, shutdown
}

func generateSelfSignedTLS(t *testing.T, commonName string) (*x509.Certificate, *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{commonName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: cert}
	return cert, &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{http3.NextProtoH3}}
}

func clientTLSFor(cert *x509.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{RootCAs: pool, NextProtos: []string{http3.NextProtoH3}}
}

func TestDialUpstreamWebTransport_Succeeds(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	addr, root, shutdown := startTestWebTransportServer(t, func(sess *webtransport.Session, _ *http.Request) {
		_ = sess.CloseWithError(0, "")
	})
	t.Cleanup(shutdown)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://localhost:%d/", addr.Port)
	rsp, sess, err := dialUpstreamWebTransport(ctx, clientTLSFor(root), url, nil, nil, "")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer sess.CloseWithError(0, "")
	if rsp != nil {
		defer rsp.Body.Close()
	}
	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", rsp.StatusCode)
	}
}

func TestDialUpstreamWebTransport_ForwardsHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	gotUA := make(chan string, 1)
	addr, root, shutdown := startTestWebTransportServer(t, func(sess *webtransport.Session, r *http.Request) {
		gotUA <- r.Header.Get("User-Agent")
		_ = sess.CloseWithError(0, "")
	})
	t.Cleanup(shutdown)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hdr := http.Header{"User-Agent": []string{"caddy-wt-test"}}

	url := fmt.Sprintf("https://localhost:%d/", addr.Port)
	rsp, sess, err := dialUpstreamWebTransport(ctx, clientTLSFor(root), url, hdr, nil, "")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer sess.CloseWithError(0, "")
	if rsp != nil {
		defer rsp.Body.Close()
	}

	select {
	case got := <-gotUA:
		if got != "caddy-wt-test" {
			t.Errorf("User-Agent not forwarded; got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("server handler did not observe User-Agent header in time")
	}
}

func TestDialUpstreamWebTransport_BadAddress(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	// No server on this port; expect a dial error within the context deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// Use a loopback port we picked at random and left unbound.
	freePort := pickFreeUDPPort(t)
	url := fmt.Sprintf("https://127.0.0.1:%d/", freePort)
	_, _, err := dialUpstreamWebTransport(ctx, &tls.Config{InsecureSkipVerify: true}, url, nil, nil, "") //nolint:gosec // test only
	if err == nil {
		t.Fatal("expected error dialing unbound port, got nil")
	}
}

func TestParseWTAvailableProtocols(t *testing.T) {
	header := func(v string) http.Header {
		h := make(http.Header)
		if v != "" {
			h.Set(wtAvailableProtocolsHeader, v)
		}
		return h
	}
	for i, tc := range []struct {
		name string
		hdr  http.Header
		want []string
	}{
		{name: "missing", hdr: http.Header{}},
		{
			name: "single",
			hdr:  header(`"moqt-19"`),
			want: []string{"moqt-19"},
		},
		{
			name: "preference order",
			hdr:  header(`"moqt-19", "moqt-18"`),
			want: []string{"moqt-19", "moqt-18"},
		},
		{
			name: "malformed",
			hdr:  header("not a structured field"),
		},
	} {
		got := parseWTAvailableProtocols(tc.hdr)
		if len(got) != len(tc.want) {
			t.Errorf("test %d (%s): got %v, want %v", i, tc.name, got, tc.want)
			continue
		}
		for j := range got {
			if got[j] != tc.want[j] {
				t.Errorf("test %d (%s): got %v, want %v", i, tc.name, got, tc.want)
				break
			}
		}
	}
}

func TestDialUpstreamWebTransport_NegotiatesProtocol(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	addr, root, shutdown := startTestWebTransportServer(t, func(sess *webtransport.Session, _ *http.Request) {
		_ = sess.CloseWithError(0, "")
	}, "moqt-19")
	t.Cleanup(shutdown)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := fmt.Sprintf("https://localhost:%d/", addr.Port)
	rsp, sess, err := dialUpstreamWebTransport(ctx, clientTLSFor(root), url, nil, []string{"moqt-19"}, "")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer sess.CloseWithError(0, "")
	if rsp != nil {
		defer rsp.Body.Close()
	}
	if got := sess.SessionState().ApplicationProtocol; got != "moqt-19" {
		t.Errorf("ApplicationProtocol = %q, want moqt-19", got)
	}
	if got := rsp.Header.Get(wtProtocolHeader); got == "" {
		t.Error("expected WT-Protocol on the response")
	}
}

func TestDialUpstreamWebTransport_PreparedHost(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	gotHost := make(chan string, 1)
	addr, root, shutdown := startTestWebTransportServer(t, func(sess *webtransport.Session, r *http.Request) {
		gotHost <- r.Host
		_ = sess.CloseWithError(0, "")
	})
	t.Cleanup(shutdown)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	url := fmt.Sprintf("https://localhost:%d/", addr.Port)
	wantHost := "wt.example.test"
	rsp, sess, err := dialUpstreamWebTransport(ctx, clientTLSFor(root), url, nil, nil, wantHost)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer sess.CloseWithError(0, "")
	if rsp != nil {
		defer rsp.Body.Close()
	}
	select {
	case got := <-gotHost:
		if got != wantHost {
			t.Errorf("Host = %q, want %q", got, wantHost)
		}
	case <-time.After(time.Second):
		t.Fatal("server handler did not observe Host in time")
	}
}

func TestApplyWebTransportResponseHeaders(t *testing.T) {
	rw := httptest.NewRecorder()
	up := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"X-Upstream":     []string{"yes"},
			"Connection":     []string{"keep-alive"},
			"Keep-Alive":     []string{"timeout=5"},
			wtProtocolHeader: []string{"moqt-19"},
		},
	}
	h := &Handler{
		Headers: &headers.Handler{
			Response: &headers.RespHeaderOps{
				HeaderOps: &headers.HeaderOps{
					Set: http.Header{"X-Down": []string{"from-caddy"}},
				},
			},
		},
	}
	applyWebTransportResponseHeaders(rw, up, h, caddy.NewReplacer())
	if got := rw.Header().Get("X-Upstream"); got != "yes" {
		t.Errorf("X-Upstream = %q, want yes", got)
	}
	if got := rw.Header().Get("X-Down"); got != "from-caddy" {
		t.Errorf("X-Down = %q, want from-caddy", got)
	}
	if got := rw.Header().Get(wtProtocolHeader); got != "moqt-19" {
		t.Errorf("WT-Protocol = %q, want moqt-19", got)
	}
	if got := rw.Header().Get("Keep-Alive"); got != "" {
		t.Errorf("hop-by-hop Keep-Alive leaked: %q", got)
	}
}

// pickFreeUDPPort returns a local UDP port that was free when picked. The
// caller should use it immediately — there's no guarantee another process
// hasn't bound it in the interim.
func pickFreeUDPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	return port
}
