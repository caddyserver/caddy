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
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
  "admin": {
    "listen": "localhost:2999"
  },
  "apps": {
    "http": {
      "http_port": 9080,
      "https_port": 9443,
      "grace_period": 1,
      "servers": {
        "srv0": {
          "listen": [":9443"],
          "protocols": ["h3"],
          "routes": [
            {
              "handle": [{"handler": "webtransport"}]
            }
          ],
          "tls_connection_policies": [
            {
              "certificate_selection": {"any_tag": ["cert0"]},
              "default_sni": "a.caddy.localhost"
            }
          ]
        }
      }
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
    "pki": {
      "certificate_authorities": {
        "local": {"install_trust": false}
      }
    }
  }
}`, "json")

	dialer := &webtransport.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test uses a local CA
			ServerName:         "a.caddy.localhost",
			NextProtos:         []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}

	// Connect. Give the freshly-reconfigured server a brief window to be
	// ready on the UDP port; retry a handful of times instead of racing.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		rsp  *http.Response
		sess *webtransport.Session
		err  error
	)
	deadline := time.Now().Add(3 * time.Second)
	for {
		rsp, sess, err = dialer.Dial(ctx, "https://127.0.0.1:9443/", nil)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("webtransport dial failed after retries: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer sess.CloseWithError(0, "")

	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", rsp.StatusCode)
	}

	// Open a bidirectional stream and send payload; expect it echoed back.
	str, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	const payload = "hello webtransport"
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

// TestWebTransport_ReverseProxyEndToEnd spins up a single Caddy instance
// running two HTTP/3 servers: one on :9443 acting as the WebTransport
// reverse proxy, and one on :9444 acting as the terminating echo
// upstream. A real webtransport.Dialer dials the proxy; the pump should
// bridge to the upstream so bytes written on a bidi stream are echoed.
func TestWebTransport_ReverseProxyEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
  "admin": {
    "listen": "localhost:2999"
  },
  "apps": {
    "http": {
      "http_port": 9080,
      "https_port": 9443,
      "grace_period": 1,
      "servers": {
        "proxy": {
          "listen": [":9443"],
          "protocols": ["h3"],
          "routes": [
            {
              "handle": [
                {
                  "handler": "reverse_proxy",
                  "transport": {
                    "protocol": "http",
                    "versions": ["3"],
                    "webtransport": true,
                    "tls": {"insecure_skip_verify": true}
                  },
                  "upstreams": [{"dial": "127.0.0.1:9444"}]
                }
              ]
            }
          ],
          "tls_connection_policies": [
            {
              "certificate_selection": {"any_tag": ["cert0"]},
              "default_sni": "a.caddy.localhost"
            }
          ]
        },
        "upstream": {
          "listen": [":9444"],
          "protocols": ["h3"],
          "routes": [
            {"handle": [{"handler": "webtransport"}]}
          ],
          "tls_connection_policies": [
            {
              "certificate_selection": {"any_tag": ["cert0"]},
              "default_sni": "a.caddy.localhost"
            }
          ]
        }
      }
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
    "pki": {
      "certificate_authorities": {
        "local": {"install_trust": false}
      }
    }
  }
}`, "json")

	dialer := &webtransport.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // local CA
			ServerName:         "a.caddy.localhost",
			NextProtos:         []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Retry briefly while both listeners finish binding.
	var (
		sess *webtransport.Session
		rsp  *http.Response
		err  error
	)
	deadline := time.Now().Add(3 * time.Second)
	for {
		rsp, sess, err = dialer.Dial(ctx, "https://127.0.0.1:9443/", nil)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("webtransport dial through proxy failed after retries: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer sess.CloseWithError(0, "")

	if rsp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", rsp.StatusCode)
	}

	str, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream through proxy: %v", err)
	}
	const payload = "reverse-proxied via the pump"
	if _, err := io.WriteString(str, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := str.Close(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	got, err := io.ReadAll(str)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("echo mismatch:\n  got:  %q\n  want: %q", strings.TrimSpace(string(got)), payload)
	}
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

	// Capture the first Extended CONNECT's headers.
	gotHeaders := make(chan http.Header, 1)
	upstreamAddr, stopUpstream := startStandaloneWebTransport(t, func(sess *webtransport.Session, r *http.Request) {
		select {
		case gotHeaders <- r.Header.Clone():
		default:
		}
		_ = sess.CloseWithError(0, "")
	})
	t.Cleanup(stopUpstream)

	config := fmt.Sprintf(`{
  "admin": {"listen": "localhost:2999"},
  "apps": {
    "http": {
      "http_port": 9080,
      "https_port": 9443,
      "grace_period": 1,
      "servers": {
        "proxy": {
          "listen": [":9443"],
          "protocols": ["h3"],
          "routes": [
            {
              "handle": [
                {
                  "handler": "reverse_proxy",
                  "transport": {
                    "protocol": "http",
                    "versions": ["3"],
                    "webtransport": true,
                    "tls": {"insecure_skip_verify": true}
                  },
                  "headers": {
                    "request": {
                      "set": {"X-Caddy-Test": ["caddy-wt-hdr"]}
                    }
                  },
                  "upstreams": [{"dial": "127.0.0.1:%d"}]
                }
              ]
            }
          ],
          "tls_connection_policies": [
            {
              "certificate_selection": {"any_tag": ["cert0"]},
              "default_sni": "a.caddy.localhost"
            }
          ]
        }
      }
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
}`, upstreamAddr.Port)

	tester := caddytest.NewTester(t)
	tester.InitServer(config, "json")

	dialer := &webtransport.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // local CA
			ServerName:         "a.caddy.localhost",
			NextProtos:         []string{http3.NextProtoH3},
		},
		QUICConfig: &quic.Config{
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var sess *webtransport.Session
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, s, err := dialer.Dial(ctx, "https://127.0.0.1:9443/", nil)
		if err == nil {
			sess = s
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("webtransport dial through proxy failed: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
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

// startStandaloneWebTransport starts a webtransport.Server on a random UDP
// port with a self-signed cert. handler runs after a successful Upgrade.
// Returns the listener addr and a shutdown func.
func startStandaloneWebTransport(t *testing.T, handler func(s *webtransport.Session, r *http.Request)) (*net.UDPAddr, func()) {
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
	wtServer := &webtransport.Server{H3: h3}
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
