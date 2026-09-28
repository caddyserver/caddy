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

package caddyhttp

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
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestStopWaitsForPreviousConfiguration(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		for _, grace := range []time.Duration{0, 5 * time.Second} {
			t.Run(fmt.Sprintf("http2=%t/grace=%s", http2, grace), func(t *testing.T) {
				previous, response, release := appWithPendingResponse(t, http2)
				previous.GracePeriod = caddy.Duration(grace)
				if err := previous.stop(false); err != nil {
					t.Fatal(err)
				}

				current := &App{logger: zap.NewNop()}
				stopped := make(chan error, 1)
				go func() { stopped <- current.stop(true) }()
				select {
				case err := <-stopped:
					t.Fatalf("termination returned while the previous response was active: %v", err)
				case <-time.After(50 * time.Millisecond):
				}

				release()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != "before\nafter\n" {
					t.Fatalf("unexpected response body: %q", body)
				}
				select {
				case err := <-stopped:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("termination did not finish after the previous response completed")
				}
			})
		}
	}
}

func TestStopPreviousConfigurationGracePeriod(t *testing.T) {
	previous, response, release := appWithPendingResponse(t, false)
	if err := previous.stop(false); err != nil {
		t.Fatal(err)
	}

	current := &App{GracePeriod: caddy.Duration(50 * time.Millisecond), logger: zap.NewNop()}
	stopped := make(chan error, 1)
	start := time.Now()
	go func() { stopped <- current.stop(true) }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("termination ignored its grace period while waiting for the previous configuration")
	}
	if elapsed := time.Since(start); elapsed < time.Duration(current.GracePeriod) {
		t.Errorf("termination returned after %s, before its grace period expired", elapsed)
	}

	release()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
}

func appWithPendingResponse(t *testing.T, http2 bool) (*App, *http.Response, func()) {
	t.Helper()

	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "before")
		http.NewResponseController(w).Flush()
		select {
		case <-released:
			fmt.Fprintln(w, "after")
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = http2
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(release)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	if http2 && response.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", response.Proto)
	}
	app := &App{
		Servers: map[string]*Server{"test": {server: server.Config}},
		logger:  zap.NewNop(),
	}
	t.Cleanup(func() {
		release()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Config.Shutdown(ctx)
	})
	return app, response, release
}

// TestServerErrorLoggerLevels verifies that recovered net/http handler panics
// written to http.Server.ErrorLog surface at ERROR level (so they're visible
// at the default log level), while other standard library server messages stay
// at DEBUG. Regression test for #7923.
func TestServerErrorLoggerLevels(t *testing.T) {
	for _, tc := range []struct {
		name      string
		message   string
		wantLevel zapcore.Level
	}{
		{
			name:      "recovered handler panic logs at error",
			message:   "http: panic serving 127.0.0.1:12345: boom\ngoroutine 1 [running]:\nmain.handler()",
			wantLevel: zapcore.ErrorLevel,
		},
		{
			name:      "other server message logs at debug",
			message:   "http: TLS handshake error from 127.0.0.1:12345: EOF",
			wantLevel: zapcore.DebugLevel,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			serverLogger := serverErrorLogger(zap.New(core))

			serverLogger.Print(tc.message)

			entries := logs.All()
			if len(entries) != 1 {
				t.Fatalf("expected exactly 1 log entry, got %d", len(entries))
			}
			got := entries[0]
			if got.Level != tc.wantLevel {
				t.Errorf("expected level %s, got %s", tc.wantLevel, got.Level)
			}
			if got.Message != tc.message {
				t.Errorf("expected message %q, got %q", tc.message, got.Message)
			}
		})
	}
}

// TestStopGracePeriodOnReload checks that on a reload, active connections
// get the whole grace period and are closed once it is over, and that stop
// hooks run only after the shutdown is done.
func TestStopGracePeriodOnReload(t *testing.T) {
	for _, proto := range []string{"h1", "h2", "h3"} {
		t.Run(proto, func(t *testing.T) {
			t.Run("completes within grace period", func(t *testing.T) {
				g := newGracePeriodServer(t, proto, 3*time.Second)
				defer g.close()

				requestDone := make(chan error, 1)
				go func() {
					requestDone <- g.get()
				}()
				<-g.started

				if err := g.app.Stop(); err != nil {
					t.Fatalf("stop: %v", err)
				}

				// shutdown isn't done, so the hook must not have run
				select {
				case <-g.hookRan:
					t.Error("stop hook ran while a request was still being served")
				default:
				}

				// now let the request finish, within the grace period
				g.unblock()

				select {
				case err := <-requestDone:
					if err != nil {
						t.Fatalf("request should have completed within the grace period: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("request did not complete within the grace period")
				}

				// the server is done, so the hook should run
				select {
				case <-g.hookRan:
				case <-time.After(10 * time.Second):
					t.Fatal("stop hook did not run after shutdown completed")
				}

				if shutdownLogs := g.logs.FilterMessage(g.shutdownLog).All(); len(shutdownLogs) != 0 {
					t.Errorf("unexpected shutdown error within grace period: %v", shutdownLogs)
				}

				// it drained in time, so nothing should be force-closed
				if closeLogs := g.logs.FilterMessage("server close after grace period").All(); len(closeLogs) != 0 {
					t.Errorf("server was force-closed despite draining in time: %v", closeLogs)
				}
			})

			t.Run("forcefully closed after grace period", func(t *testing.T) {
				const gracePeriod = 500 * time.Millisecond
				g := newGracePeriodServer(t, proto, gracePeriod)
				defer g.close()

				requestDone := make(chan error, 1)
				go func() {
					requestDone <- g.get()
				}()
				<-g.started

				start := time.Now()
				if err := g.app.Stop(); err != nil {
					t.Fatalf("stop: %v", err)
				}

				// on a reload, Stop must not wait for the grace period
				if elapsed := time.Since(start); elapsed > gracePeriod {
					t.Errorf("Stop blocked for %s; it should return without waiting for the grace period", elapsed)
				}

				select {
				case err := <-requestDone:
					if err == nil {
						t.Fatal("expected the active request to be forcefully closed")
					}
					if elapsed := time.Since(start); elapsed < gracePeriod {
						t.Errorf("connection was closed after %s, before the %s grace period was over", elapsed, gracePeriod)
					}
				case <-time.After(gracePeriod + 10*time.Second):
					t.Fatal("connection was not closed after the grace period")
				}

				// the hook should run after the forced close, not before
				select {
				case <-g.hookRan:
				case <-time.After(10 * time.Second):
					t.Fatal("stop hook did not run after the forced close")
				}

				// the grace period is over, but the hook still needs a
				// context it can use for its cleanup
				if g.hookErr != nil {
					t.Errorf("stop hook got an expired context after the grace period: %v", g.hookErr)
				}

				shutdownLogs := g.logs.FilterMessage(g.shutdownLog).All()
				if len(shutdownLogs) == 0 {
					t.Error("expected a server shutdown error after the grace period")
				}
				for _, entry := range shutdownLogs {
					errMsg, _ := entry.ContextMap()["error"].(string)
					if !strings.Contains(errMsg, "server graceful shutdown") {
						t.Errorf("expected grace period timeout error, got: %v", errMsg)
					}
				}
			})
		})
	}
}

// gracePeriodServer is a running server for one HTTP protocol, plus a client
// and the bits needed to watch how App.Stop shuts it down.
type gracePeriodServer struct {
	app          *App
	url          string
	client       *http.Client
	protoMajor   int
	shutdownLog  string
	started      chan struct{}
	release      chan struct{}
	releaseOnce  sync.Once
	hookRan      chan struct{}
	hookRanOnce  sync.Once
	hookErr      error
	logs         *observer.ObservedLogs
	cleanupFuncs []func()
}

// newGracePeriodServer starts a server whose handler signals started and
// then blocks, so the test decides when the request finishes.
func newGracePeriodServer(t *testing.T, proto string, gracePeriod time.Duration) *gracePeriodServer {
	t.Helper()

	g := &gracePeriodServer{
		started: make(chan struct{}),
		release: make(chan struct{}),
		hookRan: make(chan struct{}),
	}
	var startedOnce sync.Once
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedOnce.Do(func() { close(g.started) })
		// wait for the test, or for the connection to be closed
		select {
		case <-g.release:
			_, _ = io.WriteString(w, "ok")
		case <-r.Context().Done():
		}
	})

	// a stop hook, part of the cleanup after shutdown; it fails if it
	// gets an expired context, since then it could not do its work
	stopHook := func(ctx context.Context) error {
		err := ctx.Err()
		g.hookRanOnce.Do(func() {
			g.hookErr = err
			close(g.hookRan)
		})
		return err
	}

	core, logs := observer.New(zapcore.DebugLevel)
	g.logs = logs

	var srv *Server
	switch proto {
	case "h1":
		ts := httptest.NewServer(handler)
		srv = &Server{server: ts.Config}
		g.url = ts.URL
		g.client = ts.Client()
		g.protoMajor = 1
		g.shutdownLog = "server shutdown"
		g.cleanupFuncs = append(g.cleanupFuncs, ts.Close)

	case "h2":
		ts := httptest.NewUnstartedServer(handler)
		ts.EnableHTTP2 = true
		ts.StartTLS()
		srv = &Server{server: ts.Config}
		g.url = ts.URL
		g.client = ts.Client()
		g.protoMajor = 2
		g.shutdownLog = "server shutdown"
		g.cleanupFuncs = append(g.cleanupFuncs, ts.Close)

	case "h3":
		tlsConf := &tls.Config{Certificates: []tls.Certificate{testTLSCertificate(t)}}
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		transport := &quic.Transport{Conn: udpConn}
		h3ln, err := transport.Listen(http3.ConfigureTLSConfig(tlsConf), &quic.Config{})
		if err != nil {
			t.Fatalf("listen quic: %v", err)
		}
		h3server := &http3.Server{Handler: handler, TLSConfig: tlsConf}
		go func() { _ = h3server.ServeListener(h3ln) }()

		srv = &Server{
			h3server:      h3server,
			quicListeners: []http3.QUICListener{h3ln},
		}

		rt := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
		g.url = "https://" + h3ln.Addr().String() + "/"
		g.client = &http.Client{Transport: rt}
		g.protoMajor = 3
		g.shutdownLog = "HTTP/3 server shutdown"
		g.cleanupFuncs = append(g.cleanupFuncs,
			func() { _ = rt.Close() },
			func() { _ = transport.Close() },
			func() { _ = udpConn.Close() },
		)

	default:
		t.Fatalf("unknown protocol %q", proto)
	}

	srv.onStopFuncs = []func(context.Context) error{stopHook}

	g.app = &App{
		GracePeriod: caddy.Duration(gracePeriod),
		logger:      zap.New(core),
		Servers:     map[string]*Server{"srv0": srv},
	}
	return g
}

// get performs a GET request to the test server and verifies the response.
func (g *gracePeriodServer) get() error {
	req, err := http.NewRequest(http.MethodGet, g.url, nil)
	if err != nil {
		return err
	}
	// close the connection after the response so the server can finish
	// shutting down; this doesn't affect the request itself
	req.Close = true

	resp, err := g.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if string(body) != "ok" {
		return fmt.Errorf("unexpected body %q", body)
	}
	// make sure we didn't quietly fall back to HTTP/1.1
	if resp.ProtoMajor != g.protoMajor {
		return fmt.Errorf("served over %s, expected HTTP/%d", resp.Proto, g.protoMajor)
	}
	return nil
}

// unblock lets the handler finish; safe to call more than once.
func (g *gracePeriodServer) unblock() {
	g.releaseOnce.Do(func() { close(g.release) })
}

// close unblocks the handler and releases the server's resources.
func (g *gracePeriodServer) close() {
	g.unblock()
	for i := len(g.cleanupFuncs) - 1; i >= 0; i-- {
		g.cleanupFuncs[i]()
	}
}

// testTLSCertificate returns a self-signed certificate suitable for tests.
func testTLSCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
