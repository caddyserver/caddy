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
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(acceptSignalWrapper{})
}

// acceptSignalWrapper is a listener wrapper for tests: it reports, through
// the acceptSignals registered under its name, each connection its server
// accepts and when its server's accept loop gets an error (its listener
// was closed; the Serve loop returns next).
type acceptSignalWrapper struct {
	Name string `json:"name,omitempty"`
}

func (acceptSignalWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.test_accept_signal",
		New: func() caddy.Module { return new(acceptSignalWrapper) },
	}
}

func (w *acceptSignalWrapper) WrapListener(ln net.Listener) net.Listener {
	sig, _ := acceptSignalsByName.Load(w.Name)
	return &acceptSignalListener{Listener: ln, sig: sig.(*acceptSignals)}
}

type acceptSignalListener struct {
	net.Listener
	sig *acceptSignals
}

func (l *acceptSignalListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		l.sig.closeOnce.Do(func() { close(l.sig.closed) })
		return nil, err
	}
	select {
	case l.sig.accepted <- struct{}{}:
	default:
	}
	return c, nil
}

type acceptSignals struct {
	name      string
	accepted  chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
}

var (
	acceptSignalsByName sync.Map
	acceptSignalsSeq    atomic.Int64
)

func newAcceptSignals(t *testing.T) *acceptSignals {
	sig := &acceptSignals{
		name:     fmt.Sprintf("%s-%d", t.Name(), acceptSignalsSeq.Add(1)),
		accepted: make(chan struct{}, 16),
		closed:   make(chan struct{}),
	}
	acceptSignalsByName.Store(sig.name, sig)
	t.Cleanup(func() { acceptSignalsByName.Delete(sig.name) })
	return sig
}

// shutdownTestConfig serves body on addr over HTTP/1.1 and h2c, with an
// acceptSignalWrapper named sigName.
func shutdownTestConfig(addr, sigName, body, gracePeriod string) []byte {
	return fmt.Appendf(nil, `{
		"admin": {"disabled": true},
		"logging": {"logs": {"default": {"level": "ERROR"}}},
		"apps": {"http": {
			"grace_period": %q,
			"servers": {"srv": {
				"listen": [%q],
				"protocols": ["h1", "h2c"],
				"automatic_https": {"disable": true},
				"listener_wrappers": [{"wrapper": "test_accept_signal", "name": %q}],
				"routes": [{"handle": [{"handler": "static_response", "body": %q}]}]
			}}
		}}
	}`, gracePeriod, addr, sigName, body)
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func mustLoad(t *testing.T, cfg []byte) {
	t.Helper()
	if err := caddy.Load(cfg, true); err != nil {
		t.Fatalf("loading config: %v", err)
	}
}

// await fails the test if ch does not receive in time. The timeout only
// keeps a broken build from hanging; the tests synchronise on ch.
func await[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// shutdownsSince returns the server shutdowns begun since before was taken
// (with before nil, it returns all of them as before).
func shutdownsSince(before map[any]bool) (map[any]bool, []chan struct{}) {
	all := map[any]bool{}
	var started []chan struct{}
	pendingServerShutdowns.Range(func(done, _ any) bool {
		all[done] = true
		if before != nil && !before[done] {
			started = append(started, done.(chan struct{}))
		}
		return true
	})
	return all, started
}

func dialTest(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

// roundTrip sends a GET on conn with HTTP/1.1, or with HTTP/2 (h2c, prior
// knowledge), and returns the response body.
func roundTrip(conn net.Conn, addr string, h2 bool) (string, error) {
	var resp *http.Response
	if h2 {
		cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(conn)
		if err != nil {
			return "", err
		}
		req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/", nil)
		if err != nil {
			return "", err
		}
		if resp, err = cc.RoundTrip(req); err != nil {
			return "", err
		}
		if resp.ProtoMajor != 2 {
			return "", fmt.Errorf("got %s, want HTTP/2", resp.Proto)
		}
	} else {
		if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+addr+"\r\nConnection: close\r\n\r\n"); err != nil {
			return "", err
		}
		var err error
		if resp, err = http.ReadResponse(bufio.NewReader(conn), nil); err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	return string(body), nil
}

// A connection the old config's server accepted, whose first request
// arrives only after that server's listener closed for a reload, is
// answered by the old config. Before, the request was read after
// http.Server.Shutdown began and the connection closed with no response.
// The listener is either kept by the new config (same address, reused
// through the listener pool) or removed from it.
func TestReloadAnswersAcceptedConnection(t *testing.T) {
	for _, listener := range []string{"reused", "removed"} {
		for _, proto := range []string{"HTTP/1.1", "HTTP/2"} {
			t.Run(listener+"/"+proto, func(t *testing.T) {
				h2 := proto == "HTTP/2"
				oldAddr := freeTCPAddr(t)
				newAddr := oldAddr
				if listener == "removed" {
					newAddr = freeTCPAddr(t)
				}

				oldSig := newAcceptSignals(t)
				mustLoad(t, shutdownTestConfig(oldAddr, oldSig.name, "old", "0"))
				t.Cleanup(func() { _ = caddy.Stop() })

				conn := dialTest(t, oldAddr)
				await(t, oldSig.accepted, "the old server to accept the connection")

				before, _ := shutdownsSince(nil)
				newSig := newAcceptSignals(t)
				mustLoad(t, shutdownTestConfig(newAddr, newSig.name, "new", "0"))
				_, oldStops := shutdownsSince(before)
				// the old server's accept loop is done: it no longer
				// accepts and is being shut down
				await(t, oldSig.closed, "the old server's listener to close")

				body, err := roundTrip(conn, oldAddr, h2)
				if err != nil {
					t.Fatalf("connection accepted before the reload, request sent after: %v", err)
				}
				if body != "old" {
					t.Fatalf("answered %q, want the old config's answer", body)
				}
				// and the old config finishes shutting down, while the
				// client keeps its connection open (HTTP/2: it was told
				// to go away)
				for _, done := range oldStops {
					await(t, done, "the old config's shutdown to finish")
				}

				// and the new config serves new connections
				body, err = roundTrip(dialTest(t, newAddr), newAddr, h2)
				if err != nil || body != "new" {
					t.Fatalf("after the reload: %q, %v", body, err)
				}
			})
		}
	}
}

// A client that connects and never sends does not hold the old config's
// shutdown past grace_period.
func TestReloadSilentConnectionWithinGracePeriod(t *testing.T) {
	const grace = 200 * time.Millisecond
	addr := freeTCPAddr(t)

	oldSig := newAcceptSignals(t)
	mustLoad(t, shutdownTestConfig(addr, oldSig.name, "old", grace.String()))
	t.Cleanup(func() { _ = caddy.Stop() })

	dialTest(t, addr)
	await(t, oldSig.accepted, "the old server to accept the connection")

	before, _ := shutdownsSince(nil)
	start := time.Now()
	newSig := newAcceptSignals(t)
	mustLoad(t, shutdownTestConfig(addr, newSig.name, "new", grace.String()))
	_, oldStops := shutdownsSince(before)
	for _, done := range oldStops {
		select {
		case <-done:
		case <-time.After(newConnMaxWait - time.Second):
			t.Fatalf("old config still shutting down after %s, grace_period %s", time.Since(start), grace)
		}
	}
	if elapsed := time.Since(start); elapsed < grace {
		t.Fatalf("old config shut down in %s, before grace_period %s ended with a connection open", elapsed, grace)
	}
}

// An HTTP/1 connection becomes StateActive before net/http checks whether
// the server is shutting down, so StateActive alone does not mean its
// request will be answered. Hold such a connection between the two (from
// the ConnState hook) while the old config is stopped: the stop must keep
// waiting on it rather than begin Shutdown.
func TestReloadWaitsForActiveConnectionPastShutdownCheck(t *testing.T) {
	addr := freeTCPAddr(t)
	oldSig := newAcceptSignals(t)
	mustLoad(t, shutdownTestConfig(addr, oldSig.name, "old", "0"))
	t.Cleanup(func() { _ = caddy.Stop() })

	httpApp, err := caddy.ActiveContext().AppIfConfigured("http")
	if err != nil {
		t.Fatal(err)
	}
	shutdownBegan := make(chan struct{})
	httpApp.(*App).Servers["srv"].server.RegisterOnShutdown(func() { close(shutdownBegan) })

	active := make(chan struct{})
	release := make(chan struct{})
	var holdOnce sync.Once
	hold := func(_ net.Conn, state http.ConnState) {
		if state == http.StateActive {
			holdOnce.Do(func() {
				close(active)
				<-release
			})
		}
	}
	testHookNewConnState.Store(&hold)
	t.Cleanup(func() { testHookNewConnState.Store(nil) })
	stopWaits := make(chan int, 1)
	awaiting := func(pending int) {
		select {
		case stopWaits <- pending:
		default:
		}
	}
	testHookAwaitNewConns.Store(&awaiting)
	t.Cleanup(func() { testHookAwaitNewConns.Store(nil) })

	conn := dialTest(t, addr)
	await(t, oldSig.accepted, "the old server to accept the connection")
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+addr+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	await(t, active, "the request to be read")

	newSig := newAcceptSignals(t)
	mustLoad(t, shutdownTestConfig(addr, newSig.name, "new", "0"))
	select {
	case <-stopWaits:
	case <-shutdownBegan:
	case <-time.After(10 * time.Second):
		t.Fatal("the old config's stop neither waited nor shut down")
	}
	close(release)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("request read before the stop, checked after: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "old" {
		t.Fatalf("answered %q, %v", body, err)
	}
}
