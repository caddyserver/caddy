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

package fastcgi

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

// extra is sent past the declared body and must never be logged.
const extra = "EXTRA-BODY-BYTES"

type fcgiRecord struct {
	recType uint8
	content string
	delay   time.Duration // before sending
}

func stdout(s string) fcgiRecord { return fcgiRecord{recType: Stdout, content: s} }

func sendRecords(recs ...fcgiRecord) func(*streamWriter) error {
	return func(w *streamWriter) error {
		for _, rec := range recs {
			time.Sleep(rec.delay)
			if err := w.writeRecord(rec.recType, []byte(rec.content)); err != nil {
				return err
			}
		}
		return w.writeRecord(EndRequest, make([]byte, 8))
	}
}

// fcgiResponder accepts one connection, reads the request and calls respond,
// which unlike net/http/fcgi can send any body. It then holds the connection
// open until the client closes it, and closes the returned channel.
func fcgiResponder(t *testing.T, respond func(*streamWriter) error) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	closed := make(chan struct{})
	go func() {
		defer close(closed)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var rec record
		for rec.fill(conn) == nil && (rec.h.Type != Stdin || rec.h.ContentLength > 0) {
			_, _ = io.Copy(io.Discard, &rec)
		}
		_ = respond(&streamWriter{c: &client{rwc: conn, reqID: 1}, buf: new(bytes.Buffer)})
		_, _ = io.Copy(io.Discard, conn)
	}()
	return ln.Addr().String(), closed
}

// fcgiRequest sends a request to the responder at addr as Transport.RoundTrip
// does, and returns the response and the client's logs.
func fcgiRequest(t *testing.T, addr, method string, readTimeout time.Duration) (*http.Response, *observer.ObservedLogs) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // fail rather than hang

	core, logs := observer.New(zapcore.DebugLevel)
	c := &client{rwc: conn, reqID: 1, stderr: true, logger: zap.New(core)}
	_ = c.SetReadTimeout(readTimeout)
	resp, err := c.Request(map[string]string{"REQUEST_METHOD": method, "CONTENT_LENGTH": "0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resp, logs
}

func waitClosed(t *testing.T, closed <-chan struct{}) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Error("connection to the responder was not closed")
	}
}

// surplusLogged returns the surplus_bytes of the one surplus warning, or 0
// without one, and fails the test if any entry carries body bytes.
func surplusLogged(t *testing.T, logs *observer.ObservedLogs) int64 {
	t.Helper()
	var n int64
	for _, e := range logs.All() {
		if strings.Contains(e.Message+fmt.Sprint(e.ContextMap()), extra) {
			t.Errorf("log entry %q contains body bytes", e.Message)
		}
		if e.Message == "discarding upstream response bytes beyond the declared Content-Length" {
			if n != 0 || e.Level != zapcore.WarnLevel {
				t.Errorf("want one surplus warning at warn level, got another at %s", e.Level)
			}
			n = e.ContextMap()["surplus_bytes"].(int64)
		}
	}
	return n
}

func TestResponseBody(t *testing.T) {
	t.Parallel()

	const page = "Content-Length: 5\r\n\r\nhello"
	warning := fcgiRecord{recType: Stderr, content: "PHP Warning"}
	lateWarning := fcgiRecord{recType: Stderr, content: "PHP Warning", delay: maxSurplusWait + 200*time.Millisecond}

	for _, tc := range []struct {
		name        string
		method      string
		records     []fcgiRecord
		readTimeout time.Duration
		body        string
		err         error
		surplus     int
		stderr      string
	}{
		{name: "exact, then stderr", records: []fcgiRecord{stdout(page), warning}, body: "hello", stderr: "PHP Warning"},
		{name: "exact, then stderr after a pause", records: []fcgiRecord{stdout(page), lateWarning}, body: "hello", stderr: "PHP Warning"},
		{name: "exact, then the read timeout", records: []fcgiRecord{stdout(page), lateWarning}, readTimeout: 300 * time.Millisecond, body: "hello", err: os.ErrDeadlineExceeded},
		{name: "shorter", records: []fcgiRecord{stdout("Content-Length: 10\r\n\r\nhello")}, body: "hello", err: io.ErrUnexpectedEOF},
		{name: "excessive, then stderr", records: []fcgiRecord{stdout(page + extra), warning}, body: "hello", surplus: len(extra), stderr: "PHP Warning"},
		{name: "zero length", records: []fcgiRecord{stdout("Content-Length: 0\r\n\r\n" + extra)}, surplus: len(extra)},
		// Unknown lengths, and responses without a body, are read in full as before.
		{name: "no length", records: []fcgiRecord{stdout("Content-Type: text/plain\r\n\r\nhello" + extra)}, body: "hello" + extra},
		{name: "invalid length", records: []fcgiRecord{stdout("Content-Length: abc\r\n\r\nhello" + extra)}, body: "hello" + extra},
		{name: "negative length", records: []fcgiRecord{stdout("Content-Length: -5\r\n\r\nhello" + extra)}, body: "hello" + extra},
		{name: "chunked", records: []fcgiRecord{stdout("Transfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n5\r\nhello\r\n0\r\n\r\n")}, body: "hello"},
		{name: "HEAD", method: http.MethodHead, records: []fcgiRecord{stdout(page + extra)}, body: "hello" + extra},
		{name: "1xx", records: []fcgiRecord{stdout("Status: 103 Early Hints\r\n" + page + extra)}, body: "hello" + extra},
		{name: "204", records: []fcgiRecord{stdout("Status: 204 No Content\r\n" + page + extra)}, body: "hello" + extra},
		{name: "304", records: []fcgiRecord{stdout("Status: 304 Not Modified\r\n" + page + extra)}, body: "hello" + extra},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr, closed := fcgiResponder(t, sendRecords(tc.records...))
			resp, logs := fcgiRequest(t, addr, cmp.Or(tc.method, http.MethodGet), tc.readTimeout)

			body, err := io.ReadAll(resp.Body)
			if string(body) != tc.body || !errors.Is(err, tc.err) {
				t.Errorf("ReadAll() = %q, %v; want %q, %v", body, err, tc.body, tc.err)
			}
			if tc.err != nil {
				// The proxy can read again after an error.
				if _, err := resp.Body.Read(make([]byte, 1)); !errors.Is(err, tc.err) {
					t.Errorf("Read() after the error = %v, want %v", err, tc.err)
				}
			}
			resp.Body.Close()
			waitClosed(t, closed)

			if got := surplusLogged(t, logs); got != int64(tc.surplus) {
				t.Errorf("surplus_bytes = %d, want %d", got, tc.surplus)
			}
			var stderr string
			for _, e := range logs.FilterMessage("stderr").All() {
				stderr += e.ContextMap()["body"].(string)
			}
			if stderr != tc.stderr {
				t.Errorf("logged stderr %q, want %q", stderr, tc.stderr)
			}
		})
	}
}

// TestResponseSurplusIsBounded checks that a responder writing past its body
// cannot hold the connection: reading to the end stops within the surplus
// limits, and Close returns at once, even when the body was not read to its
// end. The proxy stops flushing once the body ends, so any wait in Close
// would hold back what it had not yet sent.
func TestResponseSurplusIsBounded(t *testing.T) {
	t.Parallel()

	hold := func(response string) func(*streamWriter) error {
		return func(w *streamWriter) error { return w.writeRecord(Stdout, []byte(response)) }
	}
	// overflow writes past the body for 3s, so reading fails rather than hangs
	// without the limits.
	overflow := func(interval time.Duration, size int) func(*streamWriter) error {
		return func(w *streamWriter) error {
			data := []byte("Content-Length: 5\r\n\r\nhello")
			for start := time.Now(); time.Since(start) < 3*time.Second; data = make([]byte, size) {
				if err := w.writeRecord(Stdout, data); err != nil {
					return err
				}
				time.Sleep(interval)
			}
			return w.writeRecord(EndRequest, make([]byte, 8))
		}
	}

	for _, tc := range []struct {
		name        string
		respond     func(*streamWriter) error
		read        int64 // before Close; more than the body reads it to its end
		readTimeout time.Duration
		max         time.Duration // to read and close
		warn        bool
	}{
		{name: "body partly read", respond: hold("Content-Length: 10\r\n\r\nhello"), read: 5, max: 100 * time.Millisecond},
		{name: "empty body not read", respond: hold("Content-Length: 0\r\n\r\n"), max: 100 * time.Millisecond},
		{name: "flood", respond: overflow(0, 4096), read: 6, max: 500 * time.Millisecond, warn: true},
		{name: "trickle", respond: overflow(20*time.Millisecond, 1), read: 6, max: 1500 * time.Millisecond, warn: true},
		{name: "trickle past read timeout", respond: overflow(20*time.Millisecond, 1), read: 6, readTimeout: 300 * time.Millisecond, max: 800 * time.Millisecond, warn: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr, closed := fcgiResponder(t, tc.respond)
			resp, logs := fcgiRequest(t, addr, http.MethodGet, tc.readTimeout)
			start := time.Now()
			_, _ = io.CopyN(io.Discard, resp.Body, tc.read)
			closing := time.Now()
			resp.Body.Close()
			if took := time.Since(closing); took > 100*time.Millisecond {
				t.Errorf("Close() took %s, want it to return at once", took)
			}
			if took := time.Since(start); took > tc.max {
				t.Errorf("reading and closing took %s, want at most %s", took, tc.max)
			}
			waitClosed(t, closed)

			if got := surplusLogged(t, logs); (got > 0) != tc.warn {
				t.Errorf("surplus_bytes = %d, want a warning: %v", got, tc.warn)
			}
		})
	}
}

// fastcgiProxy serves a reverse proxy to the responder at addr, and returns a
// func that waits for its one request and reports whether the proxy aborted
// the response, which it does by panicking with http.ErrAbortHandler.
func fastcgiProxy(t *testing.T, addr string, http2 bool) (*httptest.Server, *observer.ObservedLogs, func() bool) {
	t.Helper()
	cfgCtx, err := caddy.ProvisionContext(&caddy.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfgCtx.Context = t.Context() // keeps the config, which Handler.Provision needs
	ctx, cancel := caddy.NewContext(cfgCtx)
	t.Cleanup(cancel)
	h := &reverseproxy.Handler{
		TransportRaw: caddyconfig.JSONModuleObject(Transport{Root: "/", ReadTimeout: caddy.Duration(5 * time.Second)}, "protocol", "fastcgi", nil),
		Upstreams:    reverseproxy.UpstreamPool{{Dial: addr}},
	}
	if err := h.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Cleanup() })
	core, logs := observer.New(zapcore.DebugLevel)
	h.Transport.(*Transport).logger = zap.New(core)

	var aborted atomic.Bool
	done := make(chan struct{})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			v := recover()
			aborted.Store(v == http.ErrAbortHandler)
			close(done)
			if v != nil {
				panic(v)
			}
		}()
		r = caddyhttp.PrepareRequest(r, caddy.NewReplacer(), w, &caddyhttp.Server{})
		if err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })); err != nil {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	t.Cleanup(srv.Close)
	srv.EnableHTTP2 = http2
	if http2 {
		srv.StartTLS()
	} else {
		srv.Start()
	}

	return srv, logs, func() bool { <-done; return aborted.Load() }
}

// TestProxyResponseBody checks what clients of the proxy receive over HTTP/1.1
// and HTTP/2. It and its subtests run one at a time because provisioning
// writes package-level state in caddy and reverseproxy.
func TestProxyResponseBody(t *testing.T) {
	for _, proto := range []string{"HTTP/1.1", "HTTP/2.0"} {
		for _, tc := range []struct {
			name     string
			response string
			body     string // and no error, unless shorter
			shorter  bool
			surplus  int
		}{
			{name: "exact", response: "Content-Length: 5\r\n\r\nhello", body: "hello"},
			{name: "excessive", response: "Content-Length: 5\r\n\r\nhello" + extra, body: "hello", surplus: len(extra)},
			{name: "shorter", response: "Content-Length: 10\r\n\r\nhello", shorter: true},
		} {
			t.Run(proto+"/"+tc.name, func(t *testing.T) {
				addr, closed := fcgiResponder(t, sendRecords(stdout(tc.response)))
				srv, logs, aborted := fastcgiProxy(t, addr, proto == "HTTP/2.0")

				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/index.php", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := srv.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.Proto != proto {
					t.Fatalf("response protocol = %s, want %s", resp.Proto, proto)
				}
				body, err := io.ReadAll(resp.Body)
				if tc.shorter != (err != nil) || !tc.shorter && string(body) != tc.body {
					t.Errorf("ReadAll() = %q, %v; want %q and an error: %v", body, err, tc.body, tc.shorter)
				}
				waitClosed(t, closed)
				if aborted() != tc.shorter {
					t.Errorf("proxy aborted the response: %v, want %v", !tc.shorter, tc.shorter)
				}

				if got := surplusLogged(t, logs); got != int64(tc.surplus) {
					t.Errorf("surplus_bytes = %d, want %d", got, tc.surplus)
				}
				for _, e := range logs.FilterMessage("discarding upstream response bytes beyond the declared Content-Length").All() {
					if req, _ := e.ContextMap()["request"].(map[string]any); req["uri"] != "/index.php" {
						t.Errorf("surplus warning has request %v, want the request URI", req)
					}
				}
			})
		}
	}
}
