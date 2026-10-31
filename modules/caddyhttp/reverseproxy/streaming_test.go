package reverseproxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestHandlerCopyResponse(t *testing.T) {
	h := Handler{}
	testdata := []string{
		"",
		strings.Repeat("a", defaultBufferSize),
		strings.Repeat("123456789 123456789 123456789 12", 3000),
	}

	dst := bytes.NewBuffer(nil)
	recorder := httptest.NewRecorder()
	recorder.Body = dst

	for _, d := range testdata {
		src := bytes.NewBuffer([]byte(d))
		dst.Reset()
		err := h.copyResponse(recorder, src, 0, caddy.Log())
		if err != nil {
			t.Errorf("failed with error: %v", err)
		}
		out := dst.String()
		if out != d {
			t.Errorf("bad read: got %q", out)
		}
	}
}

func TestSwitchProtocolCopierBufferSize(t *testing.T) {
	var wg sync.WaitGroup
	var errc = make(chan error, 1)
	var dst bytes.Buffer
	var sent, received int64

	copier := switchProtocolCopier{
		user:       nopReadWriteCloser{Reader: strings.NewReader("hello")},
		backend:    nopReadWriteCloser{Writer: &dst},
		wg:         &wg,
		bufferSize: 7,
		sent:       &sent,
		received:   &received,
	}

	buf := copier.buffer()
	if got := len(buf); got != 7 {
		t.Fatalf("buffer len = %d, want 7", got)
	}

	wg.Add(1)
	go copier.copyToBackend(errc)
	wg.Wait()

	// The destination cannot be half-closed, so a clean copy reports errCopyDone.
	if err := <-errc; !errors.Is(err, errCopyDone) {
		t.Fatalf("copyToBackend() error = %v", err)
	}
	if got := dst.String(); got != "hello" {
		t.Fatalf("copied data = %q, want %q", got, "hello")
	}
}

// A clean EOF in one direction must be propagated to the destination as a
// write-half close instead of tearing the whole tunnel down.
// See https://github.com/caddyserver/caddy/issues/8026.
func TestSwitchProtocolCopierHalfClose(t *testing.T) {
	closeWriteErr := errors.New("no half-close")

	for _, tc := range []struct {
		name    string
		dst     io.ReadWriteCloser
		wantErr error // nil means the half-close was propagated
	}{
		{
			name:    "destination supports CloseWrite",
			dst:     &closeWriteRecorder{},
			wantErr: nil,
		},
		{
			name:    "destination does not support CloseWrite",
			dst:     nopReadWriteCloser{Writer: io.Discard},
			wantErr: errCopyDone,
		},
		{
			name:    "CloseWrite fails",
			dst:     &closeWriteRecorder{err: closeWriteErr},
			wantErr: closeWriteErr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wg sync.WaitGroup
			var sent, received int64
			errc := make(chan error, 1)
			copier := switchProtocolCopier{
				user:     nopReadWriteCloser{Reader: strings.NewReader("hello")},
				backend:  tc.dst,
				wg:       &wg,
				sent:     &sent,
				received: &received,
			}

			wg.Add(1)
			go copier.copyToBackend(errc)
			wg.Wait()

			if err := <-errc; !errors.Is(err, tc.wantErr) {
				t.Fatalf("copyToBackend() error = %v, want %v", err, tc.wantErr)
			}
			if rec, ok := tc.dst.(*closeWriteRecorder); ok && !rec.called {
				t.Fatal("CloseWrite() was not called on a destination that supports it")
			}
		})
	}
}

// A copy error must be reported as-is and must not be mistaken for a clean
// half-close, so the tunnel is still torn down immediately.
func TestSwitchProtocolCopierErrorIsNotHalfClose(t *testing.T) {
	var wg sync.WaitGroup
	var sent, received int64
	errc := make(chan error, 1)
	wantErr := errors.New("write failed")
	dst := &closeWriteRecorder{writeErr: wantErr}

	copier := switchProtocolCopier{
		user:     nopReadWriteCloser{Reader: strings.NewReader("hello")},
		backend:  dst,
		wg:       &wg,
		sent:     &sent,
		received: &received,
	}

	wg.Add(1)
	go copier.copyToBackend(errc)
	wg.Wait()

	if err := <-errc; !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if dst.called {
		t.Fatal("CloseWrite() was called after a copy error")
	}
}

func TestSwitchProtocolCopierDefaultBufferSize(t *testing.T) {
	copier := switchProtocolCopier{}
	buf := copier.buffer()
	if got := len(buf); got != defaultBufferSize {
		t.Fatalf("buffer len = %d, want %d", got, defaultBufferSize)
	}
}

type nopReadWriteCloser struct {
	io.Reader
	io.Writer
}

func (nopReadWriteCloser) Close() error { return nil }

type trackingReadWriteCloser struct {
	closed chan struct{}
	one    sync.Once
}

func newTrackingReadWriteCloser() *trackingReadWriteCloser {
	return &trackingReadWriteCloser{closed: make(chan struct{})}
}

func (c *trackingReadWriteCloser) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *trackingReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (c *trackingReadWriteCloser) Close() error {
	c.one.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *trackingReadWriteCloser) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func TestHandlerCleanupLegacyModeClosesAllConnections(t *testing.T) {
	ts := newTunnelTracker(caddy.Log(), 0)
	connA := newTrackingReadWriteCloser()
	connB := newTrackingReadWriteCloser()
	ts.registerConnection(connA, nil, false, "a")
	ts.registerConnection(connB, nil, false, "b")

	h := &Handler{
		tunnelTracker:  ts,
		StreamDetached: false,
	}

	if err := h.Cleanup(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if !connA.isClosed() || !connB.isClosed() {
		t.Fatalf("legacy cleanup should close all upgraded connections")
	}
}

func TestHandlerCleanupLegacyModeHonorsDelay(t *testing.T) {
	ts := newTunnelTracker(caddy.Log(), 40*time.Millisecond)
	conn := newTrackingReadWriteCloser()
	ts.registerConnection(conn, nil, false, "a")

	h := &Handler{
		tunnelTracker:  ts,
		StreamDetached: false,
	}

	if err := h.Cleanup(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if conn.isClosed() {
		t.Fatal("connection should not close immediately when stream_close_delay is set")
	}

	select {
	case <-conn.closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("connection did not close after stream_close_delay elapsed")
	}
}

func TestHandlerCleanupDetachedModeClosesOnlyRemovedUpstreams(t *testing.T) {
	const upstreamA = "upstream-a"
	const upstreamB = "upstream-b"

	// Simulate old+new configs both referencing upstreamA (refcount 2),
	// while upstreamB is only referenced by the old config (refcount 1).
	hosts.LoadOrStore(upstreamA, struct{}{})
	hosts.LoadOrStore(upstreamA, struct{}{})
	hosts.LoadOrStore(upstreamB, struct{}{})
	t.Cleanup(func() {
		_, _ = hosts.Delete(upstreamA)
		_, _ = hosts.Delete(upstreamA)
		_, _ = hosts.Delete(upstreamB)
	})

	ts := newTunnelTracker(caddy.Log(), 0)
	registerDetachedTunnelTrackers(ts)
	connA := newTrackingReadWriteCloser()
	connB := newTrackingReadWriteCloser()
	ts.registerConnection(connA, nil, true, upstreamA)
	ts.registerConnection(connB, nil, true, upstreamB)

	h := &Handler{
		tunnelTracker:  ts,
		StreamDetached: true,
		Upstreams: UpstreamPool{
			&Upstream{Dial: upstreamA},
			&Upstream{Dial: upstreamB},
		},
	}

	if err := h.Cleanup(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	if connA.isClosed() {
		t.Fatal("connection for detached upstream should remain open")
	}
	if !connB.isClosed() {
		t.Fatal("connection for removed upstream should be closed")
	}
}

func TestHandlerUnmarshalCaddyfileStreamLogsBlock(t *testing.T) {
	d := caddyfile.NewTestDispenser(`
	reverse_proxy localhost:9000 {
		stream_logs {
			level info
			logger_name access
			skip_handshake
		}
	}
	`)

	var h Handler
	if err := h.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile() error = %v", err)
	}
	if h.StreamLogs == nil {
		t.Fatal("expected stream_logs to be configured")
	}
	if h.StreamLogs.Level != "info" {
		t.Fatalf("expected stream_logs.level=info, got %q", h.StreamLogs.Level)
	}
	if h.StreamLogs.LoggerName != "access" {
		t.Fatalf("expected stream_logs.logger_name=access, got %q", h.StreamLogs.LoggerName)
	}
	if !h.StreamLogs.SkipHandshake {
		t.Fatal("expected stream_logs.skip_handshake=true")
	}
}

// closeWriteRecorder is a destination that supports closing only its write
// half, and records whether that happened.
type closeWriteRecorder struct {
	called   bool
	err      error
	writeErr error
}

func (c *closeWriteRecorder) Read([]byte) (int, error) { return 0, io.EOF }

func (c *closeWriteRecorder) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *closeWriteRecorder) Close() error { return nil }

func (c *closeWriteRecorder) CloseWrite() error {
	c.called = true
	return c.err
}

// TestHandlerUpgradedStreamHalfClose drives a real upgraded stream through the
// handler and checks that closing one direction is propagated to the other side
// instead of tearing the whole tunnel down.
//
// It mirrors net/http/httputil's TestReverseProxyWebSocketHalfTCP, which covers
// the same class upstream (https://go.dev/issue/35892). Before the fix, the
// "close write" cases failed: the handler returned as soon as the first
// direction reported, and the deferred closes killed the other direction before
// its pending bytes could be delivered.
//
// See https://github.com/caddyserver/caddy/issues/8026.
func TestHandlerUpgradedStreamHalfClose(t *testing.T) {
	switch runtime.GOOS {
	case "plan9", "js", "wasip1":
		t.Skipf("not supported on %s", runtime.GOOS)
	}

	// Reads carry a deadline so a regression fails the test promptly instead of
	// blocking until the whole package times out.
	const readTimeout = 10 * time.Second

	mustRead := func(t *testing.T, conn *net.TCPConn, msg string) {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			t.Fatalf("failed to set read deadline: %v", err)
		}
		b := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, b); err != nil {
			t.Fatalf("failed to read: %v", err)
		}
		if got, want := string(b), msg; got != want {
			t.Fatalf("got %#q, want %#q", got, want)
		}
	}

	mustReadEOF := func(t *testing.T, conn *net.TCPConn) {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			t.Fatalf("failed to set read deadline: %v", err)
		}
		b := make([]byte, 1)
		if _, err := conn.Read(b); !errors.Is(err, io.EOF) {
			t.Fatalf("read after peer half-close: got %v, want EOF", err)
		}
	}

	mustWrite := func(t *testing.T, conn *net.TCPConn, msg string) {
		t.Helper()
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("failed to write: %v", err)
		}
	}

	mustCloseRead := func(t *testing.T, conn *net.TCPConn) {
		t.Helper()
		if err := conn.CloseRead(); err != nil {
			t.Fatalf("failed to CloseRead: %v", err)
		}
	}

	mustCloseWrite := func(t *testing.T, conn *net.TCPConn) {
		t.Helper()
		if err := conn.CloseWrite(); err != nil {
			t.Fatalf("failed to CloseWrite: %v", err)
		}
	}

	tests := map[string]func(t *testing.T, cli, srv *net.TCPConn){
		"backend close read": func(t *testing.T, cli, srv *net.TCPConn) {
			mustCloseRead(t, srv)
			mustWrite(t, srv, "backend sends")
			mustRead(t, cli, "backend sends")
		},
		"backend close write": func(t *testing.T, cli, srv *net.TCPConn) {
			mustCloseWrite(t, srv)
			mustReadEOF(t, cli)
			mustWrite(t, cli, "client sends")
			mustRead(t, srv, "client sends")
		},
		"client close read": func(t *testing.T, cli, srv *net.TCPConn) {
			mustCloseRead(t, cli)
			mustWrite(t, cli, "client sends")
			mustRead(t, srv, "client sends")
		},
		"client close write": func(t *testing.T, cli, srv *net.TCPConn) {
			mustCloseWrite(t, cli)
			mustReadEOF(t, srv)
			mustWrite(t, srv, "backend sends")
			mustRead(t, cli, "backend sends")
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			srvc := make(chan *net.TCPConn, 1)

			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, _, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Errorf("backend hijack failed: %v", err)
					return
				}
				tcp, ok := conn.(*net.TCPConn)
				if !ok {
					conn.Close()
					t.Errorf("backend conn is %T, want *net.TCPConn", conn)
					return
				}
				if _, err := io.WriteString(tcp, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
					tcp.Close()
					t.Errorf("backend upgrade write failed: %v", err)
					return
				}
				srvc <- tcp
			}))
			defer backend.Close()

			h := minimalHandler(0, &Upstream{
				Host: new(Host),
				Dial: backend.Listener.Addr().String(),
			})
			h.tunnelTracker = newTunnelTracker(caddy.Log(), 0)
			initReverseProxyMetrics(h, prometheus.NewRegistry())

			frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Isolate half-close propagation from request cancellation which has
				// its own backend-close path.
				r = r.WithContext(context.WithoutCancel(r.Context()))
				_ = h.ServeHTTP(w, prepareTestRequest(r), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
					return nil
				}))
			}))
			defer frontend.Close()

			frontendURL, err := url.Parse(frontend.URL)
			if err != nil {
				t.Fatalf("failed to parse frontend URL: %v", err)
			}
			addr, err := net.ResolveTCPAddr("tcp", frontendURL.Host)
			if err != nil {
				t.Fatalf("failed to resolve TCP address: %v", err)
			}
			cli, err := net.DialTCP("tcp", nil, addr)
			if err != nil {
				t.Fatalf("failed to dial frontend: %v", err)
			}
			defer cli.Close()

			req, _ := http.NewRequest(http.MethodGet, frontend.URL, nil)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			if err := req.Write(cli); err != nil {
				t.Fatalf("failed to write upgrade request: %v", err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(cli), &http.Request{Method: http.MethodGet})
			if err != nil {
				t.Fatalf("failed to read upgrade response: %v", err)
			}
			if resp.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("status = %d, want 101", resp.StatusCode)
			}

			var srv *net.TCPConn
			select {
			case srv = <-srvc:
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for the backend connection")
			}
			defer srv.Close()

			test(t, cli, srv)
		})
	}
}

// A response carrying the Incremental header field (RFC 10036) must be
// forwarded without buffering, whatever its Content-Type and Content-Length.
func TestFlushIntervalIncremental(t *testing.T) {
	h := Handler{FlushInterval: caddy.Duration(time.Second)}
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	for _, tc := range []struct {
		name                string
		incremental         string
		receivedIncremental bool
		want                time.Duration
	}{
		{name: "incremental", incremental: "?1", want: -1},
		{name: "not incremental", incremental: "?0", want: time.Second},
		{name: "absent", want: time.Second},
		{name: "removed by header operations", receivedIncremental: true, want: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := &http.Response{
				Header:        http.Header{"Content-Type": []string{"application/json"}},
				ContentLength: 42,
			}
			if tc.incremental != "" {
				res.Header.Set("Incremental", tc.incremental)
			}
			if got := h.flushInterval(req, res, tc.receivedIncremental); got != tc.want {
				t.Errorf("flushInterval() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHandlerCleanupDetachedRemovalWithDelay(t *testing.T) {
	const upstream = "detached-removal-with-delay"
	hosts.LoadOrStore(upstream, new(Host))
	t.Cleanup(func() { _, _ = hosts.Delete(upstream) })
	ts := newTunnelTracker(caddy.Log(), time.Hour)
	registerDetachedTunnelTrackers(ts)
	t.Cleanup(func() { unregisterDetachedTunnelTrackers(ts) })
	detached := newTrackingReadWriteCloser()
	attached := newTrackingReadWriteCloser()
	deleteDetached := ts.registerConnection(detached, nil, true, upstream)
	deleteAttached := ts.registerConnection(attached, nil, false, upstream)
	t.Cleanup(deleteDetached)
	t.Cleanup(deleteAttached)
	h := &Handler{tunnelTracker: ts, StreamDetached: true, Upstreams: UpstreamPool{&Upstream{Dial: upstream}}}
	if err := h.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if !detached.isClosed() {
		t.Error("detached stream remains open after upstream removal")
	}
	if attached.isClosed() {
		t.Error("attached stream closed before stream_close_delay elapsed")
	}
}

func TestHandlerCleanupEmptyDetachedTracker(t *testing.T) {
	for _, delay := range []time.Duration{0, time.Hour} {
		t.Run(delay.String(), func(t *testing.T) {
			ts := newTunnelTracker(caddy.Log(), delay)
			registerDetachedTunnelTrackers(ts)
			t.Cleanup(func() { unregisterDetachedTunnelTrackers(ts) })
			// Cover a tracker whose last connection closed before handler cleanup.
			conn := newTrackingReadWriteCloser()
			ts.registerConnection(conn, nil, true, "upstream")()
			if err := (&Handler{tunnelTracker: ts, StreamDetached: true}).Cleanup(); err != nil {
				t.Fatal(err)
			}
			detachedTunnelTrackersMu.Lock()
			_, retained := detachedTunnelTrackers[ts]
			detachedTunnelTrackersMu.Unlock()
			if retained {
				t.Error("empty tracker remains globally registered after cleanup")
			}
		})
	}
}

func TestDetachedTrackerRemovalAllowsConcurrentConnectionDeletion(t *testing.T) {
	ts := newTunnelTracker(caddy.Log(), 0)
	registerDetachedTunnelTrackers(ts)
	t.Cleanup(func() { unregisterDetachedTunnelTrackers(ts) })
	// An attached stream on another stopped handler can finish while an
	// upstream-removal notification closes a detached stream. Its deletion
	// must be able to acquire the registry lock and release its tracker lock.
	other := newTunnelTracker(caddy.Log(), 0)
	otherConn := newTrackingReadWriteCloser()
	deleteOther := other.registerConnection(otherConn, nil, false, "other")
	if err := other.cleanupAttachedConnections(); err != nil {
		t.Fatal(err)
	}
	deleted := make(chan struct{})
	conn := newTrackingReadWriteCloser()
	del := ts.registerConnection(conn, func() error {
		go func() {
			deleteOther()
			close(deleted)
		}()
		select {
		case <-deleted:
		case <-time.After(time.Second):
			t.Error("upstream removal blocked another connection's deletion")
		}
		return nil
	}, true, "upstream")
	t.Cleanup(del)
	if err := ts.cleanupAttachedConnections(); err != nil {
		t.Fatal(err)
	}
	if err := notifyDetachedTunnelTrackersOfUpstreamRemoval("upstream", ts); err != nil {
		t.Fatal(err)
	}
	// On a regression the notification must release its lock before waiting
	// for deletion, so the failing test does not leave a blocked goroutine.
	<-deleted
	if !conn.isClosed() {
		t.Error("removed upstream connection was not closed")
	}
}

func TestHandlerCleanupDoesNotBlockOnStalledWebsocketPeer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// The peer never reads, so writes to it block once the socket buffers fill
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Small buffers make sure the write below blocks
	_ = conn.(*net.TCPConn).SetWriteBuffer(4096)
	_ = peer.(*net.TCPConn).SetReadBuffer(4096)

	// Stands in for the tunnel's copy goroutine, stuck writing to the peer
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		_, _ = conn.Write(make([]byte, 64<<20))
	}()
	time.Sleep(100 * time.Millisecond)

	ts := newTunnelTracker(caddy.Log(), 0)
	ts.registerConnection(conn, func() error {
		return writeCloseControl(conn, false)
	}, false, "upstream")

	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		_ = ts.cleanupAttachedConnections()
	}()

	select {
	case <-cleanupDone:
	case <-time.After(10 * time.Second):
		t.Fatal("cleanup blocked on a websocket peer that stopped reading")
	}
	select {
	case <-copyDone:
	case <-time.After(10 * time.Second):
		t.Fatal("stalled write was not released")
	}
}

// opaqueUpgradeWriter supports hijacking but hides the recorder from the
// detachment helper, as a middleware wrapper without Unwrap would do.
type opaqueUpgradeWriter struct {
	http.ResponseWriter
}

func (w opaqueUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(w.ResponseWriter).Hijack()
}

type rejectingUpgradeWriter struct {
	*caddyhttp.ResponseWriterWrapper
}

func (rejectingUpgradeWriter) DetachAfterHijack(detached bool) bool {
	return !detached
}

type pipeUpgradeWriter struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w pipeUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestUpgradeDetachmentRequiresWriterSupport(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wrap     func(http.ResponseWriter) http.ResponseWriter
		detached bool
	}{
		{name: "opaque wrapper", wrap: func(w http.ResponseWriter) http.ResponseWriter { return opaqueUpgradeWriter{w} }},
		{name: "inner writer rejects detachment", wrap: func(w http.ResponseWriter) http.ResponseWriter {
			rejecting := rejectingUpgradeWriter{&caddyhttp.ResponseWriterWrapper{ResponseWriter: w}}
			return caddyhttp.NewResponseRecorder(rejecting, nil, nil)
		}},
		{name: "supported recorder", wrap: func(w http.ResponseWriter) http.ResponseWriter { return w }, detached: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			front, client := net.Pipe()
			back, backend := net.Pipe()
			defer front.Close()
			defer client.Close()
			defer back.Close()
			defer backend.Close()
			if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			echoDone := make(chan struct{})
			go func() {
				defer close(echoDone)
				_, _ = io.Copy(backend, backend)
			}()
			h := &Handler{StreamDetached: true, logger: caddy.Log(), tunnelTracker: newTunnelTracker(caddy.Log(), 0)}
			initReverseProxyMetrics(h, prometheus.NewRegistry())
			recorder := caddyhttp.NewResponseRecorder(pipeUpgradeWriter{httptest.NewRecorder(), front}, nil, nil)
			writer := tc.wrap(recorder)
			req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "/upgrade", nil))
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "test-stream")
			res := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: req.Header.Clone(), Body: back}
			handlerDone := make(chan struct{})
			go func() {
				defer close(handlerDone)
				h.handleUpgradeResponse(caddy.Log(), writer, req, res, "detachment-test")
			}()
			const payload = "echo"
			if _, err := io.WriteString(client, payload); err != nil {
				t.Fatal(err)
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(client, received); err != nil {
				t.Fatal(err)
			}
			if string(received) != payload {
				t.Fatalf("echo = %q, want %q", received, payload)
			}
			h.tunnelTracker.mu.Lock()
			for _, conn := range h.tunnelTracker.connections {
				if conn.detached != tc.detached {
					t.Errorf("tracked detached = %v, want %v", conn.detached, tc.detached)
				}
			}
			h.tunnelTracker.mu.Unlock()
			if tc.detached {
				select {
				case <-handlerDone:
				case <-time.After(time.Second):
					t.Error("supported detached tunnel kept the handler running")
				}
			} else {
				select {
				case <-handlerDone:
					t.Error("handler returned while the writer chain remained attached")
				case <-time.After(100 * time.Millisecond):
				}
			}
			client.Close()
			backend.Close()
			select {
			case <-handlerDone:
			case <-time.After(time.Second):
				t.Fatal("handler did not finish after stream close")
			}
			<-echoDone
			// Wait for detached tunnel cleanup too, so no copy goroutine can
			// still be updating counters after this subtest finishes.
			deadline := time.Now().Add(time.Second)
			for {
				h.tunnelTracker.mu.Lock()
				remaining := len(h.tunnelTracker.connections)
				h.tunnelTracker.mu.Unlock()
				if remaining == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("tunnel connections were not unregistered")
				}
				time.Sleep(time.Millisecond)
			}
			// Attached byte counters are safe to inspect after the handler has waited
			// for both copying goroutines. Partial detachment must also be undone.
			if !tc.detached {
				recorders := []caddyhttp.ResponseRecorder{recorder}
				if outer, ok := writer.(caddyhttp.ResponseRecorder); ok {
					recorders = append(recorders, outer)
				}
				for _, rr := range recorders {
					if rr.Size() != len(payload) {
						t.Errorf("attached recorder size = %d, want %d", rr.Size(), len(payload))
					}
				}
			}
		})
	}
}

func TestUpgradeResponseCleanupOnFailure(t *testing.T) {
	body := &closeTrackingBody{Buffer: bytes.NewBufferString("test body")}

	res := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     make(http.Header),
		Body:       body,
	}
	res.Header.Set("Upgrade", "websocket")
	res.Header.Set("Connection", "Upgrade")

	// Request with mismatched upgrade type -> should fail check and close body
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Upgrade", "something-else")
	req.Header.Set("Connection", "Upgrade")

	recorder := httptest.NewRecorder()
	h := &Handler{}
	logger := zap.NewNop()

	h.handleUpgradeResponse(logger, recorder, req, res, "127.0.0.1:8080")

	if !body.closed {
		t.Errorf("expected backend response body to be closed on upgrade protocol mismatch, but it was not")
	}
}

func TestUpgradeResponseCleanupAfterHijack(t *testing.T) {
	for _, tc := range []struct {
		name         string
		flushFailure bool
	}{
		{name: "handshake flush failure", flushFailure: true},
		{name: "buffered backend write failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			front, client := net.Pipe()
			back, backend := net.Pipe()
			for _, conn := range []net.Conn{front, client, back, backend} {
				t.Cleanup(func() { conn.Close() })
			}

			writeFailure := &upgradeWriteErrorConn{writeErr: errors.New("upgrade setup write failed")}
			reader := bufio.NewReader(strings.NewReader(""))
			writer := bufio.NewWriter(front)
			var body io.ReadWriteCloser = back
			var wantWrite string
			if tc.flushFailure {
				writeFailure.Conn = front
				writer = bufio.NewWriter(writeFailure)
				wantWrite = "HTTP/1.1 101 Switching Protocols\r\n\r\n"
				// Flush must have pending bytes; flushing an empty writer
				// never reaches the failing connection's Write method.
				if _, err := writer.WriteString(wantWrite); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFailure.Conn = back
				body = writeFailure
				wantWrite = "buffered client data"
				reader = bufio.NewReader(strings.NewReader(wantWrite))
				// Buffered() must be nonzero before the handler checks it.
				if _, err := reader.Peek(len(wantWrite)); err != nil {
					t.Fatal(err)
				}
			}

			rw := &upgradeFailureHijacker{
				ResponseRecorder: httptest.NewRecorder(),
				conn:             front,
				brw:              bufio.NewReadWriter(reader, writer),
			}
			req := prepareTestRequest(httptest.NewRequest(http.MethodGet, "/upgrade", nil))
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "test-stream")
			res := &http.Response{StatusCode: http.StatusSwitchingProtocols, Header: req.Header.Clone(), Body: body}
			logger := zap.NewNop()
			h := &Handler{logger: logger, tunnelTracker: newTunnelTracker(logger, 0)}
			for _, peer := range []net.Conn{client, backend} {
				if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}

			h.handleUpgradeResponse(logger, rw, req, res, "cleanup-test")

			if !rw.hijacked {
				t.Fatal("setup failed before successful client hijack")
			}
			if writeFailure.writeCalls != 1 || string(writeFailure.written) != wantWrite {
				t.Fatalf("failure injection: got %d writes of %q, want one write of %q",
					writeFailure.writeCalls, writeFailure.written, wantWrite)
			}
			for _, peer := range []struct {
				name string
				conn net.Conn
			}{
				{name: "client", conn: client},
				{name: "backend", conn: backend},
			} {
				var data [1]byte
				if n, err := peer.conn.Read(data[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Errorf("%s peer read = (%d, %v), want (0, EOF) after setup failure", peer.name, n, err)
				}
			}
			if remaining := len(h.tunnelTracker.connections); remaining != 0 {
				t.Errorf("setup failure registered %d tunnel connections", remaining)
			}
		})
	}
}

type upgradeFailureHijacker struct {
	*httptest.ResponseRecorder
	conn     net.Conn
	brw      *bufio.ReadWriter
	hijacked bool
}

func (w *upgradeFailureHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return w.conn, w.brw, nil
}

type upgradeWriteErrorConn struct {
	net.Conn
	writeErr   error
	writeCalls int
	written    []byte
}

func (c *upgradeWriteErrorConn) Write(p []byte) (int, error) {
	c.writeCalls++
	c.written = append(c.written, p...)
	return 0, c.writeErr
}

type closeTrackingBody struct {
	*bytes.Buffer
	closed bool
}

func (c *closeTrackingBody) Close() error {
	c.closed = true
	return nil
}
