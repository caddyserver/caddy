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
