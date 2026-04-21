package reverseproxy

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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

	if err := <-errc; err != nil {
		t.Fatalf("copyToBackend() error = %v", err)
	}
	if got := dst.String(); got != "hello" {
		t.Fatalf("copied data = %q, want %q", got, "hello")
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
	ts := newTunnelState(caddy.Log(), 0)
	connA := newTrackingReadWriteCloser()
	connB := newTrackingReadWriteCloser()
	ts.registerConnection(connA, nil, false, "a")
	ts.registerConnection(connB, nil, false, "b")

	h := &Handler{
		tunnel:               ts,
		StreamRetainOnReload: false,
	}

	if err := h.Cleanup(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
	if !connA.isClosed() || !connB.isClosed() {
		t.Fatalf("legacy cleanup should close all upgraded connections")
	}
}

func TestHandlerCleanupLegacyModeHonorsDelay(t *testing.T) {
	ts := newTunnelState(caddy.Log(), 40*time.Millisecond)
	conn := newTrackingReadWriteCloser()
	ts.registerConnection(conn, nil, false, "a")

	h := &Handler{
		tunnel:               ts,
		StreamRetainOnReload: false,
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

func TestHandlerCleanupRetainModeClosesOnlyRemovedUpstreams(t *testing.T) {
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

	ts := newTunnelState(caddy.Log(), 0)
	registerDetachedTunnelStates(ts)
	connA := newTrackingReadWriteCloser()
	connB := newTrackingReadWriteCloser()
	ts.registerConnection(connA, nil, true, upstreamA)
	ts.registerConnection(connB, nil, true, upstreamB)

	h := &Handler{
		tunnel:               ts,
		StreamRetainOnReload: true,
		Upstreams: UpstreamPool{
			&Upstream{Dial: upstreamA},
			&Upstream{Dial: upstreamB},
		},
	}

	if err := h.Cleanup(); err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}

	if connA.isClosed() {
		t.Fatal("connection for retained upstream should remain open")
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
