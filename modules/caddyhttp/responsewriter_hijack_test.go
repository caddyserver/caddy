package caddyhttp

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// hijackableRecorder is an http.ResponseWriter that implements http.Hijacker the
// way net/http does. This matters: after a successful Hijack the real
// (*http.response) has released its bufio.Writer (w.w = nil) and requires
// Write/WriteHeader to return ErrHijacked. FlushError, however, dereferences
// that writer without checking for the hijack, so flushing afterwards is not
// merely wrong, it is a nil pointer dereference.
type hijackableRecorder struct {
	header http.Header

	hijacked bool
	flushed  int
}

func newHijackableRecorder() *hijackableRecorder {
	return &hijackableRecorder{header: make(http.Header)}
}

func (h *hijackableRecorder) Header() http.Header { return h.header }

func (h *hijackableRecorder) WriteHeader(int) {
	if h.hijacked {
		return
	}
}

func (h *hijackableRecorder) Write(p []byte) (int, error) {
	if h.hijacked {
		return 0, http.ErrHijacked
	}
	return len(p), nil
}

// Flush mirrors stdlib (*http.response).FlushError: it does not consult the
// hijack state, which is exactly how the regression in #8151 becomes a panic.
func (h *hijackableRecorder) Flush() {
	if h.hijacked {
		panic("runtime error: invalid memory address or nil pointer dereference")
	}
	h.flushed++
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	c1, c2 := net.Pipe()
	go func() { _ = c2.Close(); _ = c1.Close() }()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

// flushAfterHijack models the deferred flush in Server.ServeHTTP. Server side it
// reads:
//
//	flushErr := http.NewResponseController(wrec).Flush()
//	if flushErr != nil &&
//	    !errors.Is(flushErr, http.ErrHijacked) &&
//	    !errors.Is(flushErr, http.ErrNotSupported) {
//	        writeErr = flushErr
//	}
//
// so it already expects ErrHijacked from a hijacked connection.
func flushAfterHijack(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("flushing a hijacked response panicked: %v", rec)
		}
	}()
	err := http.NewResponseController(w).Flush()
	if err != nil && !errors.Is(err, http.ErrHijacked) {
		t.Fatalf("expected http.ErrHijacked or nil from a hijacked response, got %v", err)
	}
}

// TestResponseRecorderFlushAfterHijack is the regression test for
// caddyserver/caddy#8151.
//
// Since #7945, Server.ServeHTTP defers a flush so the access log can observe a
// write error. When the handler hijacked the connection (reverse_proxy passing
// through a 101 Switching Protocols upgrade) and the upgraded stream outlives
// write_timeout, that deferred flush runs after the hijack, reaches net/http and
// panics with a nil pointer dereference.
//
// The recorder must remember the hijack and report it from FlushError.
func TestResponseRecorderFlushAfterHijack(t *testing.T) {
	underlying := newHijackableRecorder()

	// nil shouldBuffer means the recorder streams straight to the underlying
	// writer, the mode an upgraded reverse_proxy response uses.
	rec := NewResponseRecorder(underlying, nil, nil).(*responseRecorder)

	// reverse_proxy writes the 101 Switching Protocols status before hijacking;
	// WriteHeader is what puts the recorder into streaming mode (rr.stream), and
	// streaming mode is the branch of FlushError that reaches net/http.
	rec.WriteHeader(http.StatusSwitchingProtocols)

	if _, _, err := rec.Hijack(); err != nil {
		t.Fatalf("Hijack() returned unexpected error: %v", err)
	}

	flushAfterHijack(t, rec)

	if underlying.flushed != 0 {
		t.Fatalf("underlying writer was flushed %d time(s) after the hijack; "+
			"a hijacked response must not be flushed", underlying.flushed)
	}
}

// TestResponseRecorderFlushWithoutHijack guards the control case: the fix must
// not turn FlushError into a no-op for ordinary streamed responses.
func TestResponseRecorderFlushWithoutHijack(t *testing.T) {
	underlying := newHijackableRecorder()
	rec := NewResponseRecorder(underlying, nil, nil).(*responseRecorder)

	// Streaming mode is entered via WriteHeader, as it is for a real response.
	rec.WriteHeader(http.StatusOK)

	if err := http.NewResponseController(rec).Flush(); err != nil {
		t.Fatalf("unexpected error flushing a non-hijacked streamed response: %v", err)
	}
	if underlying.flushed != 1 {
		t.Fatalf("expected exactly 1 flush on the underlying writer, got %d", underlying.flushed)
	}
}

// TestResponseRecorderBufferedFlushUnaffected guards the pre-existing #6144
// behaviour: buffered responses suppress the flush regardless of hijack state.
func TestResponseRecorderBufferedFlushUnaffected(t *testing.T) {
	underlying := newHijackableRecorder()
	alwaysBuffer := func(int, http.Header) bool { return true }
	rec := NewResponseRecorder(underlying, nil, alwaysBuffer).(*responseRecorder)

	rec.WriteHeader(http.StatusOK)
	if !rec.Buffered() {
		t.Fatal("expected a buffered response")
	}
	if err := http.NewResponseController(rec).Flush(); err != nil {
		t.Fatalf("unexpected error flushing a buffered response: %v", err)
	}
	if underlying.flushed != 0 {
		t.Fatalf("a buffered response should suppress the flush, got %d flush(es)", underlying.flushed)
	}
}

// TestServerServeHTTPDeferredFlushAfterHijack drives the real Server.ServeHTTP
// path end to end, which is where the panic was observed: an upgraded connection
// that outlives write_timeout is flushed from the deferred func after the
// handler hijacked the connection.
func TestServerServeHTTPDeferredFlushAfterHijack(t *testing.T) {
	underlying := newHijackableRecorder()

	const handlerDuration = 5 * time.Millisecond

	handler := HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// reverse_proxy passes a 101 through, then hijacks. Writing the status
		// first is what selects the recorder's streaming branch.
		w.WriteHeader(http.StatusSwitchingProtocols)

		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("recorder does not implement http.Hijacker")
			return nil
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack failed: %v", err)
			return nil
		}
		defer conn.Close()
		// The upgrade outlives write_timeout, which is what makes the deferred
		// flush run at all.
		time.Sleep(handlerDuration)
		return nil
	})

	srv := &Server{
		primaryHandlerChain: handler,
		WriteTimeout:        caddy.Duration(time.Millisecond),
		Logs:                &ServerLogConfig{},
	}
	// Field names are unexported; set them directly as the tests in this package do.
	srv.logger = zap.NewNop()
	srv.errorLogger = zap.NewNop()
	srv.accessLogger = zap.NewNop()

	r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	r.ProtoMajor, r.ProtoMinor = 1, 1

	// Record the panic so the failure names the regression rather than the test
	// binary crashing.
	panicked := make(chan any, 1)
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				panicked <- rec
			}
		}()
		srv.ServeHTTP(underlying, r)
	}()

	select {
	case rec := <-panicked:
		t.Fatalf("ServeHTTP panicked after an upgraded connection outlived write_timeout: %v", rec)
	default:
	}

	if !underlying.hijacked {
		t.Fatal("handler did not hijack the connection; test did not exercise the upgrade path")
	}
	if underlying.flushed != 0 {
		t.Fatalf("deferred flush reached the hijacked writer %d time(s)", underlying.flushed)
	}
}
