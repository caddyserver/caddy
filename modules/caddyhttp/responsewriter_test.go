package caddyhttp

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type responseWriterSpy interface {
	http.ResponseWriter
	Written() string
	CalledReadFrom() bool
}

var (
	_ responseWriterSpy = (*baseRespWriter)(nil)
	_ responseWriterSpy = (*readFromRespWriter)(nil)
)

// a barebones http.ResponseWriter mock
type baseRespWriter []byte

func (brw *baseRespWriter) Write(d []byte) (int, error) {
	*brw = append(*brw, d...)
	return len(d), nil
}
func (brw *baseRespWriter) Header() http.Header        { return nil }
func (brw *baseRespWriter) WriteHeader(statusCode int) {}
func (brw *baseRespWriter) Written() string            { return string(*brw) }
func (brw *baseRespWriter) CalledReadFrom() bool       { return false }

// an http.ResponseWriter mock that supports ReadFrom
type readFromRespWriter struct {
	baseRespWriter
	called bool
}

func (rf *readFromRespWriter) ReadFrom(r io.Reader) (int64, error) {
	rf.called = true
	return io.Copy(&rf.baseRespWriter, r)
}

func (rf *readFromRespWriter) CalledReadFrom() bool { return rf.called }

type hijackRespWriter struct {
	baseRespWriter
	header http.Header
	status int
	conn   net.Conn
}

func newHijackRespWriter() *hijackRespWriter {
	return &hijackRespWriter{
		header: make(http.Header),
		conn:   stubConn{},
	}
}

func (hrw *hijackRespWriter) Header() http.Header {
	return hrw.header
}

func (hrw *hijackRespWriter) WriteHeader(statusCode int) {
	hrw.status = statusCode
}

func (hrw *hijackRespWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	br := bufio.NewReader(hrw.conn)
	bw := bufio.NewWriter(hrw.conn)
	return hrw.conn, bufio.NewReadWriter(br, bw), nil
}

type stubConn struct{}

func (stubConn) Read(_ []byte) (int, error)       { return 0, io.EOF }
func (stubConn) Write(p []byte) (int, error)      { return len(p), nil }
func (stubConn) Close() error                     { return nil }
func (stubConn) LocalAddr() net.Addr              { return stubAddr("local") }
func (stubConn) RemoteAddr() net.Addr             { return stubAddr("remote") }
func (stubConn) SetDeadline(time.Time) error      { return nil }
func (stubConn) SetReadDeadline(time.Time) error  { return nil }
func (stubConn) SetWriteDeadline(time.Time) error { return nil }

type stubAddr string

func (a stubAddr) Network() string { return "tcp" }
func (a stubAddr) String() string  { return string(a) }

func TestResponseWriterWrapperReadFrom(t *testing.T) {
	tests := map[string]struct {
		responseWriter responseWriterSpy
		wantReadFrom   bool
	}{
		"no ReadFrom": {
			responseWriter: &baseRespWriter{},
			wantReadFrom:   false,
		},
		"has ReadFrom": {
			responseWriter: &readFromRespWriter{},
			wantReadFrom:   true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// what we expect middlewares to do:
			type myWrapper struct {
				*ResponseWriterWrapper
			}

			wrapped := myWrapper{
				ResponseWriterWrapper: &ResponseWriterWrapper{ResponseWriter: tt.responseWriter},
			}

			const srcData = "boo!"
			// hides everything but Read, since strings.Reader implements WriteTo it would
			// take precedence over our ReadFrom.
			src := struct{ io.Reader }{strings.NewReader(srcData)}

			if _, err := io.Copy(wrapped, src); err != nil {
				t.Errorf("%s: Copy() err = %v", name, err)
			}

			if got := tt.responseWriter.Written(); got != srcData {
				t.Errorf("%s: data = %q, want %q", name, got, srcData)
			}

			if tt.responseWriter.CalledReadFrom() != tt.wantReadFrom {
				if tt.wantReadFrom {
					t.Errorf("%s: ReadFrom() should have been called", name)
				} else {
					t.Errorf("%s: ReadFrom() should not have been called", name)
				}
			}
		})
	}
}

func TestResponseWriterWrapperUnwrap(t *testing.T) {
	w := &ResponseWriterWrapper{&baseRespWriter{}}

	if _, ok := w.Unwrap().(*baseRespWriter); !ok {
		t.Errorf("Unwrap() doesn't return the underlying ResponseWriter")
	}
}

func TestResponseRecorderReadFrom(t *testing.T) {
	tests := map[string]struct {
		responseWriter responseWriterSpy
		shouldBuffer   bool
		wantReadFrom   bool
	}{
		"buffered plain": {
			responseWriter: &baseRespWriter{},
			shouldBuffer:   true,
			wantReadFrom:   false,
		},
		"streamed plain": {
			responseWriter: &baseRespWriter{},
			shouldBuffer:   false,
			wantReadFrom:   false,
		},
		"buffered ReadFrom": {
			responseWriter: &readFromRespWriter{},
			shouldBuffer:   true,
			wantReadFrom:   false,
		},
		"streamed ReadFrom": {
			responseWriter: &readFromRespWriter{},
			shouldBuffer:   false,
			wantReadFrom:   true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer

			rr := NewResponseRecorder(tt.responseWriter, &buf, func(status int, header http.Header) bool {
				return tt.shouldBuffer
			})

			const srcData = "boo!"
			// hides everything but Read, since strings.Reader implements WriteTo it would
			// take precedence over our ReadFrom.
			src := struct{ io.Reader }{strings.NewReader(srcData)}

			if _, err := io.Copy(rr, src); err != nil {
				t.Errorf("Copy() err = %v", err)
			}

			wantStreamed := srcData
			wantBuffered := ""
			if tt.shouldBuffer {
				wantStreamed = ""
				wantBuffered = srcData
			}

			if got := tt.responseWriter.Written(); got != wantStreamed {
				t.Errorf("streamed data = %q, want %q", got, wantStreamed)
			}
			if got := buf.String(); got != wantBuffered {
				t.Errorf("buffered data = %q, want %q", got, wantBuffered)
			}

			if tt.responseWriter.CalledReadFrom() != tt.wantReadFrom {
				if tt.wantReadFrom {
					t.Errorf("ReadFrom() should have been called")
				} else {
					t.Errorf("ReadFrom() should not have been called")
				}
			}
		})
	}
}

func TestResponseRecorderSwitchingProtocolsIsHijackAware(t *testing.T) {
	w := newHijackRespWriter()
	var buf bytes.Buffer

	rr := NewResponseRecorder(w, &buf, func(status int, header http.Header) bool {
		return true
	})
	rr.WriteHeader(http.StatusSwitchingProtocols)

	if rr.Buffered() {
		t.Fatal("101 switching protocols response should not remain buffered")
	}
	if rr.Status() != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", rr.Status(), http.StatusSwitchingProtocols)
	}
	if w.status != http.StatusSwitchingProtocols {
		t.Fatalf("underlying status = %d, want %d", w.status, http.StatusSwitchingProtocols)
	}

	hj, ok := rr.(http.Hijacker)
	if !ok {
		t.Fatal("response recorder does not implement http.Hijacker")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		t.Fatalf("Hijack() error = %v", err)
	}
	defer conn.Close()

	if !rr.Hijacked() {
		t.Fatal("response recorder should report hijacked state")
	}
	if !ResponseWriterHijacked(rr) {
		t.Fatal("ResponseWriterHijacked() should report true after hijack")
	}
	if err := rr.WriteResponse(); err != nil {
		t.Fatalf("WriteResponse() after hijack returned error: %v", err)
	}
	if rr.Size() != 0 {
		t.Fatalf("size = %d, want 0 after hijack handshake", rr.Size())
	}
	if got := w.Written(); got != "" {
		t.Fatalf("unexpected buffered body write after hijack: %q", got)
	}
}
