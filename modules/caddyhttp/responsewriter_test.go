package caddyhttp

import (
	"bytes"
	"io"
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

// targetIface is an interface that only the innermost writer in the tests
// below implements; it's used to assert UnwrapResponseWriterAs walks past
// outer wrappers to find it.
type targetIface interface {
	http.ResponseWriter
	magic() string
}

type targetWriter struct {
	baseRespWriter
}

func (*targetWriter) magic() string { return "ok" }

// plainWrapper wraps an http.ResponseWriter and forwards only the mandatory
// methods. It implements Unwrap() so the helper can traverse it.
type plainWrapper struct{ inner http.ResponseWriter }

func (p *plainWrapper) Header() http.Header         { return p.inner.Header() }
func (p *plainWrapper) Write(b []byte) (int, error) { return p.inner.Write(b) }
func (p *plainWrapper) WriteHeader(statusCode int)  { p.inner.WriteHeader(statusCode) }
func (p *plainWrapper) Unwrap() http.ResponseWriter { return p.inner }

func TestUnwrapResponseWriterAs_DirectMatch(t *testing.T) {
	w := &targetWriter{}
	got, ok := UnwrapResponseWriterAs[targetIface](w)
	if !ok {
		t.Fatal("expected direct match to succeed")
	}
	if got.magic() != "ok" {
		t.Errorf("unexpected writer returned: %v", got)
	}
}

func TestUnwrapResponseWriterAs_ThroughSingleWrapper(t *testing.T) {
	inner := &targetWriter{}
	outer := &ResponseWriterWrapper{ResponseWriter: inner}
	got, ok := UnwrapResponseWriterAs[targetIface](outer)
	if !ok {
		t.Fatal("expected to unwrap past ResponseWriterWrapper")
	}
	if got.magic() != "ok" {
		t.Error("expected the inner targetWriter")
	}
}

func TestUnwrapResponseWriterAs_ThroughMultipleWrappers(t *testing.T) {
	inner := &targetWriter{}
	w := http.ResponseWriter(&plainWrapper{
		inner: &ResponseWriterWrapper{
			ResponseWriter: &plainWrapper{inner: inner},
		},
	})
	got, ok := UnwrapResponseWriterAs[targetIface](w)
	if !ok {
		t.Fatal("expected to unwrap three layers down")
	}
	if got.magic() != "ok" {
		t.Error("expected the inner targetWriter")
	}
}

func TestUnwrapResponseWriterAs_NotFound(t *testing.T) {
	// None of these writers implement targetIface.
	inner := &baseRespWriter{}
	outer := &ResponseWriterWrapper{ResponseWriter: inner}
	_, ok := UnwrapResponseWriterAs[targetIface](outer)
	if ok {
		t.Error("expected no match when nothing in the chain implements the interface")
	}
}

type selfUnwrapWriter struct{ baseRespWriter }

func (s *selfUnwrapWriter) Unwrap() http.ResponseWriter { return s }

func TestUnwrapResponseWriterAs_StopsOnSelfReference(t *testing.T) {
	// Defensive: a wrapper whose Unwrap returns itself must not loop forever.
	loop := &selfUnwrapWriter{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = UnwrapResponseWriterAs[targetIface](loop)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("UnwrapResponseWriterAs hung on self-referential Unwrap")
	}
}
