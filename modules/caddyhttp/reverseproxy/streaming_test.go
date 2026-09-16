package reverseproxy

import (
	"bytes"
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
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

	copier := switchProtocolCopier{
		user:       nopReadWriteCloser{Reader: strings.NewReader("hello")},
		backend:    nopReadWriteCloser{Writer: &dst},
		wg:         &wg,
		bufferSize: 7,
	}

	buf := copier.buffer()
	if got := len(buf); got != 7 {
		t.Fatalf("buffer len = %d, want 7", got)
	}

	wg.Add(1)
	go copier.copyToBackend(errc)
	wg.Wait()

	// the destination cannot be half-closed, so a clean copy reports errCopyDone
	if err := <-errc; !errors.Is(err, errCopyDone) {
		t.Fatalf("copyToBackend() error = %v, want %v", err, errCopyDone)
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
			errc := make(chan error, 1)
			copier := switchProtocolCopier{
				user:    nopReadWriteCloser{Reader: strings.NewReader("hello")},
				backend: tc.dst,
				wg:      &wg,
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
	errc := make(chan error, 1)
	wantErr := errors.New("write failed")
	dst := &closeWriteRecorder{writeErr: wantErr}

	copier := switchProtocolCopier{
		user:    nopReadWriteCloser{Reader: strings.NewReader("hello")},
		backend: dst,
		wg:      &wg,
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
