package reverseproxy

import (
	"bufio"
	"bytes"
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

	"github.com/caddyserver/caddy/v2"
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
			mustWrite(t, cli, "client sends")
			mustRead(t, srv, "client sends")
			mustReadEOF(t, cli)
		},
		"client close read": func(t *testing.T, cli, srv *net.TCPConn) {
			mustCloseRead(t, cli)
			mustWrite(t, cli, "client sends")
			mustRead(t, srv, "client sends")
		},
		"client close write": func(t *testing.T, cli, srv *net.TCPConn) {
			mustCloseWrite(t, cli)
			mustWrite(t, srv, "backend sends")
			mustRead(t, cli, "backend sends")
			mustReadEOF(t, srv)
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
			h.connections = make(map[io.ReadWriteCloser]openConnection)
			h.connectionsMu = new(sync.Mutex)

			frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
