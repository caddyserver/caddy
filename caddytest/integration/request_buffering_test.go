package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
	"golang.org/x/net/http2"
)

// Exercise the actual FastCGI transport and Caddyfile shortcut, including
// unknown-length HTTP/1.1 and HTTP/2 uploads and errors routed through handle_errors.
func TestFastCGIRequestBuffering(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var calls atomic.Int64
	go func() {
		_ = fcgi.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if r.ContentLength != int64(len(body)) {
				http.Error(w, "wrong CONTENT_LENGTH", 500)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
		}))
	}()

	dir := t.TempDir()
	for _, tc := range []struct {
		name, buffering, extra string
		size                   int
		known, http2           bool
		status                 int
	}{
		{name: "disabled", size: 9000, status: 411},
		{name: "disabled known length", size: 9000, known: true, status: 200},
		{name: "memory", buffering: "request_buffering", size: 12, status: 200},
		{name: "disk", buffering: "request_buffering", size: 17000, status: 200},
		{name: "HTTP2 disk", buffering: "request_buffering", size: 17000, http2: true, status: 200},
		{name: "exact limit", buffering: "request_buffering {\n memory 4KiB\n max_size 16KiB\n max_disk 16KiB\n}", size: 16384, status: 200},
		{name: "over limit", buffering: "request_buffering {\n memory 4KiB\n max_size 16KiB\n}", size: 16385, status: 413},
		{name: "known length bypass", buffering: "request_buffering {\n max_size 4KiB\n}", size: 9000, known: true, status: 200},
		{name: "request_body limit", buffering: "request_buffering", extra: "request_body {\n max_size 8KiB\n}", size: 9000, status: 413},
		{name: "disk budget", buffering: "request_buffering {\n memory 4KiB\n max_disk 8KiB\n}", size: 9000, status: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Add a temporary directory to configured buffering, keeping defaults
			// otherwise. php_fastcgi passes this option to the reverse_proxy handler.
			buffering := tc.buffering
			if buffering == "request_buffering" {
				buffering = fmt.Sprintf("request_buffering {\n temp_dir %q\n}", dir)
			} else if buffering != "" {
				buffering = strings.Replace(buffering, "request_buffering {", "request_buffering {\n temp_dir "+strconv.Quote(dir), 1)
			}
			tester := caddytest.NewTester(t)
			tester.InitServer(fmt.Sprintf(`
{
 admin localhost:2999
 servers {
  protocols h1 h2c
 }
}
http://localhost:9080 {
 %s
 php_fastcgi %s {
  %s
 }
 handle_errors {
  respond "buffer-error-{err.status_code}" {err.status_code}
 }
}
`, tc.extra, listener.Addr(), buffering), "caddyfile")
			payload := strings.Repeat("x", tc.size)
			var reader io.Reader = strings.NewReader(payload)
			if !tc.known {
				reader = io.NopCloser(reader)
			}
			req, err := http.NewRequest(http.MethodPost, "http://localhost:9080/index.php", reader)
			if err != nil {
				t.Fatal(err)
			}
			before := calls.Load()
			client := tester.Client
			if tc.http2 {
				transport := &http2.Transport{AllowHTTP: true, DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}}
				defer transport.CloseIdleConnections()
				client = &http.Client{Transport: transport, Timeout: caddytest.Default.TestRequestTimeout}
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if tc.http2 && resp.ProtoMajor != 2 {
				t.Errorf("protocol = %s, want HTTP/2", resp.Proto)
			}
			if resp.StatusCode != tc.status {
				t.Fatalf("status=%d body=%q", resp.StatusCode, body)
			}
			want := payload
			if tc.status != 200 {
				want = fmt.Sprintf("buffer-error-%d", tc.status)
				if calls.Load() != before {
					t.Error("rejected upload reached FastCGI")
				}
			}
			if string(body) != want {
				t.Errorf("response differs: got %d bytes, want %d", len(body), len(want))
			}
			// The client can finish reading before the proxy's cleanup defer
			// runs, so wait briefly for ownership to be released.
			deadline := time.Now().Add(time.Second)
			for {
				files, err := filepath.Glob(filepath.Join(dir, "caddy-request-buffer-*"))
				if err != nil {
					t.Fatal(err)
				}
				if len(files) == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("temporary files remain: %v", files)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
	// No root or PHP installation is needed: the standard FastCGI server above
	// validates CONTENT_LENGTH and echoes the body received over the wire.
}
