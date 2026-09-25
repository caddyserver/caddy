package integration

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/fcgi"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// TestFastCGIChunkedRequestBody drives the case from caddyserver/caddy#7386: a
// client sending a body with Transfer-Encoding: chunked through a fastcgi
// reverse_proxy over a unix socket.
//
// FastCGI cannot express a body of unknown length — CGI/1.1 requires
// CONTENT_LENGTH, and php-fpm hangs when it is absent or wrong and the body is
// non-empty — so such a body is only forwardable once it has been buffered in
// full. request_buffers is therefore what decides the outcome, and the default
// of 4096 for this transport is far below a git push or a file upload.
func TestFastCGIChunkedRequestBody(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.SkipNow()
	}

	socketName := tempSocketName(t)

	// Report how many body bytes actually arrived, so a truncated body shows up
	// as a failure instead of passing quietly.
	ln, err := net.Listen("unix", socketName)
	if err != nil {
		t.Fatalf("failed to listen on the socket: %s", err)
	}
	go fcgi.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { //nolint:errcheck
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "received %d", n)
	}))
	t.Cleanup(func() { ln.Close() })
	runtime.Gosched()

	const requestBuffers = 4096

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		"admin": {"listen": "localhost:2999"},
		"apps": {
			"pki": {"certificate_authorities": {"local": {"install_trust": false}}},
			"http": {
				"grace_period": 1,
				"servers": {
					"srv0": {
						"listen": [":18080"],
						"routes": [
							{
								"match": [{"path": ["/limited"]}],
								"handle": [{
									"handler": "reverse_proxy",
									"request_buffers": %d,
									"transport": {"protocol": "fastcgi"},
									"upstreams": [{"dial": "unix/%s"}]
								}]
							},
							{
								"match": [{"path": ["/unlimited"]}],
								"handle": [{
									"handler": "reverse_proxy",
									"request_buffers": -1,
									"transport": {"protocol": "fastcgi"},
									"upstreams": [{"dial": "unix/%s"}]
								}]
							}
						]
					}
				}
			}
		}
	}
	`, requestBuffers, socketName, socketName), "json")

	tests := []struct {
		name       string
		path       string
		size       int
		wantStatus int
	}{
		{name: "small body fits the buffer", path: "/limited", size: 16, wantStatus: http.StatusOK},
		{name: "one below the buffer", path: "/limited", size: requestBuffers - 1, wantStatus: http.StatusOK},
		// The body is buffered up to the limit and no further, so its length
		// stays unknown and FastCGI has nothing to put in CONTENT_LENGTH.
		{name: "exactly the buffer", path: "/limited", size: requestBuffers, wantStatus: http.StatusLengthRequired},
		{name: "above the buffer", path: "/limited", size: requestBuffers * 4, wantStatus: http.StatusLengthRequired},
		// Unlimited buffering is the remedy: the whole body is read, so its
		// length is known and the request goes through at any size.
		{name: "above the buffer, buffering unlimited", path: "/unlimited", size: requestBuffers * 4, wantStatus: http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Repeat("x", tc.size)
			// A strings.Reader would let net/http size the body; wrapping it in
			// a bare io.Reader is what makes the request chunked.
			req, err := http.NewRequest(http.MethodPost, "http://localhost:18080"+tc.path, struct{ io.Reader }{strings.NewReader(body)})
			if err != nil {
				t.Fatalf("building request: %s", err)
			}

			resp := tester.AssertResponseCode(req, tc.wantStatus)
			defer resp.Body.Close()
			if tc.wantStatus != http.StatusOK {
				return
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("reading response: %s", err)
			}
			// Every byte has to reach the upstream, not just a buffer's worth.
			if want := fmt.Sprintf("received %d", tc.size); string(got) != want {
				t.Errorf("upstream got %q, want %q", got, want)
			}
		})
	}
}

// tempSocketName borrows a name inside a valid path to bind a unix socket on.
func tempSocketName(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "*.sock")
	if err != nil {
		t.Fatalf("failed to create TempFile: %s", err)
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	t.Cleanup(func() { os.Remove(name) })
	return name
}
