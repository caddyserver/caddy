package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// A timed-out upload must get an error response without sending the remainder
// of its body. HTTP/1 drains unread bodies smaller than 256 KiB before replying;
// clearing the expired read deadline makes that drain wait for the client.
func TestReverseProxyRequestBodyTimeout(t *testing.T) {
	for _, proto := range []int{1, 2} {
		for _, tc := range []struct {
			name     string
			timeouts string
			trickle  bool
			handler  string
		}{
			{"hard stalled", `"read_timeout": 300000000, "read_idle_timeout": 60000000000`, false, ""},
			{"hard trickled", `"read_timeout": 300000000, "read_idle_timeout": 60000000000`, true, ""},
			{"idle stalled", `"read_idle_timeout": 300000000`, false, ""},
			{"minimum rate trickled", `"read_idle_timeout": 300000000, "read_min_rate": 65536`, true, ""},
			{"route stalled", `"read_idle_timeout": 60000000000`, false, `{"handler": "timeouts", "read_timeout": 300000000},`},
		} {
			t.Run(fmt.Sprintf("HTTP%d/%s", proto, tc.name), func(t *testing.T) {
				type uploadResult struct {
					n   int64
					err error
				}
				upstreamRead := make(chan uploadResult, 1)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n, err := io.Copy(io.Discard, r.Body)
					upstreamRead <- uploadResult{n, err}
					w.WriteHeader(http.StatusNoContent)
				}))
				defer upstream.Close()
				tester := caddytest.NewTester(t)
				tester.InitServer(fmt.Sprintf(`{
                    "admin": {"listen": "localhost:2999", "config": {"persist": false}},
                    "apps": {
                        "tls": {"certificates": {"load_files": [{
                            "certificate": "/caddy.localhost.crt", "key": "/caddy.localhost.key"
                        }]}},
                        "http": {"grace_period": 1, "servers": {"srv0": {
                            "listen": ["127.0.0.1:9443"],
                            "automatic_https": {"disable": true},
                            "tls_connection_policies": [{}],
                            %s,
                            "routes": [{"handle": [%s{"handler": "reverse_proxy",
                                "upstreams": [{"dial": %q}]
                            }]}]
                        }}}
                    }
                }`, tc.timeouts, tc.handler, upstream.Listener.Addr().String()), "json")
				if t.Failed() {
					t.FailNow()
				}
				transport := tester.Client.Transport.(*http.Transport)
				if proto == 1 {
					transport.ForceAttemptHTTP2 = false
				}
				defer transport.CloseIdleConnections()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				pr, pw := io.Pipe()
				defer pr.Close()
				defer pw.Close()
				stopClose := context.AfterFunc(ctx, func() { pr.CloseWithError(ctx.Err()) })
				defer stopClose()
				writerDone := make(chan struct{})
				go func() {
					defer close(writerDone)
					if _, err := pw.Write(make([]byte, 1024)); err != nil {
						return
					}
					if !tc.trickle {
						return // Leave the pipe open so the request body stalls.
					}
					ticker := time.NewTicker(25 * time.Millisecond)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							if _, err := pw.Write([]byte("x")); err != nil {
								return
							}
						}
					}
				}()
				defer func() {
					cancel()
					pr.Close()
					<-writerDone
				}()
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://a.caddy.localhost:9443", pr)
				if err != nil {
					t.Fatal(err)
				}
				req.ContentLength = 100 << 10 // Below net/http's post-handler drain limit.
				resp, err := tester.Client.Do(req)
				if err != nil {
					t.Fatalf("did not receive a response to the timed-out upload: %v", err)
				}
				defer resp.Body.Close()
				if resp.ProtoMajor != proto {
					t.Fatalf("got HTTP/%d, want HTTP/%d", resp.ProtoMajor, proto)
				}
				// A read timeout can also cancel the request context, so the proxy
				// can classify it as a canceled request rather than a gateway error.
				if resp.StatusCode != 499 && resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusGatewayTimeout {
					t.Errorf("unexpected timeout response status: %d", resp.StatusCode)
				}
				select {
				case result := <-upstreamRead:
					if result.err == nil || result.n < 1024 || result.n >= req.ContentLength {
						t.Errorf("upstream upload was not interrupted: read %d bytes, error %v", result.n, result.err)
					}
				case <-ctx.Done():
					t.Fatal("upstream upload was not interrupted")
				}
			})
		}
	}
}
