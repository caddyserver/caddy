package integration

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// lateBodies receives request bodies that lateBodyReadHandler leaves to be
// read after its ServeHTTP has returned.
var lateBodies = make(chan io.ReadCloser, 1)

// lateBodyReadHandler is a test-only handler that responds without reading
// the request body and hands the body off to be read after the handler
// returns, like the reverse proxy transport does when an upstream responds
// before consuming the whole request body.
type lateBodyReadHandler struct{}

func (lateBodyReadHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.late_body_read_test",
		New: func() caddy.Module { return new(lateBodyReadHandler) },
	}
}

func (lateBodyReadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	lateBodies <- r.Body
	_, err := w.Write([]byte("ok"))
	return err
}

func init() {
	caddy.RegisterModule(lateBodyReadHandler{})
}

// TestReadBodyIdleAfterHandlerReturns is a regression test for
// https://github.com/caddyserver/caddy/issues/8101: with a read idle
// timeout configured, reading the request body of an HTTP/2 request after
// the handler has returned must not panic. The IdleTimeoutReader used to
// call SetReadDeadline on the HTTP/2 response writer, whose state is
// released once the handler returns, causing a nil pointer dereference.
func TestReadBodyIdleAfterHandlerReturns(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`
	{
		"admin": {
			"listen": "localhost:2999"
		},
		"apps": {
			"http": {
				"grace_period": 1,
				"servers": {
					"srv0": {
						"listen": [":9080"],
						"protocols": ["h1", "h2c"],
						"read_idle_timeout": "10s",
						"routes": [
							{
								"handle": [
									{
										"handler": "late_body_read_test"
									}
								]
							}
						]
					}
				}
			}
		}
	}
	`, "json")

	tr := tester.Client.Transport.(*http.Transport)
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetUnencryptedHTTP2(true)

	resp, err := tester.Client.Post("http://localhost:9080/", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", resp.Proto)
	}
	if string(respBody) != "ok" {
		t.Fatalf("expected response body %q, got %q", "ok", respBody)
	}

	body := <-lateBodies

	// the HTTP/2 server releases the response writer's state right after
	// flushing the response, so give it a moment to finish
	time.Sleep(100 * time.Millisecond)

	if err := readRecovered(body); err != nil {
		t.Fatal(err)
	}
}

// readRecovered reads from r and turns a panic into an error, so a
// regression fails the test instead of crashing the test binary.
func readRecovered(r io.Reader) (err error) {
	defer func() {
		if v := recover(); v != nil {
			err = fmt.Errorf("reading request body after handler returned panicked: %v", v)
		}
	}()
	_, _ = r.Read(make([]byte, 64))
	return nil
}
