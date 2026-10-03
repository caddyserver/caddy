// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyhttp

import (
	"bufio"
	"net"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestHTTPRedirectListenerStatusCode(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statusCode int
		expected   int
	}{
		{name: "default", statusCode: 0, expected: http.StatusPermanentRedirect},
		{name: "301", statusCode: http.StatusMovedPermanently, expected: http.StatusMovedPermanently},
		{name: "302", statusCode: http.StatusFound, expected: http.StatusFound},
		{name: "303", statusCode: http.StatusSeeOther, expected: http.StatusSeeOther},
		{name: "307", statusCode: http.StatusTemporaryRedirect, expected: http.StatusTemporaryRedirect},
		{name: "308", statusCode: http.StatusPermanentRedirect, expected: http.StatusPermanentRedirect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := doHTTPRedirectListenerRequest(t, &HTTPRedirectListenerWrapper{StatusCode: tc.statusCode})
			defer resp.Body.Close()

			if resp.StatusCode != tc.expected {
				t.Errorf("expected status %d, got %d", tc.expected, resp.StatusCode)
			}
			if expected := http.StatusText(tc.expected); resp.Status[4:] != expected {
				t.Errorf("expected status text %q, got %q", expected, resp.Status[4:])
			}
			if loc, expected := resp.Header.Get("Location"), "https://example.com:8443/foo?bar=baz"; loc != expected {
				t.Errorf("expected Location %q, got %q", expected, loc)
			}
		})
	}
}

// doHTTPRedirectListenerRequest sends a plaintext HTTP request to a
// listener wrapped by h and returns the response it writes back.
func doHTTPRedirectListenerRequest(t *testing.T, h *HTTPRedirectListenerWrapper) *http.Response {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	wrapped := h.WrapListener(ln)
	t.Cleanup(func() { _ = wrapped.Close() })

	serverErr := make(chan error, 1)
	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_, err = conn.Read(make([]byte, 1))
		serverErr <- err
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	_, err = client.Write([]byte("GET /foo?bar=baz HTTP/1.1\r\nHost: example.com:8443\r\n\r\n"))
	if err != nil {
		t.Fatalf("failed to write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	// the listener must report an error so the connection is closed
	if err := <-serverErr; err == nil {
		t.Error("expected an error from Read after redirecting, got nil")
	}

	return resp
}

func TestHTTPRedirectListenerWrapperValidate(t *testing.T) {
	for _, code := range []int{0, 301, 302, 303, 307, 308} {
		if err := (&HTTPRedirectListenerWrapper{StatusCode: code}).Validate(); err != nil {
			t.Errorf("status code %d: unexpected error: %v", code, err)
		}
	}
	for _, code := range []int{200, 300, 304, 305, 306, 309, 404} {
		if err := (&HTTPRedirectListenerWrapper{StatusCode: code}).Validate(); err == nil {
			t.Errorf("status code %d: expected an error, got nil", code)
		}
	}
}

func TestHTTPRedirectListenerWrapperUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		input      string
		shouldErr  bool
		statusCode int
	}{
		{input: `http_redirect`, statusCode: 0},
		{input: `http_redirect {
			status_code 307
		}`, statusCode: 307},
		{input: `http_redirect {
			status_code 301
		}`, statusCode: 301},
		{input: `http_redirect 307`, shouldErr: true},
		{input: `http_redirect {
			status_code
		}`, shouldErr: true},
		{input: `http_redirect {
			status_code 307 308
		}`, shouldErr: true},
		{input: `http_redirect {
			status_code 200
		}`, shouldErr: true},
		{input: `http_redirect {
			status_code temporary
		}`, shouldErr: true},
		{input: `http_redirect {
			foo bar
		}`, shouldErr: true},
	} {
		h := new(HTTPRedirectListenerWrapper)
		err := h.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if tc.shouldErr {
			if err == nil {
				t.Errorf("test %d: expected an error, got nil", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("test %d: unexpected error: %v", i, err)
			continue
		}
		if h.StatusCode != tc.statusCode {
			t.Errorf("test %d: expected status code %d, got %d", i, tc.statusCode, h.StatusCode)
		}
	}
}
