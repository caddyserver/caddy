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
	"io"
	"net"
	"net/http"
	"testing"
)

func TestHTTPRedirectListenerWrapper(t *testing.T) {
	wrapper := HTTPRedirectListenerWrapper{}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer rawListener.Close()

	wrapped := wrapper.WrapListener(rawListener)
	defer wrapped.Close()

	// Server acceptance loop in background
	go func() {
		for {
			conn, err := wrapped.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				// Read will trigger the redirect or return normal traffic
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	tests := []struct {
		name             string
		rawRequest       string
		expectedStatus   int
		expectedLocation string
	}{
		{
			name:             "origin-form GET",
			rawRequest:       "GET /index.html HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
			expectedStatus:   http.StatusPermanentRedirect,
			expectedLocation: "https://example.com:8443/index.html",
		},
		{
			name:             "origin-form with query preservation",
			rawRequest:       "GET /search?q=caddy&page=2 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
			expectedStatus:   http.StatusPermanentRedirect,
			expectedLocation: "https://example.com:8443/search?q=caddy&page=2",
		},
		{
			name:             "absolute-form HEAD with matching Host",
			rawRequest:       "HEAD http://example.com:8443/resource?filter=active HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
			expectedStatus:   http.StatusPermanentRedirect,
			expectedLocation: "https://example.com:8443/resource?filter=active",
		},
		{
			name:             "absolute-form POST with authority precedence over Host header",
			rawRequest:       "POST http://uri-authority.example:8443/submit?ref=1 HTTP/1.1\r\nHost: header-host.example:8443\r\nContent-Length: 0\r\n\r\n",
			expectedStatus:   http.StatusPermanentRedirect,
			expectedLocation: "https://uri-authority.example:8443/submit?ref=1",
		},
		{
			name:             "asterisk-form OPTIONS mapped to slash",
			rawRequest:       "OPTIONS * HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
			expectedStatus:   http.StatusPermanentRedirect,
			expectedLocation: "https://example.com:8443/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", rawListener.Addr().String())
			if err != nil {
				t.Fatalf("failed to dial: %v", err)
			}
			defer conn.Close()

			if _, err := conn.Write([]byte(tc.rawRequest)); err != nil {
				t.Fatalf("failed to write request: %v", err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("failed to read response: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}

			loc := resp.Header.Get("Location")
			if loc != tc.expectedLocation {
				t.Errorf("expected Location %q, got %q", tc.expectedLocation, loc)
			}
		})
	}
}

func TestHTTPRedirectListenerWrapper_NonHTTPPassthrough(t *testing.T) {
	wrapper := HTTPRedirectListenerWrapper{}
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer rawListener.Close()

	wrapped := wrapper.WrapListener(rawListener)
	defer wrapped.Close()

	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	serverReceived := make(chan []byte, 1)

	go func() {
		conn, err := wrapped.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len(payload))
		n, _ := io.ReadFull(conn, buf)
		serverReceived <- buf[:n]
	}()

	client, err := net.Dial("tcp", rawListener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	if _, err := client.Write(payload); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	got := <-serverReceived
	if string(got) != string(payload) {
		t.Fatalf("expected server to receive raw bytes %v, got %v", payload, got)
	}
}
