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
	"bytes"
	"io"
	"net"
	"net/http"
	"testing"
)

func sendRawRequestToRedirectListener(t *testing.T, rawReq string) *http.Response {
	t.Helper()

	baseLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	wrapper := HTTPRedirectListenerWrapper{}
	ln := wrapper.WrapListener(baseLn)
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer clientConn.Close()

	if _, err := io.WriteString(clientConn, rawReq); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	rawResp, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("read response failed: %v", err)
	}
	<-done

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(rawResp)), nil)
	if err != nil {
		t.Fatalf("parse response failed (%q): %v", string(rawResp), err)
	}
	return resp
}

func TestHTTPRedirectListenerLocation(t *testing.T) {
	tests := []struct {
		name         string
		rawRequest   string
		wantLocation string
	}{
		{
			name:         "origin-form request",
			rawRequest:   "GET /x HTTP/1.1\r\nHost: test.localhost:8446\r\n\r\n",
			wantLocation: "https://test.localhost:8446/x",
		},
		{
			name:         "origin-form preserves query parameters",
			rawRequest:   "GET /search?q=caddy&page=2 HTTP/1.1\r\nHost: test.localhost:8446\r\n\r\n",
			wantLocation: "https://test.localhost:8446/search?q=caddy&page=2",
		},
		{
			name:         "absolute-form HEAD request",
			rawRequest:   "HEAD http://evil.example/x HTTP/1.1\r\nHost: evil.example\r\n\r\n",
			wantLocation: "https://evil.example/x",
		},
		{
			name:         "absolute-form POST preserves query parameters",
			rawRequest:   "POST http://evil.example/x?foo=bar&baz=1 HTTP/1.1\r\nHost: evil.example\r\nContent-Length: 0\r\n\r\n",
			wantLocation: "https://evil.example/x?foo=bar&baz=1",
		},
		{
			name:         "absolute-form without path defaults to root",
			rawRequest:   "HEAD http://evil.example?foo=bar HTTP/1.1\r\nHost: evil.example\r\n\r\n",
			wantLocation: "https://evil.example/?foo=bar",
		},
		{
			name:         "absolute-form target authority takes precedence over Host header",
			rawRequest:   "HEAD http://authority.example:8446/x?k=v HTTP/1.1\r\nHost: header.example:8446\r\n\r\n",
			wantLocation: "https://authority.example:8446/x?k=v",
		},
		{
			name:         "asterisk-form OPTIONS maps to root",
			rawRequest:   "OPTIONS * HTTP/1.1\r\nHost: test.localhost:8446\r\n\r\n",
			wantLocation: "https://test.localhost:8446/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendRawRequestToRedirectListener(t, tc.rawRequest)
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusPermanentRedirect {
				t.Fatalf("got status %d, want %d", resp.StatusCode, http.StatusPermanentRedirect)
			}
			if got := resp.Header.Get("Location"); got != tc.wantLocation {
				t.Fatalf("got Location %q, want %q", got, tc.wantLocation)
			}
		})
	}
}
