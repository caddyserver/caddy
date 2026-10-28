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
)

func TestHTTPRedirectListenerLocation(t *testing.T) {
	cases := []struct {
		name    string
		request string
		want    string
	}{
		{
			name:    "origin-form keeps path and query",
			request: "GET /x?q=1 HTTP/1.1\r\nHost: test.localhost:8446\r\n\r\n",
			want:    "https://test.localhost:8446/x?q=1",
		},
		{
			name:    "absolute-form authority takes precedence over Host",
			request: "HEAD http://test.localhost:8446/x?q=1 HTTP/1.1\r\nHost: other.example\r\n\r\n",
			want:    "https://test.localhost:8446/x?q=1",
		},
		{
			name:    "absolute-form POST",
			request: "POST http://test.localhost:8446/x HTTP/1.1\r\nHost: test.localhost:8446\r\nContent-Length: 0\r\n\r\n",
			want:    "https://test.localhost:8446/x",
		},
		{
			name:    "asterisk-form",
			request: "OPTIONS * HTTP/1.1\r\nHost: test.localhost:8446\r\n\r\n",
			want:    "https://test.localhost:8446/",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			wrapped := (&HTTPRedirectListenerWrapper{}).WrapListener(ln)
			t.Cleanup(func() { _ = wrapped.Close() })

			go func() {
				conn, err := wrapped.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				_, _ = conn.Read(make([]byte, 512))
			}()

			client, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := client.Write([]byte(tc.request)); err != nil {
				t.Fatal(err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read redirect: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusPermanentRedirect {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusPermanentRedirect)
			}
			if got := resp.Header.Get("Location"); got != tc.want {
				t.Errorf("Location = %q, want %q", got, tc.want)
			}
		})
	}
}
