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

package fastcgi

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// cgiBackend answers one FastCGI request with stdout as the raw CGI response,
// the way fcgiwrap passes on what a CGI script prints.
func cgiBackend(t *testing.T, stdout string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		w := &streamWriter{c: &client{rwc: conn, reqID: 1}, buf: new(bytes.Buffer), recType: Stdout}
		if _, err := w.Write([]byte(stdout)); err != nil {
			return
		}
		if err := w.FlushStream(); err != nil {
			return
		}
		if err := w.writeRecord(EndRequest, make([]byte, 8)); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, conn)
	}()

	return ln.Addr().String()
}

func TestResponseStatus(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   int
	}{
		{
			name:   "no status",
			stdout: "Content-Type: text/plain\r\n\r\nhello",
			want:   http.StatusOK,
		},
		{
			name:   "location without status",
			stdout: "Location: https://example.com/new\r\n\r\n",
			want:   http.StatusFound,
		},
		{
			name:   "location with status",
			stdout: "Status: 301 Moved Permanently\r\nLocation: https://example.com/new\r\n\r\n",
			want:   http.StatusMovedPermanently,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := cgiBackend(t, tt.stdout)
			req := httptest.NewRequest(http.MethodGet, "http://example.com/index.php", nil)

			res, err := fcgiRoundTrip(t, addr, req)
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			if res.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", res.StatusCode, tt.want)
			}
		})
	}
}
