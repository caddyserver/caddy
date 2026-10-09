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

package templates

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestServeHTTPContentLength(t *testing.T) {
	const (
		source   = `{{"hello"}} world`
		rendered = "hello world"
	)

	for _, tc := range []struct {
		name       string
		method     string
		status     int
		wantLength string // empty means the header must be absent
		wantBody   string
	}{
		{name: "GET reports rendered length", method: http.MethodGet, status: http.StatusOK, wantLength: strconv.Itoa(len(rendered)), wantBody: rendered},
		{name: "HEAD drops stale length", method: http.MethodHead, status: http.StatusOK},
		{name: "204 drops stale length", method: http.MethodGet, status: http.StatusNoContent},
		{name: "304 drops stale length", method: http.MethodGet, status: http.StatusNotModified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// next behaves like file_server: it advertises the length of the
			// unrendered template and writes a body only when one is allowed
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", "text/html")
				w.Header().Set("Content-Length", strconv.Itoa(len(source)))
				w.WriteHeader(tc.status)
				if r.Method != http.MethodHead && tc.status == http.StatusOK {
					_, err := w.Write([]byte(source))
					return err
				}
				return nil
			})

			tmpl := &Templates{MIMETypes: []string{"text/html"}}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "/", nil)
			if err := tmpl.ServeHTTP(rec, req, next); err != nil {
				t.Fatalf("ServeHTTP: %v", err)
			}

			if rec.Code != tc.status {
				t.Errorf("expected status %d, got %d", tc.status, rec.Code)
			}
			gotLength, ok := rec.Header()["Content-Length"]
			switch {
			case tc.wantLength == "" && ok:
				t.Errorf("expected no Content-Length, got %q", gotLength)
			case tc.wantLength != "" && rec.Header().Get("Content-Length") != tc.wantLength:
				t.Errorf("expected Content-Length %q, got %q", tc.wantLength, rec.Header().Get("Content-Length"))
			}
			if body := rec.Body.String(); body != tc.wantBody {
				t.Errorf("expected body %q, got %q", tc.wantBody, body)
			}
		})
	}
}
