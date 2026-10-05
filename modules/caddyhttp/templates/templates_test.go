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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestServeHTTPErrorDeletesFileHeaders(t *testing.T) {
	for i, tc := range []struct {
		body       string
		wantStatus int
	}{
		{body: `{{httpError 404}}`, wantStatus: http.StatusNotFound},
		{body: `{{nosuchfunc}}`, wantStatus: http.StatusInternalServerError},
		{body: `{{include "missing.html"}}`, wantStatus: http.StatusInternalServerError},
	} {
		tmpl := &Templates{MIMETypes: defaultMIMETypes}
		next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Length", "123")
			w.Header().Set("Etag", `"abc"`)
			w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
			w.Header().Set("Accept-Ranges", "bytes")
			_, err := w.Write([]byte(tc.body))
			return err
		})

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/index.html", nil)

		err := tmpl.ServeHTTP(w, r, next)
		handlerErr, ok := errors.AsType[caddyhttp.HandlerError](err)
		if !ok {
			t.Fatalf("Test %d: expected a handler error, got %v", i, err)
		}
		if handlerErr.StatusCode != tc.wantStatus {
			t.Errorf("Test %d: expected status %d, got %d", i, tc.wantStatus, handlerErr.StatusCode)
		}
		for _, name := range []string{"Content-Length", "Content-Type", "Etag", "Last-Modified", "Accept-Ranges"} {
			if got := w.Header().Get(name); got != "" {
				t.Errorf("Test %d: expected %s to be deleted, got %q", i, name, got)
			}
		}
	}
}
