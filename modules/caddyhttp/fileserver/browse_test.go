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

package fileserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestBrowsePlainTimeFormat(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "example.txt")
	if err := os.WriteFile(filename, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	modTime := time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(filename, modTime, modTime); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name        string
		layout      string
		wantModTime string
	}{
		{
			name:        "default",
			wantModTime: "January 2, 2024 at 03:04:05",
		},
		{
			name:        "custom",
			layout:      "2006-01-02T15:04:05Z07:00",
			wantModTime: "2024-01-02T03:04:05Z",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsrv := FileServer{
				Root: root,
				Browse: &Browse{
					PlainTimeFormat: tc.layout,
				},
			}
			ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
			if err := fsrv.Provision(ctx); err != nil {
				t.Fatal(err)
			}

			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			req.Header.Set("Accept", "text/plain")
			originalReq := *req
			reqCtx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
			reqCtx = context.WithValue(reqCtx, caddyhttp.OriginalRequestCtxKey, originalReq)
			req = req.WithContext(reqCtx)

			w := httptest.NewRecorder()
			if err := fsrv.ServeHTTP(w, req, nil); err != nil {
				t.Fatal(err)
			}
			if got := w.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
				t.Fatalf("Content-Type = %q, want %q", got, "text/plain; charset=utf-8")
			}
			if !strings.Contains(w.Body.String(), tc.wantModTime) {
				t.Fatalf("response body does not contain modification time %q:\n%s", tc.wantModTime, w.Body.String())
			}
		})
	}
}
