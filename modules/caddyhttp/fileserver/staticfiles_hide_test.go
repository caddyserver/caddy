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
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
)

func TestHiddenPrecompressedSidecar(t *testing.T) {
	root := t.TempDir()
	base := []byte("public response body")
	sidecar := gzipBytes(t, []byte("different hidden body"))
	if err := os.WriteFile(filepath.Join(root, "public.txt"), base, 0o600); err != nil {
		t.Fatal(err)
	}
	hiddenPath := filepath.Join(root, "public.txt.gz")
	if err := os.WriteFile(hiddenPath, sidecar, 0o600); err != nil {
		t.Fatal(err)
	}

	fsrv := FileServer{
		Root:               root,
		Hide:               []string{hiddenPath},
		CanonicalURIs:      new(bool),
		PrecompressedOrder: []string{"gzip"},
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := fsrv.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	fsrv.precompressors = map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}

	w := httptest.NewRecorder()
	r := newPrecompressedRequest(t, "/public.txt")
	r.Header.Set("Accept-Encoding", "gzip")
	if err := fsrv.ServeHTTP(w, r, nil); err != nil {
		t.Fatal(err)
	}
	if got := w.Code; got != http.StatusOK {
		t.Fatalf("status = %d, want %d", got, http.StatusOK)
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want no encoding for a hidden sidecar", got)
	}
	if got := w.Body.Bytes(); !bytes.Equal(got, base) {
		t.Errorf("body = %x, want base file body %x", got, base)
	}
}

func TestBrowseHidesPathQualifiedEntries(t *testing.T) {
	for _, tc := range []struct {
		name       string
		requestURI string
		dirName    string
	}{
		{name: "root", requestURI: "/"},
		{name: "encoded slash and dot segment", requestURI: "/a%2Fb/../", dirName: "a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, tc.dirName)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			hiddenPath := filepath.Join(dir, "secret.txt")
			if err := os.WriteFile(hiddenPath, []byte("hidden body"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "public.txt"), []byte("public body"), 0o600); err != nil {
				t.Fatal(err)
			}

			fsrv := FileServer{Root: root, Hide: []string{hiddenPath}, Browse: &Browse{}}
			ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
			if err := fsrv.Provision(ctx); err != nil {
				t.Fatal(err)
			}

			r := httptest.NewRequest(http.MethodGet, tc.requestURI, nil)
			original := *r
			reqCtx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
			reqCtx = context.WithValue(reqCtx, caddyhttp.OriginalRequestCtxKey, original)
			r = r.WithContext(reqCtx)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			if err := fsrv.ServeHTTP(w, r, nil); err != nil {
				t.Fatal(err)
			}
			if got := w.Code; got != http.StatusOK {
				t.Fatalf("status = %d, want %d", got, http.StatusOK)
			}
			if bytes.Contains(w.Body.Bytes(), []byte("secret.txt")) {
				t.Errorf("browse response includes hidden path: %s", w.Body.String())
			}
			if !bytes.Contains(w.Body.Bytes(), []byte("public.txt")) {
				t.Errorf("browse response omits public path: %s", w.Body.String())
			}
		})
	}
}
