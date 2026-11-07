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
	"errors"
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

func TestHideRelativeDataDir(t *testing.T) {
	for _, env := range []string{"XDG_DATA_HOME", "HOME", "AppData", "HOMEDRIVE", "HOMEPATH", "USERPROFILE", "home"} {
		t.Setenv(env, "")
	}

	fsrv := FileServer{Root: "."}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := fsrv.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	key := filepath.Join("caddy", "certificates", "local", "localhost", "localhost.key")
	if !fileHidden(key, fsrv.Hide) {
		t.Errorf("%s is not hidden; hide list: %v", key, fsrv.Hide)
	}
	if fileHidden("caddyfile.go", fsrv.Hide) {
		t.Errorf("caddyfile.go is hidden; hide list: %v", fsrv.Hide)
	}
}

func TestHideAlternateSpellings(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Caddyfile"), []byte("hidden config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "secretdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secretdir", "p.txt"), []byte("hidden body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "café.txt"), []byte("hidden body"), 0o600); err != nil {
		t.Fatal(err)
	}

	fsrv := FileServer{
		Root:          root,
		Hide:          []string{filepath.Join(root, "Caddyfile"), "secretdir", "café.txt"},
		CanonicalURIs: new(bool),
	}
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := fsrv.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	for _, uri := range []string{"/Caddyfile", "/caddyfile", "/CADDYFILE", "/secretdir/p.txt", "/SecretDir/p.txt", "/caf%C3%A9.txt", "/cafe%CC%81.txt", "/CAF%C3%89.txt"} {
		t.Run(uri, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, uri, nil)
			original := *r
			reqCtx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
			reqCtx = context.WithValue(reqCtx, caddyhttp.OriginalRequestCtxKey, original)
			r = r.WithContext(reqCtx)
			w := httptest.NewRecorder()
			err := fsrv.ServeHTTP(w, r, nil)
			var handlerErr caddyhttp.HandlerError
			if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusNotFound {
				t.Errorf("got error %v and status %d, want 404", err, w.Code)
			}
		})
	}
}

func TestHideLiteralGlobNames(t *testing.T) {
	for _, tc := range []struct {
		name string
		hide func(root string) string
	}{
		{name: "path", hide: func(root string) string { return filepath.Join(root, "[A]") }},
		{name: "name only", hide: func(string) string { return "[A]" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "[A]"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "[A]", "secret.txt"), []byte("hidden body"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "public.txt"), []byte("public body"), 0o600); err != nil {
				t.Fatal(err)
			}

			fsrv := FileServer{Root: root, Hide: []string{tc.hide(root)}, Browse: &Browse{}}
			ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
			if err := fsrv.Provision(ctx); err != nil {
				t.Fatal(err)
			}

			serve := func(uri string) (*httptest.ResponseRecorder, error) {
				r := httptest.NewRequest(http.MethodGet, uri, nil)
				original := *r
				reqCtx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
				reqCtx = context.WithValue(reqCtx, caddyhttp.OriginalRequestCtxKey, original)
				r = r.WithContext(reqCtx)
				r.Header.Set("Accept", "application/json")
				w := httptest.NewRecorder()
				return w, fsrv.ServeHTTP(w, r, nil)
			}

			w, err := serve("/")
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(w.Body.Bytes(), []byte("[A]")) {
				t.Errorf("browse response includes hidden directory: %s", w.Body.String())
			}
			if !bytes.Contains(w.Body.Bytes(), []byte("public.txt")) {
				t.Errorf("browse response omits public path: %s", w.Body.String())
			}

			for _, uri := range []string{"/%5BA%5D/", "/%5BA%5D/secret.txt"} {
				w, err := serve(uri)
				var handlerErr caddyhttp.HandlerError
				if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusNotFound {
					t.Errorf("%s: got error %v and status %d, want 404", uri, err, w.Code)
				}
			}
		})
	}
}
