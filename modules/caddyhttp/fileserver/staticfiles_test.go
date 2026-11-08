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
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
)

func TestFileHidden(t *testing.T) {
	for i, tc := range []struct {
		inputHide []string
		inputPath string
		expect    bool
	}{
		{
			inputHide: nil,
			inputPath: "",
			expect:    false,
		},
		{
			inputHide: []string{".gitignore"},
			inputPath: "/.gitignore",
			expect:    true,
		},
		{
			inputHide: []string{".git"},
			inputPath: "/.gitignore",
			expect:    false,
		},
		{
			inputHide: []string{"/.git"},
			inputPath: "/.gitignore",
			expect:    false,
		},
		{
			inputHide: []string{".git"},
			inputPath: "/.git",
			expect:    true,
		},
		{
			inputHide: []string{".git"},
			inputPath: "/.git/foo",
			expect:    true,
		},
		{
			inputHide: []string{".git"},
			inputPath: "/foo/.git/bar",
			expect:    true,
		},
		{
			inputHide: []string{"/prefix"},
			inputPath: "/prefix/foo",
			expect:    true,
		},
		{
			inputHide: []string{"/foo/*/bar"},
			inputPath: "/foo/asdf/bar",
			expect:    true,
		},
		{
			inputHide: []string{"*.txt"},
			inputPath: "/foo/bar.txt",
			expect:    true,
		},
		{
			inputHide: []string{"/foo/bar/*.txt"},
			inputPath: "/foo/bar/baz.txt",
			expect:    true,
		},
		{
			inputHide: []string{"/foo/bar/*.txt"},
			inputPath: "/foo/bar.txt",
			expect:    false,
		},
		{
			inputHide: []string{"/foo/bar/*.txt"},
			inputPath: "/foo/bar/index.html",
			expect:    false,
		},
		{
			inputHide: []string{"/foo"},
			inputPath: "/foo",
			expect:    true,
		},
		{
			inputHide: []string{"/foo"},
			inputPath: "/foobar",
			expect:    false,
		},
		{
			inputHide: []string{"first", "second"},
			inputPath: "/second",
			expect:    true,
		},
	} {
		if runtime.GOOS == "windows" {
			if strings.HasPrefix(tc.inputPath, "/") {
				tc.inputPath, _ = filepath.Abs(tc.inputPath)
			}
			tc.inputPath = filepath.FromSlash(tc.inputPath)
			for i := range tc.inputHide {
				if strings.HasPrefix(tc.inputHide[i], "/") {
					tc.inputHide[i], _ = filepath.Abs(tc.inputHide[i])
				}
				tc.inputHide[i] = filepath.FromSlash(tc.inputHide[i])
			}
		}

		actual := fileHidden(tc.inputPath, tc.inputHide)
		if actual != tc.expect {
			t.Errorf("Test %d: Does %v hide %s? Got %t but expected %t",
				i, tc.inputHide, tc.inputPath, actual, tc.expect)
		}
	}
}

// Win32 path normalization strips trailing dots and spaces, so Windows opens
// hidden files under these aliases; fileHidden relies on FastAbs normalizing alike.
func TestHideWindowsTrailingDotSpace(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Win32 path normalization only")
	}

	root := t.TempDir()
	for _, dir := range []string{"publicdir", "secretdir"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"Caddyfile", "public.txt", filepath.Join("publicdir", "p.txt"), filepath.Join("secretdir", "p.txt")} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	canonicalURIs := false
	fsrv := FileServer{
		Root:          root,
		Hide:          []string{"Caddyfile", filepath.Join(root, "secretdir")},
		CanonicalURIs: &canonicalURIs,
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := fsrv.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	for i, tc := range []struct {
		path       string
		wantStatus int
	}{
		{path: "/public.txt.", wantStatus: http.StatusOK},
		{path: "/public.txt%20", wantStatus: http.StatusOK},
		{path: "/publicdir./p.txt", wantStatus: http.StatusOK},
		{path: "/Caddyfile.", wantStatus: http.StatusNotFound},
		{path: "/Caddyfile%20", wantStatus: http.StatusNotFound},
		{path: "/Caddyfile.%20..", wantStatus: http.StatusNotFound},
		{path: "/secretdir./p.txt", wantStatus: http.StatusNotFound},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		w := httptest.NewRecorder()

		status := http.StatusOK
		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			he, ok := errors.AsType[caddyhttp.HandlerError](err)
			if !ok {
				t.Fatalf("Test %d (%s): unexpected error: %v", i, tc.path, err)
			}
			status = he.StatusCode
		}
		if status != tc.wantStatus {
			t.Errorf("Test %d (%s): expected status %d, got %d (body %q)", i, tc.path, tc.wantStatus, status, w.Body.String())
		}
	}
}

// Check to make sure that we don't serve ETag and Last-Modified headers
// for files with invalid modification times
func TestModTimeHeaders(t *testing.T) {
	check_validator_headers(time.Now(), true, t)
	check_validator_headers(time.Unix(0, 0), false, t)
	check_validator_headers(time.Unix(1, 0), false, t)
	check_validator_headers(time.Unix(2, 0), true, t)
}

func check_validator_headers(modTime time.Time, expect_headers bool, t *testing.T) {
	f := false
	fsrv := FileServer{
		Root:          "./testdata",
		CanonicalURIs: &f,
	}
	w := httptest.NewRecorder()
	r, err := http.NewRequest("GET", "/modtime.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	r = r.WithContext(ctx)

	ctx2, _ := caddy.NewContext(caddy.Context{Context: context.Background()}) // module will be nil by default
	fsrv.Provision(ctx2)

	path := "testdata/modtime.txt"
	os.Chtimes(path, modTime, modTime)

	fsrv.ServeHTTP(w, r, nil)

	if expect_headers {
		if w.Header().Get("ETag") == "" {
			t.Errorf("Didn't get ETag header for file with valid mod time %s", modTime)
		}
		if w.Header().Get("Last-Modified") == "" {
			t.Errorf("Didn't get Last-Modified header for file with valid mod time %s", modTime)
		}
	} else {
		if w.Header().Get("ETag") != "" {
			t.Errorf("Got ETag header for file with invalid mod time %s", modTime)
		}
		if w.Header().Get("Last-Modified") != "" {
			t.Errorf("Got Last-Modified header for file with invalid mod time %s", modTime)
		}
	}
}

// calculateEtag concatenates the base-36 mtime and size with no separator,
// so distinct (mtime, size) pairs can produce the same digit string and
// therefore the same ETag.
func TestCalculateEtagCollision(t *testing.T) {
	fileA := fakeFileInfo{size: 75, modTime: time.Unix(2, 0)}
	fileB := fakeFileInfo{size: 3, modTime: time.Unix(72, 2)}

	etagA := calculateEtag(fileA)
	etagB := calculateEtag(fileB)

	if etagA == etagB {
		t.Fatalf("etag collision: distinct files (size=%d mtime=%s) and (size=%d mtime=%s) both produced ETag %s",
			fileA.size, fileA.modTime, fileB.size, fileB.modTime, etagA)
	}
}

type fakeFileInfo struct {
	size    int64
	modTime time.Time
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return f.modTime }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

func TestPrecompressedRangeResponse(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "range.txt"), []byte("original response body"), 0o600); err != nil {
		t.Fatal(err)
	}

	sidecar := gzipBytes(t, []byte("original response body"))
	if err := os.WriteFile(filepath.Join(root, "range.txt.gz"), sidecar, 0o600); err != nil {
		t.Fatal(err)
	}

	fsrv := FileServer{
		Root:               root,
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

	t.Run("full response", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := newPrecompressedRequest(t, "/range.txt")
		r.Header.Set("Accept-Encoding", "gzip")

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}

		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want %d", got, http.StatusOK)
		}
		if got := w.Header().Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		if got := w.Header().Get("Content-Length"); got != fmt.Sprintf("%d", len(sidecar)) {
			t.Fatalf("Content-Length = %q, want %d", got, len(sidecar))
		}
		if got := w.Header().Get("Vary"); got != "Accept-Encoding" {
			t.Fatalf("Vary = %q, want Accept-Encoding", got)
		}
		if got := w.Body.Bytes(); !bytes.Equal(got, sidecar) {
			t.Fatalf("body len = %d, want len = %d", len(got), len(sidecar))
		}
	})

	t.Run("range response", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := newPrecompressedRequest(t, "/range.txt")
		r.Header.Set("Accept-Encoding", "gzip")
		r.Header.Set("Range", "bytes=2-5")

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}

		if got := w.Code; got != http.StatusPartialContent {
			t.Fatalf("status = %d, want %d", got, http.StatusPartialContent)
		}
		if got := w.Header().Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		wantContentRange := fmt.Sprintf("bytes 2-5/%d", len(sidecar))
		if got := w.Header().Get("Content-Range"); got != wantContentRange {
			t.Fatalf("Content-Range = %q, want %q", got, wantContentRange)
		}
		if got := w.Header().Get("Content-Length"); got != "4" {
			t.Fatalf("Content-Length = %q, want 4", got)
		}
		if got := w.Header().Get("Vary"); got != "Accept-Encoding" {
			t.Fatalf("Vary = %q, want Accept-Encoding", got)
		}
		if got, want := w.Body.Bytes(), sidecar[2:6]; !bytes.Equal(got, want) {
			t.Fatalf("body = %x, want %x", got, want)
		}
	})
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newPrecompressedRequest(t *testing.T, target string) *http.Request {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, target, nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, repl)
	return r.WithContext(ctx)
}

type testPrecompressed struct {
	encoding string
	suffix   string
}

func (p testPrecompressed) AcceptEncoding() string {
	return p.encoding
}

func (p testPrecompressed) Suffix() string {
	return p.suffix
}

// A path below a regular file does not exist, so it is a 404 that pass_thru
// falls through, while a path containing a NUL byte is malformed and is a 400.
func TestServeHTTPStatErrors(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	fsrv := FileServer{Root: root}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := fsrv.Provision(ctx); err != nil {
		t.Fatal(err)
	}

	for i, tc := range []struct {
		path       string
		passThru   bool
		wantStatus int
		wantNext   bool
	}{
		{path: "/file.txt/child", wantStatus: http.StatusNotFound},
		{path: "/file.txt/child", passThru: true, wantNext: true},
		{path: "/file.txt%00", wantStatus: http.StatusBadRequest},
	} {
		fsrv.PassThru = tc.passThru
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		var calledNext bool
		next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			calledNext = true
			return nil
		})

		err := fsrv.ServeHTTP(httptest.NewRecorder(), r, next)
		if tc.wantNext {
			if err != nil || !calledNext {
				t.Errorf("Test %d: expected the next handler, got called=%t err=%v", i, calledNext, err)
			}
			continue
		}
		if he, ok := errors.AsType[caddyhttp.HandlerError](err); !ok || he.StatusCode != tc.wantStatus {
			t.Errorf("Test %d: expected status %d, got %v", i, tc.wantStatus, err)
		}
	}
}

// A trailing slash denotes a directory, so path matchers don't treat
// "/secret.env/" as "*.env"; the file server must not serve the file either.
func TestServeHTTPTrailingSlashOnFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "secret.env"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret.env.gz"), gzipBytes(t, []byte("secret")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "dir", "index.html"), []byte("index"), 0o600); err != nil {
		t.Fatal(err)
	}

	for i, tc := range []struct {
		path           string
		canonical      bool
		acceptEncoding string
		passThru       bool
		wantStatus     int
		wantLocation   string
		wantNext       bool
	}{
		{path: "/secret.env", wantStatus: http.StatusOK},
		{path: "/secret.env/", wantStatus: http.StatusNotFound},
		{path: "/secret.env/./", wantStatus: http.StatusNotFound},
		{path: "/secret.env//", wantStatus: http.StatusNotFound},
		{path: "/secret.env%2F", wantStatus: http.StatusNotFound},
		{path: "/secret.env%5c", wantStatus: http.StatusNotFound},
		{path: "/secret.env%5C", wantStatus: http.StatusNotFound},
		{path: `/secret.env\`, wantStatus: http.StatusNotFound},
		{path: "/secret.env%5c", canonical: true, wantStatus: http.StatusNotFound},
		{path: "/secret.env%5C", canonical: true, wantStatus: http.StatusNotFound},
		{path: `/secret.env\`, canonical: true, wantStatus: http.StatusNotFound},
		{path: "/secret.env/", acceptEncoding: "gzip", wantStatus: http.StatusNotFound},
		{path: "/secret.env/", passThru: true, wantNext: true},
		{path: "/secret.env/", canonical: true, wantStatus: http.StatusPermanentRedirect, wantLocation: "/secret.env"},
		{path: "/dir/", wantStatus: http.StatusOK},
		{path: "/dir", wantStatus: http.StatusOK},
		{path: "/dir/index.html/", wantStatus: http.StatusNotFound},
	} {
		fsrv := FileServer{
			Root:               root,
			CanonicalURIs:      &tc.canonical,
			PassThru:           tc.passThru,
			PrecompressedOrder: []string{"gzip"},
		}
		ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
		if err := fsrv.Provision(ctx); err != nil {
			t.Fatal(err)
		}
		fsrv.precompressors = map[string]encode.Precompressed{
			"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
		}

		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r.Header.Set("Accept-Encoding", tc.acceptEncoding)
		reqCtx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
		reqCtx = context.WithValue(reqCtx, caddyhttp.OriginalRequestCtxKey, *r)
		r = r.WithContext(reqCtx)

		var calledNext bool
		next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			calledNext = true
			return nil
		})

		w := httptest.NewRecorder()
		err := fsrv.ServeHTTP(w, r, next)
		cancel()

		if tc.wantNext {
			if err != nil || !calledNext {
				t.Errorf("Test %d (%s): expected the next handler, got called=%t err=%v", i, tc.path, calledNext, err)
			}
			continue
		}
		status := w.Code
		if he, ok := errors.AsType[caddyhttp.HandlerError](err); ok {
			status = he.StatusCode
		} else if err != nil {
			t.Errorf("Test %d (%s): unexpected error: %v", i, tc.path, err)
			continue
		}
		if status != tc.wantStatus {
			t.Errorf("Test %d (%s): expected status %d, got %d", i, tc.path, tc.wantStatus, status)
		}
		if got := w.Header().Get("Location"); got != tc.wantLocation {
			t.Errorf("Test %d (%s): expected Location %q, got %q", i, tc.path, tc.wantLocation, got)
		}
	}
}

// The trailing separator of a filesystem root such as "/" or `C:\` must be
// kept, else `C:` resolves to the current directory of the drive.
func TestServeHTTPFilesystemRoot(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	volume := filepath.VolumeName(wd)
	// top-level directory leading to wd, listed only if the root is served
	topDir := strings.Split(strings.TrimPrefix(wd[len(volume):], separator), separator)[0]

	roots := []string{volume + separator}
	if runtime.GOOS == "windows" {
		roots = append(roots, separator)
	}
	for _, root := range roots {
		t.Run(root, func(t *testing.T) {
			fsrv := FileServer{Root: root, Browse: &Browse{}}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()
			if err := fsrv.Provision(ctx); err != nil {
				t.Fatal(err)
			}

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			reqCtx := context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
			reqCtx = context.WithValue(reqCtx, caddyhttp.OriginalRequestCtxKey, *r)
			r = r.WithContext(reqCtx)
			r.Header.Set("Accept", "application/json")
			w := httptest.NewRecorder()
			if err := fsrv.ServeHTTP(w, r, nil); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
			}

			var items []struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
				t.Fatal(err)
			}
			for _, item := range items {
				if strings.TrimSuffix(item.Name, "/") == topDir {
					return
				}
			}
			t.Errorf("listing of %q doesn't contain %q: %s", root, topDir, w.Body.String())
		})
	}
}
