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

func TestHasWindowsShortName(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want bool
	}{
		{
			name: "final component",
			path: "/DIRECT~1.TXT",
			want: true,
		},
		{
			name: "parent component with long final filename",
			path: "/PROTEC~1/this-is-a-long-final-filename.txt",
			want: true,
		},
		{
			name: "middle component",
			path: "/public/PROTEC~1/file.txt",
			want: true,
		},
		{
			name: "backslash separator",
			path: `\public\PROTEC~1\file.txt`,
			want: true,
		},
		{
			name: "two digit short name suffix",
			path: "/PROTE~12/file.txt",
			want: true,
		},
		{
			name: "trailing dots and spaces",
			path: "/PROTEC~1.  /file.txt",
			want: true,
		},
		{
			name: "permitted punctuation",
			path: "/$%'-_~1.!#&",
			want: true,
		},
		{
			name: "ordinary tilde name",
			path: "/ordinary~name/file.txt",
			want: false,
		},
		{
			name: "space in short name shape",
			path: "/my f~1.txt",
			want: false,
		},
		{
			name: "space in long tilde name",
			path: "/my file~1.txt",
			want: false,
		},
		{
			name: "non-ASCII short name shape",
			path: "/café~1.txt",
			want: false,
		},
		{
			name: "forbidden punctuation",
			path: "/MY+F~1.TXT",
			want: false,
		},
		{
			name: "tilde followed by non-digit",
			path: "/SHORT~A/file.txt",
			want: false,
		},
		{
			name: "characters after numeric suffix",
			path: "/SHORT~1-file.txt",
			want: false,
		},
		{
			name: "base too long for 8.3",
			path: "/TOOLONG~1/file.txt",
			want: false,
		},
		{
			name: "extension too long for 8.3",
			path: "/SHORT~1.LONG/file.txt",
			want: false,
		},
		{
			name: "multiple extension separators",
			path: "/SHORT~1.T.X/file.txt",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasWindowsShortName(tc.path); got != tc.want {
				t.Fatalf("hasWindowsShortName(%q) = %t, want %t", tc.path, got, tc.want)
			}
		})
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
