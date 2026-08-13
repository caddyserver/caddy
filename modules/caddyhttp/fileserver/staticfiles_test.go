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
	"crypto/sha256"
	"encoding/base64"
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

func TestContentDigestExactValues(t *testing.T) {
	fsrv := FileServer{
		ContentDigest: []string{"sha-256", "sha-512"},
	}
	content := []byte("hello world")
	rs := bytes.NewReader(content)

	// "hello world" sha256 base64: uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=
	// "hello world" sha512 base64: MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9yab572QcvMFTBLFvhNBWB2zavfE1TXfG7wQ==
	wantSHA256 := "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
	wantSHA512 := "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw=="

	digest := fsrv.calculateContentDigest(rs, nil, int64(len(content)))
	want := fmt.Sprintf("sha-256=:%s:, sha-512=:%s:", wantSHA256, wantSHA512)
	if digest != want {
		t.Errorf("calculateContentDigest = %q, want %q", digest, want)
	}
}

func TestContentDigestIntegration(t *testing.T) {
	root := t.TempDir()
	content := []byte("caddy server content digest test payload")
	if err := os.WriteFile(filepath.Join(root, "file.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	sidecar := gzipBytes(t, []byte("caddy server content digest test payload"))
	if err := os.WriteFile(filepath.Join(root, "file.txt.gz"), sidecar, 0o600); err != nil {
		t.Fatal(err)
	}

	fsrv := FileServer{
		Root:               root,
		CanonicalURIs:      new(bool),
		ContentDigest:      []string{"sha-256"},
		PrecompressedOrder: []string{"gzip"},
	}

	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := fsrv.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	fsrv.precompressors = map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}

	// Full content sha-256: "caddy server content digest test payload" -> Base64
	hFull := sha256.Sum256(content)
	fullDigestWant := "sha-256=:" + base64.StdEncoding.EncodeToString(hFull[:]) + ":"

	t.Run("GET full request", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/file.txt", nil)
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
		if got := w.Header().Get("Content-Digest"); got != fullDigestWant {
			t.Fatalf("Content-Digest = %q, want %q", got, fullDigestWant)
		}
	})

	t.Run("HEAD request", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodHead, "/file.txt", nil)
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
		if got := w.Header().Get("Content-Digest"); got != fullDigestWant {
			t.Fatalf("Content-Digest = %q, want %q", got, fullDigestWant)
		}
	})

	t.Run("206 Partial Content range request", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/file.txt", nil)
		r.Header.Set("Range", "bytes=6-11")
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusPartialContent {
			t.Fatalf("status = %d, want 206", got)
		}

		// RFC 9530: Digest on 206 must cover the selected representation range "server"
		rangeBytes := content[6:12]
		hRange := sha256.Sum256(rangeBytes)
		wantRangeDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(hRange[:]) + ":"

		if got := w.Header().Get("Content-Digest"); got != wantRangeDigest {
			t.Fatalf("Content-Digest = %q, want %q", got, wantRangeDigest)
		}
	})

	t.Run("304 Not Modified request", func(t *testing.T) {
		// First get Etag
		w1 := httptest.NewRecorder()
		r1 := httptest.NewRequest(http.MethodGet, "/file.txt", nil)
		r1 = r1.WithContext(context.WithValue(r1.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
		_ = fsrv.ServeHTTP(w1, r1, nil)
		etag := w1.Header().Get("Etag")

		// Send conditional request
		w2 := httptest.NewRecorder()
		r2 := httptest.NewRequest(http.MethodGet, "/file.txt", nil)
		r2.Header.Set("If-None-Match", etag)
		r2 = r2.WithContext(context.WithValue(r2.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))

		if err := fsrv.ServeHTTP(w2, r2, nil); err != nil {
			t.Fatal(err)
		}
		if got := w2.Code; got != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", got)
		}
		if got := w2.Header().Get("Content-Digest"); got != fullDigestWant {
			t.Fatalf("Content-Digest on 304 = %q, want %q", got, fullDigestWant)
		}
	})

	t.Run("Precompressed gzip request", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/file.txt", nil)
		r.Header.Set("Accept-Encoding", "gzip")
		r = r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}

		// Content-Digest for precompressed sidecar must match sidecar bytes digest
		hSidecar := sha256.Sum256(sidecar)
		wantSidecarDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(hSidecar[:]) + ":"
		if got := w.Header().Get("Content-Digest"); got != wantSidecarDigest {
			t.Fatalf("Content-Digest precompressed = %q, want %q", got, wantSidecarDigest)
		}
	})
}
