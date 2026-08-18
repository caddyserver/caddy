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
	"crypto/sha512"
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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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

func TestNormalizeContentDigestAlgos(t *testing.T) {
	t.Run("default path keeps order and canonical names", func(t *testing.T) {
		got, err := normalizeContentDigestAlgos([]string{"sha512", "SHA-256", "sha-512", "sha256"})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"sha-512", "sha-256"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	})

	t.Run("rejects unsupported algorithms", func(t *testing.T) {
		_, err := normalizeContentDigestAlgos([]string{"sha-256", "md5"})
		if err == nil {
			t.Fatal("expected error for unsupported algorithm")
		}
		if !strings.Contains(err.Error(), "md5") {
			t.Fatalf("error = %v, want mention of md5", err)
		}
	})

	t.Run("rejects empty algorithm token", func(t *testing.T) {
		_, err := normalizeContentDigestAlgos([]string{""})
		if err == nil {
			t.Fatal("expected error for empty algorithm")
		}
	})
}

func TestContentDigestCaddyfileValidateDedup(t *testing.T) {
	t.Run("validates and deduplicates", func(t *testing.T) {
		input := `file_server {
	content_digest sha256 sha-512 sha-256 SHA512
}`
		d := caddyfile.NewTestDispenser(input)
		var fsrv FileServer
		if err := fsrv.UnmarshalCaddyfile(d); err != nil {
			t.Fatal(err)
		}
		want := []string{"sha-256", "sha-512"}
		if len(fsrv.ContentDigest) != len(want) {
			t.Fatalf("ContentDigest = %v, want %v", fsrv.ContentDigest, want)
		}
		for i := range want {
			if fsrv.ContentDigest[i] != want[i] {
				t.Fatalf("ContentDigest = %v, want %v", fsrv.ContentDigest, want)
			}
		}
	})

	t.Run("default algorithm", func(t *testing.T) {
		input := `file_server {
	digest
}`
		d := caddyfile.NewTestDispenser(input)
		var fsrv FileServer
		if err := fsrv.UnmarshalCaddyfile(d); err != nil {
			t.Fatal(err)
		}
		if len(fsrv.ContentDigest) != 1 || fsrv.ContentDigest[0] != "sha-256" {
			t.Fatalf("ContentDigest = %v, want [sha-256]", fsrv.ContentDigest)
		}
	})

	t.Run("rejects unsupported", func(t *testing.T) {
		input := `file_server {
	content_digest sha-256 blake3
}`
		d := caddyfile.NewTestDispenser(input)
		var fsrv FileServer
		if err := fsrv.UnmarshalCaddyfile(d); err == nil {
			t.Fatal("expected error for unsupported algorithm")
		}
	})
}

func TestFormatContentDigestExactValues(t *testing.T) {
	content := []byte("hello world")

	// Known digests for "hello world" (RFC 9530 sf-binary base64).
	wantSHA256 := "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
	wantSHA512 := "MJ7MSJwS1utMxA9QyQLytNDtd+5RGnx6m808qG1M2G+YndNbxf9JlnDaNCVbRbDP2DDoH2Bdz33FVC6TrpzXbw=="

	digest, err := formatContentDigest([]string{"sha-256", "sha-512"}, content)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("sha-256=:%s:, sha-512=:%s:", wantSHA256, wantSHA512)
	if digest != want {
		t.Errorf("formatContentDigest = %q, want %q", digest, want)
	}
}

func TestFormatContentDigestEmpty(t *testing.T) {
	// SHA-256/512 of empty input (RFC 9530 Appendix B.2 style empty content).
	wantSHA256 := base64.StdEncoding.EncodeToString(sha256.New().Sum(nil))
	wantSHA512 := base64.StdEncoding.EncodeToString(sha512.New().Sum(nil))

	digest, err := formatContentDigest([]string{"sha-256", "sha-512"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("sha-256=:%s:, sha-512=:%s:", wantSHA256, wantSHA512)
	if digest != want {
		t.Fatalf("formatContentDigest(empty) = %q, want %q", digest, want)
	}
}

func TestContentDigestResponseWriterFinalize(t *testing.T) {
	content := []byte("hello world")
	wantSHA256 := "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek="
	want := "sha-256=:" + wantSHA256 + ":"

	t.Run("hashes buffered 200 body", func(t *testing.T) {
		rec := httptest.NewRecorder()
		cd := &contentDigestResponseWriter{ResponseWriter: rec, algos: []string{"sha-256"}}
		cd.WriteHeader(http.StatusOK)
		if _, err := cd.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := cd.finalize(); err != nil {
			t.Fatal(err)
		}
		if got := rec.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
		if got := rec.Header().Get("Content-Digest"); got != want {
			t.Fatalf("Content-Digest = %q, want %q", got, want)
		}
		if !bytes.Equal(rec.Body.Bytes(), content) {
			t.Fatalf("body = %q, want %q", rec.Body.Bytes(), content)
		}
	})

	t.Run("206 hashes partial body only", func(t *testing.T) {
		partial := content[0:5]
		h := sha256.Sum256(partial)
		wantPartial := "sha-256=:" + base64.StdEncoding.EncodeToString(h[:]) + ":"

		rec := httptest.NewRecorder()
		cd := &contentDigestResponseWriter{ResponseWriter: rec, algos: []string{"sha-256"}}
		cd.WriteHeader(http.StatusPartialContent)
		if _, err := cd.Write(partial); err != nil {
			t.Fatal(err)
		}
		if err := cd.finalize(); err != nil {
			t.Fatal(err)
		}
		if got := rec.Header().Get("Content-Digest"); got != wantPartial {
			t.Fatalf("Content-Digest = %q, want %q", got, wantPartial)
		}
		if got := rec.Header().Get("Content-Digest"); got == want {
			t.Fatal("206 digest must not equal full-body digest")
		}
	})

	t.Run("304 omits digest", func(t *testing.T) {
		rec := httptest.NewRecorder()
		cd := &contentDigestResponseWriter{ResponseWriter: rec, algos: []string{"sha-256"}}
		cd.WriteHeader(http.StatusNotModified)
		if err := cd.finalize(); err != nil {
			t.Fatal(err)
		}
		if got := rec.Header().Get("Content-Digest"); got != "" {
			t.Fatalf("Content-Digest = %q, want empty", got)
		}
	})

	t.Run("dynamic Content-Encoding omits digest", func(t *testing.T) {
		rec := httptest.NewRecorder()
		cd := &contentDigestResponseWriter{ResponseWriter: rec, algos: []string{"sha-256"}}
		cd.Header().Set("Content-Encoding", "gzip")
		cd.WriteHeader(http.StatusOK)
		if _, err := cd.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := cd.finalize(); err != nil {
			t.Fatal(err)
		}
		if got := rec.Header().Get("Content-Digest"); got != "" {
			t.Fatalf("Content-Digest = %q, want empty under dynamic encoding", got)
		}
	})

	t.Run("precompress encoding keeps digest", func(t *testing.T) {
		rec := httptest.NewRecorder()
		cd := &contentDigestResponseWriter{
			ResponseWriter: rec,
			algos:          []string{"sha-256"},
			precompress:    "gzip",
		}
		cd.Header().Set("Content-Encoding", "gzip")
		cd.WriteHeader(http.StatusOK)
		if _, err := cd.Write(content); err != nil {
			t.Fatal(err)
		}
		if err := cd.finalize(); err != nil {
			t.Fatal(err)
		}
		if got := rec.Header().Get("Content-Digest"); got != want {
			t.Fatalf("Content-Digest = %q, want %q", got, want)
		}
	})
}

func TestContentDigestIntegration(t *testing.T) {
	root := t.TempDir()
	content := []byte("caddy server content digest test payload")
	if err := os.WriteFile(filepath.Join(root, "file.txt"), content, 0o600); err != nil {
		t.Fatal(err)
	}

	sidecar := gzipBytes(t, content)
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

	hFull := sha256.Sum256(content)
	fullDigestWant := "sha-256=:" + base64.StdEncoding.EncodeToString(hFull[:]) + ":"

	withReplacer := func(r *http.Request) *http.Request {
		return r.WithContext(context.WithValue(r.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
	}

	t.Run("GET full request", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
		if got := w.Header().Get("Content-Digest"); got != fullDigestWant {
			t.Fatalf("Content-Digest = %q, want %q", got, fullDigestWant)
		}
		if !bytes.Equal(w.Body.Bytes(), content) {
			t.Fatalf("body mismatch after digest calculation")
		}
	})

	t.Run("HEAD request uses empty-content digest", func(t *testing.T) {
		// RFC 9530: Content-Digest covers message content. HEAD has an empty
		// body, so the empty-content digest is required (Appendix B.2), not the
		// selected-representation hash (that would be Repr-Digest).
		hEmpty := sha256.Sum256(nil)
		emptyDigestWant := "sha-256=:" + base64.StdEncoding.EncodeToString(hEmpty[:]) + ":"

		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodHead, "/file.txt", nil))

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
		if got := w.Header().Get("Content-Digest"); got != emptyDigestWant {
			t.Fatalf("Content-Digest = %q, want empty-content %q (not full-file %q)", got, emptyDigestWant, fullDigestWant)
		}
		if len(w.Body.Bytes()) != 0 {
			t.Fatalf("HEAD body length = %d, want 0", len(w.Body.Bytes()))
		}
	})

	t.Run("206 Partial Content range request digests selected bytes", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r.Header.Set("Range", "bytes=6-11")

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusPartialContent {
			t.Fatalf("status = %d, want 206", got)
		}

		rangeBytes := content[6:12]
		if !bytes.Equal(w.Body.Bytes(), rangeBytes) {
			t.Fatalf("206 body = %q, want %q", w.Body.Bytes(), rangeBytes)
		}
		hRange := sha256.Sum256(rangeBytes)
		wantRangeDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(hRange[:]) + ":"
		if got := w.Header().Get("Content-Digest"); got != wantRangeDigest {
			t.Fatalf("Content-Digest = %q, want partial %q (not full %q)", got, wantRangeDigest, fullDigestWant)
		}
	})

	t.Run("206 suffix range digests selected bytes", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r.Header.Set("Range", "bytes=-7")

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusPartialContent {
			t.Fatalf("status = %d, want 206", got)
		}
		suffix := content[len(content)-7:]
		if !bytes.Equal(w.Body.Bytes(), suffix) {
			t.Fatalf("206 body = %q, want %q", w.Body.Bytes(), suffix)
		}
		hSuffix := sha256.Sum256(suffix)
		wantSuffixDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(hSuffix[:]) + ":"
		if got := w.Header().Get("Content-Digest"); got != wantSuffixDigest {
			t.Fatalf("Content-Digest = %q, want %q", got, wantSuffixDigest)
		}
	})

	t.Run("304 Not Modified omits Content-Digest", func(t *testing.T) {
		w1 := httptest.NewRecorder()
		r1 := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		if err := fsrv.ServeHTTP(w1, r1, nil); err != nil {
			t.Fatal(err)
		}
		etag := w1.Header().Get("Etag")
		if etag == "" {
			t.Fatal("expected Etag from first response")
		}

		w2 := httptest.NewRecorder()
		r2 := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r2.Header.Set("If-None-Match", etag)

		if err := fsrv.ServeHTTP(w2, r2, nil); err != nil {
			t.Fatal(err)
		}
		if got := w2.Code; got != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", got)
		}
		// 304 has no message content; Content-Digest must not advertise the full-file hash.
		if got := w2.Header().Get("Content-Digest"); got != "" {
			t.Fatalf("Content-Digest on 304 = %q, want empty", got)
		}
	})

	t.Run("If-Range match yields 206 with partial Content-Digest", func(t *testing.T) {
		w1 := httptest.NewRecorder()
		r1 := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		if err := fsrv.ServeHTTP(w1, r1, nil); err != nil {
			t.Fatal(err)
		}
		etag := w1.Header().Get("Etag")
		if etag == "" {
			t.Fatal("expected Etag")
		}

		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r.Header.Set("Range", "bytes=0-5")
		r.Header.Set("If-Range", etag)

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusPartialContent {
			t.Fatalf("status = %d, want 206", got)
		}
		partial := content[0:6]
		if !bytes.Equal(w.Body.Bytes(), partial) {
			t.Fatalf("body = %q, want %q", w.Body.Bytes(), partial)
		}
		hPartial := sha256.Sum256(partial)
		wantPartial := "sha-256=:" + base64.StdEncoding.EncodeToString(hPartial[:]) + ":"
		if got := w.Header().Get("Content-Digest"); got != wantPartial {
			t.Fatalf("Content-Digest = %q, want partial %q", got, wantPartial)
		}
	})

	t.Run("If-Range mismatch yields 200 with full Content-Digest", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r.Header.Set("Range", "bytes=0-5")
		r.Header.Set("If-Range", `"definitely-not-the-etag"`)

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
		if got := w.Header().Get("Content-Digest"); got != fullDigestWant {
			t.Fatalf("Content-Digest = %q, want %q", got, fullDigestWant)
		}
		if !bytes.Equal(w.Body.Bytes(), content) {
			t.Fatalf("body mismatch on If-Range fallback to full content")
		}
	})

	t.Run("invalid Range omits Content-Digest", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r.Header.Set("Range", "bytes=99999-100000")

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusRequestedRangeNotSatisfiable {
			t.Fatalf("status = %d, want 416", got)
		}
		if got := w.Header().Get("Content-Digest"); got != "" {
			t.Fatalf("Content-Digest = %q, want empty for 416", got)
		}
	})

	t.Run("multipart Range digests actual multipart body", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r.Header.Set("Range", "bytes=0-3,6-11")

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		// Digest must cover the exact message content ServeContent wrote (multipart body),
		// not the full source file.
		body := w.Body.Bytes()
		if len(body) == 0 {
			t.Fatal("expected multipart body")
		}
		hBody := sha256.Sum256(body)
		wantBodyDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(hBody[:]) + ":"
		if got := w.Header().Get("Content-Digest"); got != wantBodyDigest {
			t.Fatalf("Content-Digest = %q, want body digest %q (status %d)", got, wantBodyDigest, w.Code)
		}
		if got := w.Header().Get("Content-Digest"); got == fullDigestWant {
			t.Fatalf("multipart Content-Digest must not equal full-file digest")
		}
	})

	t.Run("Precompressed gzip request", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r.Header.Set("Accept-Encoding", "gzip")

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}

		// Content-Digest for precompressed sidecar must match sidecar bytes, not the original file.
		hSidecar := sha256.Sum256(sidecar)
		wantSidecarDigest := "sha-256=:" + base64.StdEncoding.EncodeToString(hSidecar[:]) + ":"
		if got := w.Header().Get("Content-Digest"); got != wantSidecarDigest {
			t.Fatalf("Content-Digest precompressed = %q, want %q", got, wantSidecarDigest)
		}
		if got := w.Header().Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		// Body is the compressed sidecar representation.
		if !bytes.Equal(w.Body.Bytes(), sidecar) {
			t.Fatalf("precompressed body mismatch")
		}
	})

	t.Run("Precompressed with Range digests partial sidecar bytes", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r.Header.Set("Accept-Encoding", "gzip")
		r.Header.Set("Range", "bytes=0-3")

		if err := fsrv.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		if got := w.Code; got != http.StatusPartialContent {
			t.Fatalf("status = %d, want 206", got)
		}
		partialSidecar := sidecar[0:4]
		if !bytes.Equal(w.Body.Bytes(), partialSidecar) {
			t.Fatalf("body = %q, want %q", w.Body.Bytes(), partialSidecar)
		}
		hPartial := sha256.Sum256(partialSidecar)
		wantPartial := "sha-256=:" + base64.StdEncoding.EncodeToString(hPartial[:]) + ":"
		if got := w.Header().Get("Content-Digest"); got != wantPartial {
			t.Fatalf("Content-Digest = %q, want %q", got, wantPartial)
		}
	})

	t.Run("Dynamic Content-Encoding omits Content-Digest", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))

		// Outer middleware (such as caddyhttp/encode) wraps ResponseWriter before calling file_server
		// and sets Content-Encoding header during negotiation / handling.
		outerWrapper := &dynamicCompressResponseWriter{ResponseWriter: w}
		outerWrapper.Header().Set("Content-Encoding", "gzip")

		if err := fsrv.ServeHTTP(outerWrapper, r, nil); err != nil {
			t.Fatal(err)
		}

		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
		if got := w.Header().Get("Content-Digest"); got != "" {
			t.Fatalf("Content-Digest = %q, want empty when dynamic Content-Encoding is present", got)
		}
	})

	t.Run("status override 200 with Range digests partial content path", func(t *testing.T) {
		// Digest follows ServeContent's content path (206 partial bytes) even when a
		// status override will rewrite the client-visible status after finalize.
		override := FileServer{
			Root:          root,
			CanonicalURIs: new(bool),
			ContentDigest: []string{"sha-256"},
			StatusCode:    caddyhttp.WeakString("200"),
		}
		ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
		if err := override.Provision(ctx); err != nil {
			t.Fatal(err)
		}

		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r.Header.Set("Range", "bytes=0-5")

		if err := override.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		// Client-visible status is overridden to 200; body is still the selected range.
		if got := w.Code; got != http.StatusOK {
			t.Fatalf("status = %d, want overridden 200", got)
		}
		partial := content[0:6]
		if !bytes.Equal(w.Body.Bytes(), partial) {
			t.Fatalf("body = %q, want partial %q", w.Body.Bytes(), partial)
		}
		hPartial := sha256.Sum256(partial)
		wantPartial := "sha-256=:" + base64.StdEncoding.EncodeToString(hPartial[:]) + ":"
		if got := w.Header().Get("Content-Digest"); got != wantPartial {
			t.Fatalf("Content-Digest = %q, want partial %q (not full %q)", got, wantPartial, fullDigestWant)
		}
	})

	t.Run("status override 200 with If-None-Match omits digest on 304 path", func(t *testing.T) {
		w1 := httptest.NewRecorder()
		r1 := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		if err := fsrv.ServeHTTP(w1, r1, nil); err != nil {
			t.Fatal(err)
		}
		etag := w1.Header().Get("Etag")
		if etag == "" {
			t.Fatal("expected Etag")
		}

		override := FileServer{
			Root:          root,
			CanonicalURIs: new(bool),
			ContentDigest: []string{"sha-256"},
			StatusCode:    caddyhttp.WeakString("200"),
		}
		ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
		if err := override.Provision(ctx); err != nil {
			t.Fatal(err)
		}

		w := httptest.NewRecorder()
		r := withReplacer(httptest.NewRequest(http.MethodGet, "/file.txt", nil))
		r.Header.Set("If-None-Match", etag)

		if err := override.ServeHTTP(w, r, nil); err != nil {
			t.Fatal(err)
		}
		// ServeContent chose 304 (no body). Digest must stay omitted even if the
		// status override rewrites the client-visible code to 200.
		if len(w.Body.Bytes()) != 0 {
			t.Fatalf("body length = %d, want 0 for conditional not-modified path", len(w.Body.Bytes()))
		}
		if got := w.Header().Get("Content-Digest"); got != "" {
			t.Fatalf("Content-Digest = %q, want empty on 304 content path", got)
		}
	})

	t.Run("Provision rejects unsupported algorithm from JSON config", func(t *testing.T) {
		bad := FileServer{ContentDigest: []string{"sha-256", "md5"}}
		ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
		if err := bad.Provision(ctx); err == nil {
			t.Fatal("expected provision error for unsupported algorithm")
		}
	})
}

type dynamicCompressResponseWriter struct {
	http.ResponseWriter
}

func (d *dynamicCompressResponseWriter) WriteHeader(status int) {
	d.ResponseWriter.Header().Set("Content-Encoding", "gzip")
	d.ResponseWriter.WriteHeader(status)
}

func (d *dynamicCompressResponseWriter) Write(b []byte) (int, error) {
	d.ResponseWriter.Header().Set("Content-Encoding", "gzip")
	return d.ResponseWriter.Write(b)
}
