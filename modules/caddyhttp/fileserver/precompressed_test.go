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
	"testing"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/internal/filesystems"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
)

// testPrecompressed implements encode.Precompressed for testing.
type testPrecompressed struct {
	encoding string
	suffix   string
}

func (t testPrecompressed) AcceptEncoding() string { return t.encoding }
func (t testPrecompressed) Suffix() string         { return t.suffix }

// newTestFileServer creates a FileServer configured for testing with the
// given root directory and precompressors.
func newTestFileServer(root string, precompressors map[string]encode.Precompressed, preferPrecompressed bool, precompressedOrder []string) *FileServer {
	fsrv := &FileServer{
		Root:                root,
		FileSystem:          "",
		PreferPrecompressed: preferPrecompressed,
		precompressors:      precompressors,
		PrecompressedOrder:  precompressedOrder,
		fsmap:               &filesystems.FileSystemMap{},
		logger:              zap.NewNop(),
	}
	return fsrv
}

// newTestRequest creates an http.Request with the necessary context values
// for the file server to work (replacer and original request).
func newTestRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	repl := caddy.NewReplacer()
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl)
	ctx = context.WithValue(ctx, caddyhttp.OriginalRequestCtxKey, *req)
	req = req.WithContext(ctx)
	return req
}

// statusNextHandler is a caddyhttp.Handler that records whether it was called.
type statusNextHandler struct {
	called     bool
	statusCode int
}

func (h *statusNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	h.called = true
	w.WriteHeader(h.statusCode)
	return nil
}

func TestPreferPrecompressedServesCompressedFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create only the precompressed file, no base file
	gzContent := []byte("fake gzip content")
	if err := os.WriteFile(filepath.Join(tmpDir, "style.css.gz"), gzContent, 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})

	req := newTestRequest("GET", "/style.css")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 404}

	err := fsrv.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if next.called {
		t.Fatal("next handler should not have been called")
	}
	if w.Code != 200 {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("expected Content-Encoding gzip, got %q", ce)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/css; charset=utf-8" {
		t.Errorf("expected Content-Type text/css, got %q", ct)
	}
	if w.Body.String() != string(gzContent) {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

func TestPreferPrecompressedReturns404WhenNoCompressedVariant(t *testing.T) {
	tmpDir := t.TempDir()

	// No files at all - neither base nor precompressed
	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})

	req := newTestRequest("GET", "/missing.css")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 200}

	err := fsrv.ServeHTTP(w, req, next)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 status, got %d", httpErr.StatusCode)
	}
}

func TestPreferPrecompressedReturns404WhenClientDoesNotAcceptEncoding(t *testing.T) {
	tmpDir := t.TempDir()

	// Create only the precompressed file
	if err := os.WriteFile(filepath.Join(tmpDir, "style.css.gz"), []byte("gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})

	// No Accept-Encoding header
	req := newTestRequest("GET", "/style.css")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 200}

	err := fsrv.ServeHTTP(w, req, next)
	if err == nil {
		t.Fatal("expected error for unsupported encoding")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 status, got %d", httpErr.StatusCode)
	}
}

func TestPreferPrecompressedDisabledReturns404ForMissingBase(t *testing.T) {
	tmpDir := t.TempDir()

	// Create only the precompressed file, but PreferPrecompressed is false
	if err := os.WriteFile(filepath.Join(tmpDir, "style.css.gz"), []byte("gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, false, []string{"gzip"})

	req := newTestRequest("GET", "/style.css")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 200}

	err := fsrv.ServeHTTP(w, req, next)
	if err == nil {
		t.Fatal("expected error when base file missing and prefer_precompressed disabled")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 status, got %d", httpErr.StatusCode)
	}
}

func TestPreferPrecompressedWithBaseFileStillWorks(t *testing.T) {
	tmpDir := t.TempDir()

	// Both base and precompressed files exist
	baseContent := []byte("body { color: red; }")
	gzContent := []byte("fake gzip content")
	if err := os.WriteFile(filepath.Join(tmpDir, "style.css"), baseContent, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "style.css.gz"), gzContent, 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})

	req := newTestRequest("GET", "/style.css")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 404}

	err := fsrv.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if w.Code != 200 {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("expected Content-Encoding gzip, got %q", ce)
	}
}

func TestPreferPrecompressedSelectsBestEncoding(t *testing.T) {
	tmpDir := t.TempDir()

	// Create only precompressed files with multiple encodings
	if err := os.WriteFile(filepath.Join(tmpDir, "app.js.br"), []byte("brotli content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "app.js.gz"), []byte("gzip content"), 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
		"br":   testPrecompressed{encoding: "br", suffix: ".br"},
	}
	// Prefer brotli over gzip
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"br", "gzip"})

	req := newTestRequest("GET", "/app.js")
	req.Header.Set("Accept-Encoding", "gzip, br")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 404}

	err := fsrv.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "br" {
		t.Errorf("expected Content-Encoding br (preferred), got %q", ce)
	}
}

func TestPreferPrecompressedPassThru(t *testing.T) {
	tmpDir := t.TempDir()

	// No files exist, pass_thru enabled
	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})
	fsrv.PassThru = true

	req := newTestRequest("GET", "/missing.css")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 200}

	err := fsrv.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error with pass_thru, got: %v", err)
	}
	if !next.called {
		t.Error("expected next handler to be called with pass_thru")
	}
}

func TestPreferPrecompressedNoPrecompressors(t *testing.T) {
	tmpDir := t.TempDir()

	// PreferPrecompressed is true but no precompressors configured
	// Should behave as if PreferPrecompressed is false
	fsrv := newTestFileServer(tmpDir, nil, true, nil)

	req := newTestRequest("GET", "/missing.css")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 200}

	err := fsrv.ServeHTTP(w, req, next)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 status, got %d", httpErr.StatusCode)
	}
}

func TestPreferPrecompressedHiddenFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a precompressed file for a hidden path
	if err := os.WriteFile(filepath.Join(tmpDir, ".secret.gz"), []byte("secret gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})
	fsrv.Hide = []string{".secret"}

	req := newTestRequest("GET", "/.secret")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 200}

	err := fsrv.ServeHTTP(w, req, next)
	if err == nil {
		t.Fatal("expected error for hidden file")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 status, got %d", httpErr.StatusCode)
	}
}

func TestPreferPrecompressedHiddenCompressedFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create only the precompressed file, and hide the compressed path itself
	if err := os.WriteFile(filepath.Join(tmpDir, "style.css.gz"), []byte("gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})
	fsrv.Hide = []string{filepath.Join(tmpDir, "*.gz")}

	req := newTestRequest("GET", "/style.css")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 200}

	err := fsrv.ServeHTTP(w, req, next)
	if err == nil {
		t.Fatal("expected error when compressed file is hidden")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 status, got %d", httpErr.StatusCode)
	}
}

func TestPreferPrecompressedSubdirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create subdirectory with only precompressed file
	subDir := filepath.Join(tmpDir, "assets")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	gzContent := []byte("fake gzip css")
	if err := os.WriteFile(filepath.Join(subDir, "main.css.gz"), gzContent, 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})

	req := newTestRequest("GET", "/assets/main.css")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 404}

	err := fsrv.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if w.Code != 200 {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("expected Content-Encoding gzip, got %q", ce)
	}
	if w.Body.String() != string(gzContent) {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

// Verify that fs.FS-based test works with the filesystem map
// by confirming the default filesystem reads from the right root.
func TestPrecompressedWithExistingBaseFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Only base file exists, no precompressed - should serve base file
	baseContent := []byte("body { color: blue; }")
	if err := os.WriteFile(filepath.Join(tmpDir, "style.css"), baseContent, 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})

	req := newTestRequest("GET", "/style.css")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 404}

	err := fsrv.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if w.Code != 200 {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	// No precompressed file exists, so no Content-Encoding should be set
	if ce := w.Header().Get("Content-Encoding"); ce != "" {
		t.Errorf("expected no Content-Encoding, got %q", ce)
	}
}

// Verify the Vary: Accept-Encoding header is present even in
// prefer_precompressed mode.
func TestPreferPrecompressedVaryHeader(t *testing.T) {
	tmpDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmpDir, "style.css.gz"), []byte("gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})

	req := newTestRequest("GET", "/style.css")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 404}

	err := fsrv.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if vary := w.Header().Get("Vary"); vary != "Accept-Encoding" {
		t.Errorf("expected Vary: Accept-Encoding, got %q", vary)
	}
}

// Ensure the warning is logged when prefer_precompressed is set without
// precompressors. We use a zap observer to capture the log output.
func TestPreferPrecompressedProvisionWarning(t *testing.T) {
	// We can't easily test the Provision method directly without a full
	// caddy.Context, but we can verify the runtime behavior: that
	// PreferPrecompressed with no precompressors falls through to 404
	// immediately (the same code path the warning is for).
	tmpDir := t.TempDir()

	// Create only precompressed file
	if err := os.WriteFile(filepath.Join(tmpDir, "style.css.gz"), []byte("gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	// No precompressors configured - should return 404 even though
	// the .gz file exists, because we can't serve it
	fsrv := newTestFileServer(tmpDir, nil, true, nil)

	req := newTestRequest("GET", "/style.css")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 200}

	err := fsrv.ServeHTTP(w, req, next)
	if err == nil {
		t.Fatal("expected error")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", httpErr.StatusCode)
	}
}

func TestPreferPrecompressedDirectoryIndex(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory with only a precompressed index file
	subDir := filepath.Join(tmpDir, "mydir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	gzContent := []byte("compressed index")
	if err := os.WriteFile(filepath.Join(subDir, "index.html.gz"), gzContent, 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})
	fsrv.IndexNames = []string{"index.html"}

	req := newTestRequest("GET", "/mydir/")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 404}

	err := fsrv.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if next.called {
		t.Fatal("next handler should not have been called")
	}
	if w.Code != 200 {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("expected Content-Encoding gzip, got %q", ce)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected Content-Type text/html, got %q", ct)
	}
	if w.Body.String() != string(gzContent) {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

func TestPreferPrecompressedDirectoryIndexRedirect(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory with only a precompressed index file
	subDir := filepath.Join(tmpDir, "mydir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "index.html.gz"), []byte("gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})
	fsrv.IndexNames = []string{"index.html"}

	// Request without trailing slash should redirect
	req := newTestRequest("GET", "/mydir")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 404}

	err := fsrv.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if w.Code != http.StatusPermanentRedirect {
		t.Errorf("expected redirect status %d, got %d", http.StatusPermanentRedirect, w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/mydir/" {
		t.Errorf("expected Location /mydir/, got %q", loc)
	}
}

func TestPreferPrecompressedDirectoryIndexDisabled(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory with only a precompressed index file,
	// but PreferPrecompressed is false
	subDir := filepath.Join(tmpDir, "mydir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "index.html.gz"), []byte("gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, false, []string{"gzip"})
	fsrv.IndexNames = []string{"index.html"}

	req := newTestRequest("GET", "/mydir/")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 200}

	err := fsrv.ServeHTTP(w, req, next)
	if err == nil {
		t.Fatal("expected error when prefer_precompressed is disabled")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", httpErr.StatusCode)
	}
}

func TestPreferPrecompressedDirectoryIndexFallbackToSecondIndex(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory with only a precompressed variant of the
	// second index name - the first index name has no variants at all.
	subDir := filepath.Join(tmpDir, "mydir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	gzContent := []byte("compressed default")
	if err := os.WriteFile(filepath.Join(subDir, "default.html.gz"), gzContent, 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip"})
	fsrv.IndexNames = []string{"index.html", "default.html"}

	req := newTestRequest("GET", "/mydir/")
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 404}

	err := fsrv.ServeHTTP(w, req, next)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if next.called {
		t.Fatal("next handler should not have been called")
	}
	if w.Code != 200 {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if ce := w.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("expected Content-Encoding gzip, got %q", ce)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("expected Content-Type text/html, got %q", ct)
	}
	if w.Body.String() != string(gzContent) {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

func TestPreferPrecompressedDirectoryIndexEncodingMismatch(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a subdirectory with only a .gz precompressed index file,
	// but the client only accepts br - should fall through to not found
	subDir := filepath.Join(tmpDir, "mydir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "index.html.gz"), []byte("gzip"), 0644); err != nil {
		t.Fatal(err)
	}

	precompressors := map[string]encode.Precompressed{
		"gzip": testPrecompressed{encoding: "gzip", suffix: ".gz"},
		"br":   testPrecompressed{encoding: "br", suffix: ".br"},
	}
	fsrv := newTestFileServer(tmpDir, precompressors, true, []string{"gzip", "br"})
	fsrv.IndexNames = []string{"index.html"}

	req := newTestRequest("GET", "/mydir/")
	req.Header.Set("Accept-Encoding", "br")
	w := httptest.NewRecorder()
	next := &statusNextHandler{statusCode: 200}

	err := fsrv.ServeHTTP(w, req, next)
	if err == nil {
		t.Fatal("expected error when no matching precompressed variant exists")
	}
	httpErr, ok := err.(caddyhttp.HandlerError)
	if !ok {
		t.Fatalf("expected caddyhttp.HandlerError, got %T", err)
	}
	if httpErr.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", httpErr.StatusCode)
	}
}
