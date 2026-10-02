package encode

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func BenchmarkOpenResponseWriter(b *testing.B) {
	enc := new(Encode)
	for b.Loop() {
		enc.openResponseWriter("test", nil, false)
	}
}

// discardResponseWriter is a minimal http.ResponseWriter used to isolate
// WriteHeader's own cost from a real transport.
type discardResponseWriter struct {
	header http.Header
}

func (w *discardResponseWriter) Header() http.Header         { return w.header }
func (w *discardResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *discardResponseWriter) WriteHeader(int)             {}

// BenchmarkResponseWriterWriteHeader covers the branches inside WriteHeader:
// the plain/common case, the SSE Content-Type check (both when it doesn't
// match and when it does and rw.init() runs), CONNECT 2xx, informational
// (1xx), and 304 Not Modified (Vary bookkeeping).
func BenchmarkResponseWriterWriteHeader(b *testing.B) {
	benchCases := []struct {
		name        string
		encoding    string
		isConnect   bool
		status      int
		contentType string
	}{
		{name: "plain", encoding: "test", status: http.StatusOK},
		{name: "html", encoding: "test", status: http.StatusOK, contentType: "text/html; charset=utf-8"},
		{name: "event-stream", encoding: "gzip", status: http.StatusOK, contentType: "text/event-stream"},
		{name: "connect", encoding: "test", isConnect: true, status: http.StatusOK},
		{name: "informational", encoding: "test", status: http.StatusEarlyHints},
		{name: "not-modified", encoding: "test", status: http.StatusNotModified},
	}

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			enc := new(Encode)
			if bc.name == "event-stream" {
				enc.writerPools = map[string]*sync.Pool{
					"gzip": {New: func() any { return mockEncoder{} }},
				}
				ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
				defer cancel()
				if err := enc.Provision(ctx); err != nil {
					b.Fatalf("Provision() error = %v", err)
				}
			}

			w := &discardResponseWriter{header: make(http.Header)}
			rw := enc.openResponseWriter(bc.encoding, w, bc.isConnect)

			for b.Loop() {
				for k := range rw.Header() {
					delete(rw.Header(), k)
				}
				if bc.contentType != "" {
					rw.Header().Set("Content-Type", bc.contentType)
				}
				rw.wroteHeader = false
				rw.statusCode = 0
				rw.disabled = false
				rw.w = nil
				rw.WriteHeader(bc.status)
			}
		})
	}
}

func TestIsSSE(t *testing.T) {
	for _, tc := range []struct {
		contentType string
		want        bool
	}{
		{"", false},
		{"text/plain", false},
		{"text/event-stream", true},
		{"Text/Event-Stream", true},
		{"text/event-stream; charset=utf-8", true},
		{"text/event-stream ; charset=utf-8", true},
		{"text/event-stream  ", true},
		{"text/event-streamfoo", false},
		{"text/event-stream nonsense", false},
		{"text/event-stream x; charset=utf-8", false},
	} {
		if got := isSSE(tc.contentType); got != tc.want {
			t.Errorf("isSSE(%q) = %v, want %v", tc.contentType, got, tc.want)
		}
	}
}

func TestPreferOrder(t *testing.T) {
	testCases := []struct {
		name     string
		accept   string
		prefer   []string
		expected []string
	}{
		{
			name:     "PreferOrder(): 4 accept, 3 prefer",
			accept:   "deflate, gzip, br, zstd",
			prefer:   []string{"zstd", "br", "gzip"},
			expected: []string{"zstd", "br", "gzip", "deflate"},
		},
		{
			name:     "PreferOrder(): 2 accept, 3 prefer",
			accept:   "deflate, zstd",
			prefer:   []string{"zstd", "br", "gzip"},
			expected: []string{"zstd", "deflate"},
		},
		{
			name:     "PreferOrder(): 2 accept (1 empty), 3 prefer",
			accept:   "gzip,,zstd",
			prefer:   []string{"zstd", "br", "gzip"},
			expected: []string{"zstd", "gzip", ""},
		},
		{
			name:     "PreferOrder(): 1 accept, 2 prefer",
			accept:   "gzip",
			prefer:   []string{"zstd", "gzip"},
			expected: []string{"gzip"},
		},
		{
			name:     "PreferOrder(): 4 accept (1 duplicate), 1 prefer",
			accept:   "deflate, gzip, br, br",
			prefer:   []string{"br"},
			expected: []string{"br", "br", "deflate", "gzip"},
		},
		{
			name:     "PreferOrder(): empty accept, 0 prefer",
			accept:   "",
			prefer:   []string{},
			expected: []string{},
		},
		{
			name:     "PreferOrder(): empty accept, 1 prefer",
			accept:   "",
			prefer:   []string{"gzip"},
			expected: []string{},
		},
		{
			name:     "PreferOrder(): with q-factor",
			accept:   "deflate;q=0.8, gzip;q=0.4, br;q=0.2, zstd",
			prefer:   []string{"gzip"},
			expected: []string{"zstd", "deflate", "gzip", "br"},
		},
		{
			name:     "PreferOrder(): with q-factor, no prefer",
			accept:   "deflate;q=0.8, gzip;q=0.4, br;q=0.2, zstd",
			prefer:   []string{},
			expected: []string{"zstd", "deflate", "gzip", "br"},
		},
		{
			name:     "PreferOrder(): q-factor=0 filtered out",
			accept:   "deflate;q=0.1, gzip;q=0.4, br;q=0.5, zstd;q=0",
			prefer:   []string{"gzip"},
			expected: []string{"br", "gzip", "deflate"},
		},
		{
			name:     "PreferOrder(): q-factor=0 filtered out, no prefer",
			accept:   "deflate;q=0.1, gzip;q=0.4, br;q=0.5, zstd;q=0",
			prefer:   []string{},
			expected: []string{"br", "gzip", "deflate"},
		},
		{
			name:     "PreferOrder(): with invalid q-factor",
			accept:   "br, deflate, gzip;q=2, zstd;q=0.1",
			prefer:   []string{"zstd", "gzip"},
			expected: []string{"gzip", "br", "deflate", "zstd"},
		},
		{
			name:     "PreferOrder(): with invalid q-factor, no prefer",
			accept:   "br, deflate, gzip;q=2, zstd;q=0.1",
			prefer:   []string{},
			expected: []string{"br", "deflate", "gzip", "zstd"},
		},
	}

	enc := new(Encode)
	r, _ := http.NewRequest("", "", nil)

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			if test.accept == "" {
				r.Header.Del("Accept-Encoding")
			} else {
				r.Header.Set("Accept-Encoding", test.accept)
			}
			enc.Prefer = test.prefer
			result := AcceptedEncodings(r, enc.Prefer)
			if !slices.Equal(result, test.expected) {
				t.Errorf("AcceptedEncodings() actual: %s expected: %s",
					result,
					test.expected)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	type testCase struct {
		name    string
		prefer  []string
		wantErr bool
	}

	var err error
	var testCases []testCase
	enc := new(Encode)

	enc.writerPools = map[string]*sync.Pool{
		"zstd": nil,
		"gzip": nil,
		"br":   nil,
	}
	testCases = []testCase{
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): valid order with all encoder",
			prefer:  []string{"zstd", "br", "gzip"},
			wantErr: false,
		},
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): valid order with 2 out of 3 encoders",
			prefer:  []string{"br", "gzip"},
			wantErr: false,
		},
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): valid order with 1 out of 3 encoders",
			prefer:  []string{"gzip"},
			wantErr: false,
		},
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): 1 duplicated (once) encoder",
			prefer:  []string{"gzip", "zstd", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): 1 not enabled encoder in prefer list",
			prefer:  []string{"br", "zstd", "gzip", "deflate"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd, gzip & br enabled): no prefer list",
			prefer:  []string{},
			wantErr: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			enc.Prefer = test.prefer
			err = enc.Validate()
			if (err != nil) != test.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}

	enc.writerPools = map[string]*sync.Pool{
		"zstd": nil,
		"gzip": nil,
	}
	testCases = []testCase{
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 1 not enabled encoder in prefer list",
			prefer:  []string{"zstd", "br", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 2 not enabled encoder in prefer list",
			prefer:  []string{"br", "zstd", "gzip", "deflate"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): only not enabled encoder in prefer list",
			prefer:  []string{"deflate", "br", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 1 duplicated (once) encoder in prefer list",
			prefer:  []string{"gzip", "zstd", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 1 duplicated (twice) encoder in prefer list",
			prefer:  []string{"gzip", "zstd", "gzip", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 1 duplicated encoder in prefer list",
			prefer:  []string{"zstd", "zstd", "gzip", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 1 duplicated not enabled encoder in prefer list",
			prefer:  []string{"br", "br", "gzip"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): 2 duplicated not enabled encoder in prefer list",
			prefer:  []string{"br", "deflate", "br", "deflate"},
			wantErr: true,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): valid order zstd first",
			prefer:  []string{"zstd", "gzip"},
			wantErr: false,
		},
		{
			name:    "ValidatePrefer (zstd & gzip enabled): valid order gzip first",
			prefer:  []string{"gzip", "zstd"},
			wantErr: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			enc.Prefer = test.prefer
			err = enc.Validate()
			if (err != nil) != test.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, test.wantErr)
			}
		})
	}
}

func TestIsEncodeAllowed(t *testing.T) {
	testCases := []struct {
		name     string
		headers  http.Header
		expected bool
	}{
		{
			name:     "Without any headers",
			headers:  http.Header{},
			expected: true,
		},
		{
			name: "Without Cache-Control HTTP header",
			headers: http.Header{
				"Accept-Encoding": {"gzip"},
			},
			expected: true,
		},
		{
			name: "Cache-Control HTTP header ending with no-transform directive",
			headers: http.Header{
				"Accept-Encoding": {"gzip"},
				"Cache-Control":   {"no-cache; no-transform"},
			},
			expected: false,
		},
		{
			name: "With Cache-Control HTTP header no-transform as Cache-Extension value",
			headers: http.Header{
				"Accept-Encoding": {"gzip"},
				"Cache-Control":   {`no-store; no-cache; community="no-transform"`},
			},
			expected: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			if result := isEncodeAllowed(test.headers); result != test.expected {
				t.Errorf("The headers given to the isEncodeAllowed should return %t, %t given.",
					result,
					test.expected)
			}
		})
	}
}

type mockEncoder struct{}

func (mockEncoder) Write(p []byte) (n int, err error) { return len(p), nil }
func (mockEncoder) Close() error                      { return nil }
func (mockEncoder) Reset(w io.Writer)                 {}
func (mockEncoder) Flush() error                      { return nil }

func TestServeHTTPDefaultEncodingPreference(t *testing.T) {
	enc := new(Encode)
	enc.MinLength = 1 // compress everything
	enc.writerPools = map[string]*sync.Pool{
		"gzip": {
			New: func() any { return mockEncoder{} },
		},
		"zstd": {
			New: func() any { return mockEncoder{} },
		},
	}

	// Call Provision() with a valid caddy.Context to exercise the real path
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := enc.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Test default preference: zstd preferred over gzip
	r, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf("error creating request: %v", err)
	}
	r.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")

	w := httptest.NewRecorder()
	w.Header().Set("Content-Type", "text/plain")

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Hello, world! This is a long enough string to satisfy min length if it wasn't 1."))
		return err
	})

	err = enc.ServeHTTP(w, r, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// ETag suffix or Content-Encoding header should reflect zstd
	contentEncoding := w.Header().Get("Content-Encoding")
	if contentEncoding != "zstd" {
		t.Errorf("Expected Content-Encoding to be 'zstd' by default, got '%s'", contentEncoding)
	}

	// Test explicit user preference: gzip over zstd
	enc.Prefer = []string{"gzip", "zstd"}

	w2 := httptest.NewRecorder()
	w2.Header().Set("Content-Type", "text/plain")
	err = enc.ServeHTTP(w2, r, next)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	contentEncoding2 := w2.Header().Get("Content-Encoding")
	if contentEncoding2 != "gzip" {
		t.Errorf("Expected Content-Encoding to be 'gzip' when explicitly preferred, got '%s'", contentEncoding2)
	}
}
