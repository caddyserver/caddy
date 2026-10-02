package encode_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
)

const conformanceContentType = "text/plain"

// TestStandardEncoderContract verifies Reset, Flush, Close, and Reset-after-Close
// reuse for each encoder using the same HTML/JSON/JS/CSS payloads as the benchmark suite.
func TestStandardEncoderContract(t *testing.T) {
	for _, encCase := range standardEncoderCases(t) {
		t.Run(encCase.name, func(t *testing.T) {
			for _, corpus := range benchmarkCorpora(t) {
				t.Run(corpus.name, func(t *testing.T) {
					encoder := encCase.encoding.NewEncoder()
					original := corpus.data

					encodeAndVerifyRoundTrip(t, encCase, encoder, original)

					// Simulate writer-pool reuse: Close → Reset(nil) → Reset(writer).
					encoder.Reset(nil)
					encodeAndVerifyRoundTrip(t, encCase, encoder, original)
				})
			}
		})
	}
}

// TestEncodeCorpusResponse verifies encoded-response semantics (Content-Encoding, Vary,
// ETag suffix, header stripping) for each benchmark corpus and encoder.
func TestEncodeCorpusResponse(t *testing.T) {
	for _, encCase := range standardEncoderCases(t) {
		t.Run(encCase.name, func(t *testing.T) {
			for _, corpus := range benchmarkCorpora(t) {
				t.Run(corpus.name, func(t *testing.T) {
					enc := newEncodeHandler(t, encCase, 1)
					r := httptest.NewRequest(http.MethodGet, "/", nil)
					r.Header.Set("Accept-Encoding", encCase.encoding.AcceptEncoding())
					w := httptest.NewRecorder()

					next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
						w.Header().Set("Content-Type", corpus.contentType)
						w.Header().Set("Content-Length", fmt.Sprintf("%d", len(corpus.data)))
						w.Header().Set("Accept-Ranges", "bytes")
						w.Header().Set("Etag", `"response"`)
						_, err := w.Write(corpus.data)
						return err
					})

					if err := enc.ServeHTTP(w, r, next); err != nil {
						t.Fatalf("ServeHTTP() error = %v", err)
					}
					checkEncodedCorpusResponse(t, w, encCase, corpus)
				})
			}
		})
	}
}

type encodeScenario struct {
	name          string
	method        string
	minLength     int
	reqHeaders    func(encoderCase) http.Header
	checkRequest  func(*testing.T, *http.Request)
	next          func(encoderCase) caddyhttp.Handler
	checkResponse func(*testing.T, *httptest.ResponseRecorder, encoderCase)
}

var encodeScenarios = []encodeScenario{
	{
		name:      "minimum length prevents encoding",
		method:    http.MethodGet,
		minLength: 1024,
		next: func(encoderCase) caddyhttp.Handler {
			return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", conformanceContentType)
				_, err := w.Write([]byte("short"))
				return err
			})
		},
		checkResponse: checkMinLengthPreventsEncoding,
	},
	{
		name:      "not modified adds vary without encoding",
		method:    http.MethodGet,
		minLength: 1,
		next: func(encoderCase) caddyhttp.Handler {
			return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusNotModified)
				return nil
			})
		},
		checkResponse: checkNotModifiedVary,
	},
	{
		name:      "head response headers can be encoded without body",
		method:    http.MethodHead,
		minLength: 1,
		next: func(encoderCase) caddyhttp.Handler {
			return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", conformanceContentType)
				w.Header().Set("Content-Length", "128")
				return nil
			})
		},
		checkResponse: checkHeadEncodedHeaders,
	},
	{
		name:      "range response bypasses encoding",
		method:    http.MethodGet,
		minLength: 1,
		reqHeaders: func(encoderCase) http.Header {
			return http.Header{"Range": {"bytes=0-15"}}
		},
		next: func(encoderCase) caddyhttp.Handler {
			return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", conformanceContentType)
				w.Header().Set("Content-Range", "bytes 0-15/128")
				w.Header().Set("Accept-Ranges", "bytes")
				w.WriteHeader(http.StatusPartialContent)
				_, err := w.Write([]byte("0123456789abcdef"))
				return err
			})
		},
		checkResponse: checkRangeResponseBypassesEncoding,
	},
	{
		name:      "websocket handshake bypasses encoding",
		method:    http.MethodGet,
		minLength: 1,
		reqHeaders: func(encoderCase) http.Header {
			return http.Header{
				"Connection":        {"Upgrade"},
				"Sec-WebSocket-Key": {"dGhlIHNhbXBsZSBub25jZQ=="},
				"Upgrade":           {"websocket"},
			}
		},
		next: func(encoderCase) caddyhttp.Handler {
			return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusSwitchingProtocols)
				return nil
			})
		},
		checkResponse: checkWebSocketBypass,
	},
	{
		name:      "strips encoded etag suffix before next handler",
		method:    http.MethodGet,
		minLength: 1,
		reqHeaders: func(encCase encoderCase) http.Header {
			return http.Header{
				"If-None-Match": {fmt.Sprintf(`"response-%s"`, encCase.encoding.AcceptEncoding())},
			}
		},
		checkRequest: func(t *testing.T, r *http.Request) {
			if got := r.Header.Get("If-None-Match"); got != `"response"` {
				t.Fatalf("If-None-Match = %q, want %q", got, `"response"`)
			}
		},
		next: func(encoderCase) caddyhttp.Handler {
			return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusNotModified)
				return nil
			})
		},
		checkResponse: checkStripsEncodedETagSuffix,
	},
	{
		name:      "request cache-control no-transform prevents encoding",
		method:    http.MethodGet,
		minLength: 1,
		reqHeaders: func(encoderCase) http.Header {
			return http.Header{"Cache-Control": {"no-cache, no-transform"}}
		},
		next: func(encoderCase) caddyhttp.Handler {
			return conformanceLargeBodyHandler(conformanceContentType)
		},
		checkResponse: checkBypassesEncoding,
	},
	{
		name:      "response cache-control no-transform prevents encoding",
		method:    http.MethodGet,
		minLength: 1,
		next: func(encoderCase) caddyhttp.Handler {
			return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", conformanceContentType)
				w.Header().Set("Cache-Control", "no-cache, no-transform")
				_, err := w.Write(conformanceLargeBody())
				return err
			})
		},
		checkResponse: checkBypassesEncoding,
	},
	{
		name:      "content type matcher rejection prevents encoding",
		method:    http.MethodGet,
		minLength: 1,
		next: func(encoderCase) caddyhttp.Handler {
			return conformanceLargeBodyHandler("image/png")
		},
		checkResponse: checkBypassesEncoding,
	},
}

// TestEncodeResponseSemantics verifies HTTP edge cases (304, HEAD, range, WebSocket,
// minimum_length, ETag request rewriting, no-transform, matcher rejection) independent
// of the benchmark corpora.
func TestEncodeResponseSemantics(t *testing.T) {
	for _, encCase := range standardEncoderCases(t) {
		t.Run(encCase.name, func(t *testing.T) {
			for _, sc := range encodeScenarios {
				t.Run(sc.name, func(t *testing.T) {
					runEncodeScenario(t, encCase, sc)
				})
			}
		})
	}
}

func runEncodeScenario(t *testing.T, encCase encoderCase, sc encodeScenario) {
	t.Helper()

	enc := newEncodeHandler(t, encCase, sc.minLength)
	r := httptest.NewRequest(sc.method, "/", nil)
	r.Header.Set("Accept-Encoding", encCase.encoding.AcceptEncoding())
	if sc.reqHeaders != nil {
		for name, values := range sc.reqHeaders(encCase) {
			r.Header.Del(name)
			for _, value := range values {
				r.Header.Add(name, value)
			}
		}
	}
	w := httptest.NewRecorder()

	var rw http.ResponseWriter = w
	if sc.method == http.MethodHead {
		// httptest.ResponseRecorder still stores body writes on HEAD; discard them
		// so Close() path matches real clients that must not receive a body.
		rw = noBodyResponseWriter{ResponseRecorder: w}
	}

	next := sc.next(encCase)
	if sc.checkRequest != nil {
		inner := next
		next = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			sc.checkRequest(t, r)
			return inner.ServeHTTP(w, r)
		})
	}

	if err := enc.ServeHTTP(rw, r, next); err != nil {
		t.Fatalf("%s: ServeHTTP() error = %v", sc.name, err)
	}
	sc.checkResponse(t, w, encCase)
}

// noBodyResponseWriter discards Write data while still allowing the encode
// middleware to observe writes for Content-Length / min-length decisions.
type noBodyResponseWriter struct {
	*httptest.ResponseRecorder
}

func (w noBodyResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func checkEncodedCorpusResponse(t *testing.T, w *httptest.ResponseRecorder, encCase encoderCase, corpus benchmarkCorpus) {
	t.Helper()

	encName := encCase.encoding.AcceptEncoding()
	if got := w.Header().Get("Content-Encoding"); got != encName {
		t.Fatalf("Content-Encoding = %q, want %q", got, encName)
	}
	if !encode.HasVaryValue(w.Header(), "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", w.Header().Values("Vary"))
	}
	if got := w.Header().Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want empty", got)
	}
	if got := w.Header().Get("Accept-Ranges"); got != "" {
		t.Fatalf("Accept-Ranges = %q, want empty", got)
	}
	wantETag := fmt.Sprintf(`"response-%s"`, encName)
	if got := w.Header().Get("Etag"); got != wantETag {
		t.Fatalf("Etag = %q, want %q", got, wantETag)
	}
	assertDecompresses(t, encCase, w.Body.Bytes(), corpus.data)
}

func checkMinLengthPreventsEncoding(t *testing.T, w *httptest.ResponseRecorder, encCase encoderCase) {
	t.Helper()

	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := w.Body.String(); got != "short" {
		t.Fatalf("body = %q, want short", got)
	}
}

func checkNotModifiedVary(t *testing.T, w *httptest.ResponseRecorder, encCase encoderCase) {
	t.Helper()

	if got := w.Code; got != http.StatusNotModified {
		t.Fatalf("status = %d, want %d", got, http.StatusNotModified)
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if !encode.HasVaryValue(w.Header(), "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", w.Header().Values("Vary"))
	}
	if got := w.Body.Len(); got != 0 {
		t.Fatalf("body length = %d, want 0", got)
	}
}

func checkHeadEncodedHeaders(t *testing.T, w *httptest.ResponseRecorder, encCase encoderCase) {
	t.Helper()

	if got := w.Header().Get("Content-Encoding"); got != encCase.encoding.AcceptEncoding() {
		t.Fatalf("Content-Encoding = %q, want %q", got, encCase.encoding.AcceptEncoding())
	}
	if got := w.Body.Len(); got != 0 {
		t.Fatalf("body length = %d, want 0", got)
	}
}

func checkRangeResponseBypassesEncoding(t *testing.T, w *httptest.ResponseRecorder, encCase encoderCase) {
	t.Helper()

	if got := w.Code; got != http.StatusPartialContent {
		t.Fatalf("status = %d, want %d", got, http.StatusPartialContent)
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if got := w.Header().Get("Content-Range"); got != "bytes 0-15/128" {
		t.Fatalf("Content-Range = %q, want %q", got, "bytes 0-15/128")
	}
	if got := w.Header().Get("Accept-Ranges"); got != "bytes" {
		t.Fatalf("Accept-Ranges = %q, want bytes", got)
	}
	if got := w.Body.String(); got != "0123456789abcdef" {
		t.Fatalf("body = %q, want %q", got, "0123456789abcdef")
	}
}

func checkWebSocketBypass(t *testing.T, w *httptest.ResponseRecorder, encCase encoderCase) {
	t.Helper()

	if got := w.Code; got != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", got, http.StatusSwitchingProtocols)
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
}

func checkStripsEncodedETagSuffix(t *testing.T, w *httptest.ResponseRecorder, encCase encoderCase) {
	t.Helper()

	if got := w.Code; got != http.StatusNotModified {
		t.Fatalf("status = %d, want %d", got, http.StatusNotModified)
	}
	if !encode.HasVaryValue(w.Header(), "Accept-Encoding") {
		t.Fatalf("Vary = %q, want Accept-Encoding", w.Header().Values("Vary"))
	}
}

func conformanceLargeBodyHandler(contentType string) caddyhttp.Handler {
	body := conformanceLargeBody()
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", contentType)
		_, err := w.Write(body)
		return err
	})
}

func checkBypassesEncoding(t *testing.T, w *httptest.ResponseRecorder, encCase encoderCase) {
	t.Helper()

	want := conformanceLargeBody()
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q, want empty", got)
	}
	if !bytes.Equal(w.Body.Bytes(), want) {
		t.Fatalf("body len = %d, want len = %d", w.Body.Len(), len(want))
	}
}
