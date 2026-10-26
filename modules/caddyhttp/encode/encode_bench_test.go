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

const (
	benchmarkParallelism         = 4
	handlerBenchWarmupIterations = 5
)

// BenchmarkStandardEncodingPayloads measures raw encoder throughput (NewEncoder → Write → Close)
// across the standard HTML/JSON/JS/CSS payloads and gzip/zstd compression levels.
// Each subtest runs with 4 parallel workers (SetParallelism).
func BenchmarkStandardEncodingPayloads(b *testing.B) {
	forEachBenchmarkCase(b, func(b *testing.B, corpus benchmarkCorpus, encCase encoderCase) {
		benchmarkEncode(b, corpus.data, encCase.encoding)
	})
}

// BenchmarkEncodeHandlerCorpus measures the full encode middleware path (ServeHTTP,
// responseWriter, writer pools) using the same payload and level grid.
func BenchmarkEncodeHandlerCorpus(b *testing.B) {
	forEachBenchmarkCase(b, func(b *testing.B, corpus benchmarkCorpus, encCase encoderCase) {
		enc := newEncodeHandler(b, encCase, 1)
		benchmarkEncodeHandler(b, enc, encCase, corpus)
	})
}

func forEachBenchmarkCase(b *testing.B, fn func(b *testing.B, corpus benchmarkCorpus, encCase encoderCase)) {
	for _, corpus := range benchmarkCorpora(b) {
		for _, encCase := range benchmarkEncoderCases(b) {
			b.Run(benchmarkSubtestName(corpus.name, encCase), func(b *testing.B) {
				fn(b, corpus, encCase)
			})
		}
	}
}

func benchmarkSubtestName(corpus string, encCase encoderCase) string {
	return fmt.Sprintf("payload-%s/encoder-%s/compress-level-%s",
		corpus, encCase.encoder, encCase.level)
}

func benchmarkEncode(b *testing.B, payload []byte, encoding encode.Encoding) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.SetParallelism(benchmarkParallelism)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		encoder := encoding.NewEncoder()
		var dst bytes.Buffer
		for pb.Next() {
			dst.Reset()
			encoder.Reset(&dst)
			if _, err := encoder.Write(payload); err != nil {
				b.Fatalf("Write() error = %v", err)
			}
			if err := encoder.Close(); err != nil {
				b.Fatalf("Close() error = %v", err)
			}
		}
	})
}

func benchmarkEncodeHandler(b *testing.B, enc *encode.Encode, encCase encoderCase, corpus benchmarkCorpus) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(corpus.data)))
	b.SetParallelism(benchmarkParallelism)

	next := corpusHandler(corpus)
	w := newBenchmarkResponseWriter()
	r := newHandlerBenchRequest(encCase)
	warmupEncodeHandler(enc, w, r, next)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		w := newBenchmarkResponseWriter()
		r := newHandlerBenchRequest(encCase)
		for pb.Next() {
			w.reset()
			if err := enc.ServeHTTP(w, r, next); err != nil {
				b.Fatalf("ServeHTTP() error = %v", err)
			}
		}
	})
}

func newHandlerBenchRequest(encCase encoderCase) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Encoding", encCase.encoding.AcceptEncoding())
	return r
}

func warmupEncodeHandler(enc *encode.Encode, w *benchmarkResponseWriter, r *http.Request, next caddyhttp.Handler) {
	for range handlerBenchWarmupIterations {
		w.reset()
		if err := enc.ServeHTTP(w, r, next); err != nil {
			panic("warmup ServeHTTP: " + err.Error())
		}
	}
}

// benchmarkResponseWriter is a resettable http.ResponseWriter for handler benchmarks.
// httptest.ResponseRecorder cannot be safely reused because it keeps unexported state.
type benchmarkResponseWriter struct {
	header      http.Header
	code        int
	body        bytes.Buffer
	wroteHeader bool
}

func newBenchmarkResponseWriter() *benchmarkResponseWriter {
	return &benchmarkResponseWriter{
		header: make(http.Header),
	}
}

func (w *benchmarkResponseWriter) reset() {
	w.code = 0
	w.wroteHeader = false
	w.body.Reset()
	for k := range w.header {
		delete(w.header, k)
	}
}

func (w *benchmarkResponseWriter) Header() http.Header {
	return w.header
}

func (w *benchmarkResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}

func (w *benchmarkResponseWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.code = statusCode
	w.wroteHeader = true
}

func (w *benchmarkResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
}

func corpusHandler(corpus benchmarkCorpus) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", corpus.contentType)
		_, err := w.Write(corpus.data)
		return err
	})
}
