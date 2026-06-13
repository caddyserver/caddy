// Package encode_test provides the standard encode benchmark and conformance suite
// for Caddy's gzip and zstd encoder modules.
//
// Run encoder-level benchmarks (direct NewEncoder calls):
//
//	go test -bench=BenchmarkStandardEncodingPayloads -benchmem ./modules/caddyhttp/encode/
//
// Run middleware-level benchmarks (Encode.ServeHTTP, writer pools, responseWriter):
//
//	go test -bench=BenchmarkEncodeHandlerCorpus -benchmem ./modules/caddyhttp/encode/
//
// Benchmark subtest names:
//
//	payload-{html|json|js|css}/encoder-{gzip|zstd}/compress-level-{N|fastest|...}
//
// Each subtest uses 4 parallel workers (benchmarkParallelism in encode_bench_test.go).
// Go may append -{GOMAXPROCS} to the printed benchmark name; ignore it when comparing runs.
//
// Grid: 4 payloads × 6 compress levels (gzip 1/5/9, zstd fastest/default/best) = 24 subtests
// per benchmark function (48 total with encoder + handler).
//
// Run conformance tests (Reset/Flush/Close, Vary, ETag, 304/HEAD/range/WebSocket, minimum_length):
//
//	go test -run='TestStandardEncoderContract|TestEncodeCorpusResponse|TestEncodeResponseSemantics' ./modules/caddyhttp/encode/
//
// Conformance also covers Cache-Control no-transform, content-type matcher rejection,
// and encoder Reset-after-Close reuse (pool pattern).
package encode_test

import (
	"bytes"
	stdgzip "compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
	caddygzip "github.com/caddyserver/caddy/v2/modules/caddyhttp/encode/gzip"
	caddyzstd "github.com/caddyserver/caddy/v2/modules/caddyhttp/encode/zstd"
)

// benchmarkCorpus is a fixed payload used by both benchmarks and conformance tests.
type benchmarkCorpus struct {
	name        string
	data        []byte
	contentType string
}

var (
	benchmarkGzipLevels = []int{1, 5, 9}
	benchmarkZstdLevels = []string{"fastest", "default", "best"}
)

type encoderCase struct {
	name        string // conformance subtest label, e.g. gzip-level-5
	encoder     string // gzip or zstd
	level       string // gzip numeric level or zstd level name
	encoding    encode.Encoding
	decompress  func([]byte) ([]byte, error)
	contentType string
}

func benchmarkCorpora(tb testing.TB) []benchmarkCorpus {
	tb.Helper()

	return []benchmarkCorpus{
		{name: "html", data: readBenchmarkPayload(tb, "testdata/caddy_home.html"), contentType: "text/html; charset=utf-8"},
		{name: "json", data: readBenchmarkPayload(tb, "testdata/caddy_config_http_servers.json"), contentType: "application/json"},
		{name: "js", data: readBenchmarkPayload(tb, "testdata/caddy_asciinema_player.js"), contentType: "application/javascript"},
		{name: "css", data: readBenchmarkPayload(tb, "testdata/caddy_asciinema_player.css"), contentType: "text/css"},
	}
}

func readBenchmarkPayload(tb testing.TB, filename string) []byte {
	tb.Helper()

	data, err := os.ReadFile(filename)
	if err != nil {
		tb.Fatalf("reading benchmark payload %s: %v", filename, err)
	}
	return data
}

// conformanceLargeBody returns a payload large enough to exceed default minimum_length.
func conformanceLargeBody() []byte {
	data, err := os.ReadFile("testdata/caddy_home.html")
	if err != nil {
		panic("conformanceLargeBody: " + err.Error())
	}
	return data
}

func standardEncoderCases(t testing.TB) []encoderCase {
	t.Helper()
	return provisionEncoderCases(t, []int{5}, []string{"default"})
}

func benchmarkEncoderCases(t testing.TB) []encoderCase {
	t.Helper()
	return provisionEncoderCases(t, benchmarkGzipLevels, benchmarkZstdLevels)
}

func provisionEncoderCases(t testing.TB, gzipLevels []int, zstdLevels []string) []encoderCase {
	t.Helper()

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	var cases []encoderCase
	for _, level := range gzipLevels {
		gzipEncoding := &caddygzip.Gzip{Level: level}
		if err := gzipEncoding.Provision(ctx); err != nil {
			t.Fatalf("gzip level %d Provision() error = %v", level, err)
		}
		cases = append(cases, encoderCase{
			name:        fmt.Sprintf("gzip-level-%d", level),
			encoder:     "gzip",
			level:       fmt.Sprintf("%d", level),
			encoding:    gzipEncoding,
			decompress:  decompressGzip,
			contentType: "text/plain",
		})
	}
	for _, level := range zstdLevels {
		zstdEncoding := &caddyzstd.Zstd{Level: level}
		if err := zstdEncoding.Provision(ctx); err != nil {
			t.Fatalf("zstd level %q Provision() error = %v", level, err)
		}
		cases = append(cases, encoderCase{
			name:        "zstd-level-" + level,
			encoder:     "zstd",
			level:       level,
			encoding:    zstdEncoding,
			decompress:  decompressZstd,
			contentType: "text/plain",
		})
	}
	return cases
}

func newEncodeHandler(tb testing.TB, encCase encoderCase, minLength int) *encode.Encode {
	tb.Helper()

	encodingName := encCase.encoding.AcceptEncoding()
	enc := &encode.Encode{
		EncodingsRaw: caddy.ModuleMap{
			encodingName: caddyconfig.JSON(encCase.encoding, nil),
		},
		Prefer:    []string{encodingName},
		MinLength: minLength,
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	tb.Cleanup(cancel)
	if err := enc.Provision(ctx); err != nil {
		tb.Fatalf("Provision() error = %v", err)
	}
	if err := enc.Validate(); err != nil {
		tb.Fatalf("Validate() error = %v", err)
	}
	return enc
}

func assertDecompresses(t *testing.T, encCase encoderCase, compressed, original []byte) {
	t.Helper()

	decompressed, err := encCase.decompress(compressed)
	if err != nil {
		t.Fatalf("decompress %s: %v", encCase.name, err)
	}
	if !bytes.Equal(decompressed, original) {
		t.Fatalf("decompressed len = %d, want len = %d", len(decompressed), len(original))
	}
}

// encodeAndVerifyRoundTrip exercises Write → Flush → Write → Close and verifies
// the compressed stream round-trips to original.
func encodeAndVerifyRoundTrip(t *testing.T, encCase encoderCase, encoder encode.Encoder, original []byte) {
	t.Helper()

	var compressed bytes.Buffer
	encoder.Reset(&compressed)

	if _, err := encoder.Write(original[:len(original)/2]); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := encoder.Flush(); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if compressed.Len() == 0 {
		t.Fatal("Flush() wrote no compressed bytes")
	}
	if _, err := encoder.Write(original[len(original)/2:]); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	assertDecompresses(t, encCase, compressed.Bytes(), original)
}

func decompressGzip(compressed []byte) ([]byte, error) {
	reader, err := stdgzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func decompressZstd(compressed []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	return decoder.DecodeAll(compressed, nil)
}
