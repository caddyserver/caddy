package encode

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// The following benchmarks represent a comparison between some
// optimized methods and their previous implementation.
//
// Benchmark the old openResponseWriter implementation.
func BenchmarkOldOpenResponseWriter(b *testing.B) {
	oEnc := new(oldEncode)
	for n := 0; n < b.N; n++ {
		oEnc.openResponseWriter("test", nil)
	}
}

// Benchmark the new openResponseWriter implementation.
func BenchmarkNewOpenResponseWriter(b *testing.B) {
	enc := new(Encode)
	for n := 0; n < b.N; n++ {
		enc.openResponseWriter("test", nil)
	}
}

// oldEncode is a copy of Encode that implements the older version
// of the benchmarked methods, while the 'real' Encode holds the
// newer methods. This should ensure a fair comparison.
type oldEncode struct {
	EncodingsRaw map[string]json.RawMessage `json:"encodings,omitempty"`
	Prefer       []string                   `json:"prefer,omitempty"`
	MinLength    int                        `json:"minimum_length,omitempty"`

	writerPools map[string]*sync.Pool
}

// The old openResponseWriter version.
func (oenc *oldEncode) openResponseWriter(encodingName string, w http.ResponseWriter) *responseWriter {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	return &responseWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		encodingName:          encodingName,
		buf:                   buf,
		config:                nil,
	}
}
