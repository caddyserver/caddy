package encode

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkAcceptedEncodings(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Encoding", "gzip, deflate, br;q=0.9, zstd;q=0.8")
	prefer := []string{"zstd", "br", "gzip"}
	b.ReportAllocs()
	for b.Loop() {
		_ = AcceptedEncodings(r, prefer)
	}
}
