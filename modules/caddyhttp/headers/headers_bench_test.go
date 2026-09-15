package headers

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func BenchmarkHeaderOpsApplyToSet(b *testing.B) {
	ops := &HeaderOps{
		Set: http.Header{
			"Content-Type":    []string{"text/html; charset=utf-8"},
			"Cache-Control":   []string{"public", "max-age=3600", "immutable"},
			"X-Custom-Header": []string{"value-one", "value-two"},
		},
	}
	repl := caddy.NewReplacer()
	b.ReportAllocs()
	for b.Loop() {
		hdr := make(http.Header)
		ops.ApplyTo(hdr, repl)
	}
}
