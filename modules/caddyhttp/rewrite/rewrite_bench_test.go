package rewrite

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func BenchmarkBuildQueryString(b *testing.B) {
	repl := caddy.NewReplacer()
	const qs = "foo=bar&baz=qux&search=hello+world&page=2&sort=desc&filter=active&id=12345"
	b.ReportAllocs()
	for b.Loop() {
		_ = buildQueryString(qs, repl)
	}
}
