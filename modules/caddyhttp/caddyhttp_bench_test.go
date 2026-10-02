package caddyhttp

import "testing"

func BenchmarkCleanPathNoCollapse(b *testing.B) {
	const p = "/foo/bar/baz/qux/some/longer/path/segment/here/index.html"
	b.ReportAllocs()
	for b.Loop() {
		_ = CleanPath(p, false)
	}
}
