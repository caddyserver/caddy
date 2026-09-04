package fileserver

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func BenchmarkTransformHidePaths(b *testing.B) {
	repl := caddy.NewReplacer()
	fsrv := &FileServer{
		Hide:       []string{"/etc/caddy/Caddyfile", ".git", "/var/www/secret"},
		hideStatic: true, // all entries static; set during Provision in real use
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = fsrv.transformHidePaths(repl)
	}
}
