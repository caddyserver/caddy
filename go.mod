module github.com/caddyserver/caddy2

go 1.12

require (
	github.com/dustin/go-humanize v1.0.0
	github.com/go-acme/lego v2.6.0+incompatible
	github.com/klauspost/cpuid v1.2.1
	github.com/mholt/certmagic v0.5.1
	github.com/rs/cors v1.6.0
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/starlight-go/starlight v0.0.0-20181207205707-b06f321544f3
	go.starlark.net v0.0.0-20190604130855-6ddc71c0ba77
	golang.org/x/net v0.0.0-20190603091049-60506f45cf65
	gopkg.in/russross/blackfriday.v2 v2.0.1
)

replace gopkg.in/russross/blackfriday.v2 v2.0.1 => github.com/russross/blackfriday/v2 v2.0.1

replace github.com/mholt/certmagic v0.5.1 => ../../mholt/certmagic
