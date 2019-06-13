module github.com/caddyserver/caddy2

go 1.12

require (
	github.com/DataDog/zstd v1.4.0 // indirect
	github.com/andybalholm/brotli v0.0.0-20190430215306-5c318f9037cb // indirect
	github.com/dustin/go-humanize v1.0.0
	github.com/go-acme/lego v2.6.0+incompatible
	github.com/google/go-cmp v0.3.0 // indirect
	github.com/klauspost/compress v1.7.1-0.20190613161414-0b31f265a57b
	github.com/klauspost/cpuid v1.2.1
	github.com/mholt/certmagic v0.5.2-0.20190605043235-e49d0d405641
	github.com/rs/cors v1.6.0
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/starlight-go/starlight v0.0.0-20181207205707-b06f321544f3
	go.starlark.net v0.0.0-20190604130855-6ddc71c0ba77
	golang.org/x/net v0.0.0-20190603091049-60506f45cf65
	gopkg.in/russross/blackfriday.v2 v2.0.1
)

replace gopkg.in/russross/blackfriday.v2 v2.0.1 => github.com/russross/blackfriday/v2 v2.0.1
