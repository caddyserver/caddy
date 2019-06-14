package main

import (
	caddycmd "github.com/caddyserver/caddy/cmd"

	// this is where modules get plugged in
	_ "github.com/caddyserver/caddy/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/caddylog"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/encode"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/encode/brotli"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/encode/gzip"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/encode/zstd"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/fileserver"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/headers"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/markdown"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/requestbody"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy/modules/caddyhttp/rewrite"
	_ "github.com/caddyserver/caddy/modules/caddytls"
	_ "github.com/caddyserver/caddy/modules/caddytls/standardstek"
)

func main() {
	caddycmd.Main()
}
