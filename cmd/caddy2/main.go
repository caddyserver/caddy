package main

import (
	caddycmd "github.com/caddyserver/caddy2/cmd"

	// this is where modules get plugged in
	_ "github.com/caddyserver/caddy2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy2/modules/caddyhttp/caddylog"
	_ "github.com/caddyserver/caddy2/modules/caddyhttp/fileserver"
	_ "github.com/caddyserver/caddy2/modules/caddyhttp/headers"
	_ "github.com/caddyserver/caddy2/modules/caddyhttp/markdown"
	_ "github.com/caddyserver/caddy2/modules/caddyhttp/requestbody"
	_ "github.com/caddyserver/caddy2/modules/caddyhttp/reverseproxy"
	_ "github.com/caddyserver/caddy2/modules/caddyhttp/rewrite"
	_ "github.com/caddyserver/caddy2/modules/caddytls"
	_ "github.com/caddyserver/caddy2/modules/caddytls/standardstek"
)

func main() {
	caddycmd.Main()
}
