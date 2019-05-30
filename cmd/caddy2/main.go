package main

import (
	caddycmd "bitbucket.org/lightcodelabs/caddy2/cmd"

	// this is where modules get plugged in
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp/caddylog"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp/fileserver"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp/headers"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp/markdown"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp/requestbody"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp/reverseproxy"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp/rewrite"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddytls"
	_ "bitbucket.org/lightcodelabs/caddy2/modules/caddytls/standardstek"
)

func main() {
	caddycmd.Main()
}
