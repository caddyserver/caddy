package caddyhttp

import (
	// plug in the server
	_ "github.com/mholt/caddy/caddyhttp/httpserver"

	// plug in the standard directives
	_ "github.com/mholt/caddy/caddyhttp/bind"
	_ "github.com/mholt/caddy/caddyhttp/gzip"
	_ "github.com/mholt/caddy/caddyhttp/log"
	_ "github.com/mholt/caddy/caddyhttp/root"
	_ "github.com/mholt/caddy/startupshutdown"
)
