package caddyhttp

import (
	// plug in the server
	_ "github.com/mholt/caddy2/caddyhttp/httpserver"

	// plug in its directives
	_ "github.com/mholt/caddy2/caddyhttp/bind"
	_ "github.com/mholt/caddy2/caddyhttp/root"
)
