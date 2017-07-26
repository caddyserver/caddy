package caddyhttp

import (
	// plug in the server
	_ "github.com/mholt/caddy/caddyhttp/httpserver"

	// plug in the standard directives
	_ "github.com/mholt/caddy/caddyhttp/basicauth"
	_ "github.com/mholt/caddy/caddyhttp/bind"
	_ "github.com/mholt/caddy/caddyhttp/browse"
	_ "github.com/mholt/caddy/caddyhttp/errors"
	_ "github.com/mholt/caddy/caddyhttp/expvar"
	_ "github.com/mholt/caddy/caddyhttp/extensions"
	_ "github.com/mholt/caddy/caddyhttp/fastcgi"
	_ "github.com/mholt/caddy/caddyhttp/gzip"
	_ "github.com/mholt/caddy/caddyhttp/header"
	_ "github.com/mholt/caddy/caddyhttp/index"
	_ "github.com/mholt/caddy/caddyhttp/internalsrv"
	_ "github.com/mholt/caddy/caddyhttp/limits"
	_ "github.com/mholt/caddy/caddyhttp/log"
	_ "github.com/mholt/caddy/caddyhttp/markdown"
	_ "github.com/mholt/caddy/caddyhttp/mime"
	_ "github.com/mholt/caddy/caddyhttp/pprof"
	_ "github.com/mholt/caddy/caddyhttp/proxy"
	_ "github.com/mholt/caddy/caddyhttp/push"
	_ "github.com/mholt/caddy/caddyhttp/redirect"
	_ "github.com/mholt/caddy/caddyhttp/requestid"
	_ "github.com/mholt/caddy/caddyhttp/rewrite"
	_ "github.com/mholt/caddy/caddyhttp/root"
	_ "github.com/mholt/caddy/caddyhttp/status"
	_ "github.com/mholt/caddy/caddyhttp/templates"
	_ "github.com/mholt/caddy/caddyhttp/timeouts"
	_ "github.com/mholt/caddy/caddyhttp/websocket"
	_ "github.com/mholt/caddy/startupshutdown"
)
