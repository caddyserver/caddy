package config

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/extensionless"
	"github.com/mholt/caddy/middleware/fastcgi"
	"github.com/mholt/caddy/middleware/gzip"
	"github.com/mholt/caddy/middleware/headers"
	"github.com/mholt/caddy/middleware/log"
	"github.com/mholt/caddy/middleware/markdown"
	"github.com/mholt/caddy/middleware/proxy"
	"github.com/mholt/caddy/middleware/redirect"
	"github.com/mholt/caddy/middleware/rewrite"
	"github.com/mholt/caddy/middleware/websockets"
)

// This init function registers middleware. Register middleware
// in the order they should be executed during a request.
// Middleware execute in this order: A-B-C-*-C-B-A
func init() {
	register("gzip", gzip.New)
	register("header", headers.New)
	register("log", log.New)
	register("rewrite", rewrite.New)
	register("redirect", redirect.New)
	register("ext", extensionless.New)
	register("proxy", proxy.New)
	register("fastcgi", fastcgi.New)
	register("websocket", websockets.New)
	register("markdown", markdown.New)
}

var (
	// registry stores the registered middleware:
	// both the order and the directives to which they
	// are bound.
	registry = struct {
		directiveMap map[string]middleware.Generator
		ordered      []string
	}{
		directiveMap: make(map[string]middleware.Generator),
	}
)

// register binds a middleware generator (outer function)
// to a directive. Upon each request, middleware will be
// executed in the order they are registered.
func register(directive string, generator middleware.Generator) {
	registry.directiveMap[directive] = generator
	registry.ordered = append(registry.ordered, directive)
}

// middlewareRegistered returns whether or not a directive is registered.
func middlewareRegistered(directive string) bool {
	_, ok := registry.directiveMap[directive]
	return ok
}
