package config

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/basicauth"
	"github.com/mholt/caddy/middleware/browse"
	"github.com/mholt/caddy/middleware/errors"
	"github.com/mholt/caddy/middleware/extensions"
	"github.com/mholt/caddy/middleware/fastcgi"
	"github.com/mholt/caddy/middleware/git"
	"github.com/mholt/caddy/middleware/gzip"
	"github.com/mholt/caddy/middleware/headers"
	"github.com/mholt/caddy/middleware/log"
	"github.com/mholt/caddy/middleware/markdown"
	"github.com/mholt/caddy/middleware/proxy"
	"github.com/mholt/caddy/middleware/redirect"
	"github.com/mholt/caddy/middleware/rewrite"
	"github.com/mholt/caddy/middleware/templates"
	"github.com/mholt/caddy/middleware/websockets"
)

// This init function registers middleware. Register
// middleware in the order they should be executed
// during a request (A, B, C...). Middleware execute
// in the order A-B-C-*-C-B-A, assuming they call
// the Next handler in the chain.
//
// Note: Ordering is VERY important. Every middleware
// will feel the effects of all other middleware below
// (after) them, but must not care what middleware above
// them are doing.
//
// For example, log needs to know the status code and exactly
// how many bytes were written to the client, which every
// other middleware can affect, so it gets registered first.
// The errors middleware does not care if gzip or log modifies
// its response, so it gets registered below them. Gzip, on the
// other hand, DOES care what errors does to the response since
// it must compress every output to the client, even error pages,
// so it must be registered before the errors middleware and any
// others that would write to the response.
func init() {
	register("log", log.New)
	register("gzip", gzip.New)
	register("errors", errors.New)
	register("header", headers.New)
	register("rewrite", rewrite.New)
	register("redir", redirect.New)
	register("ext", extensions.New)
	register("basicauth", basicauth.New)
	register("proxy", proxy.New)
	register("git", git.New)
	register("fastcgi", fastcgi.New)
	register("websocket", websockets.New)
	register("markdown", markdown.New)
	register("templates", templates.New)
	register("browse", browse.New)
}

// registry stores the registered middleware:
// both the order and the directives to which they
// are bound.
var registry = struct {
	directiveMap map[string]middleware.Generator
	ordered      []string
}{
	directiveMap: make(map[string]middleware.Generator),
}

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
