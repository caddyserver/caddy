package config

import (
	"github.com/mholt/caddy/config/parse"
	"github.com/mholt/caddy/config/setup"
	"github.com/mholt/caddy/middleware"
)

func init() {
	// The parse package must know which directives
	// are valid, but it must not import the setup
	// or config package. To solve this problem, we
	// fill up this map in our init function here.
	// The parse package does not need to know the
	// ordering of the directives.
	for _, dir := range directiveOrder {
		parse.ValidDirectives[dir.name] = struct{}{}
	}
}

// Directives are registered in the order they should be
// executed. Middleware (directives that inject a handler)
// are executed in the order A-B-C-*-C-B-A, assuming
// they all call the Next handler in the chain.
//
// Ordering is VERY important. Every middleware will
// feel the effects of all other middleware below
// (after) them during a request, but they must not
// care what middleware above them are doing.
//
// For example, log needs to know the status code and
// exactly how many bytes were written to the client,
// which every other middleware can affect, so it gets
// registered first. The errors middleware does not
// care if gzip or log modifies its response, so it
// gets registered below them. Gzip, on the other hand,
// DOES care what errors does to the response since it
// must compress every output to the client, even error
// pages, so it must be registered before the errors
// middleware and any others that would write to the
// response.
var directiveOrder = []directive{
	// Essential directives that initialize vital configuration settings
	{"root", setup.Root},
	{"tls", setup.TLS},
	{"bind", setup.BindHost},

	// Other directives that don't create HTTP handlers
	{"startup", setup.Startup},
	{"shutdown", setup.Shutdown},

	// Directives that inject handlers (middleware)
	{"log", setup.Log},
	{"gzip", setup.Gzip},
	{"errors", setup.Errors},
	{"header", setup.Headers},
	{"rewrite", setup.Rewrite},
	{"redir", setup.Redir},
	{"ext", setup.Ext},
	{"basicauth", setup.BasicAuth},
	{"internal", setup.Internal},
	{"proxy", setup.Proxy},
	{"fastcgi", setup.FastCGI},
	{"websocket", setup.WebSocket},
	{"markdown", setup.Markdown},
	{"templates", setup.Templates},
	{"browse", setup.Browse},
}

// directive ties together a directive name with its setup function.
type directive struct {
	name  string
	setup SetupFunc
}

// A setup function takes a setup controller. Its return values may
// both be nil. If middleware is not nil, it will be chained into
// the HTTP handlers in the order specified in this package.
type SetupFunc func(c *setup.Controller) (middleware.Middleware, error)
