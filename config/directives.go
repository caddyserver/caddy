package config

import (
	"github.com/mholt/caddy/config/parse"
	"github.com/mholt/caddy/config/setup"
	"github.com/mholt/caddy/middleware"
)

func init() {
	// The parse package must know which directives
	// are valid, but it must not import the setup
	// or config package.
	for _, dir := range directiveOrder {
		parse.ValidDirectives[dir.name] = struct{}{}
	}
}

var directiveOrder = []directive{
	{"root", setup.Root},
	{"tls", setup.TLS},
	{"startup", setup.Startup},
	{"shutdown", setup.Shutdown},

	{"log", setup.Log},
	{"gzip", setup.Gzip},
	{"errors", setup.Errors},
	{"header", setup.Headers},
	{"rewrite", setup.Rewrite},
	{"redir", setup.Redir},
	{"ext", setup.Ext},
	{"basicauth", setup.BasicAuth},
	{"proxy", setup.Proxy},
	{"fastcgi", setup.FastCGI},
	// {"websocket", setup.WebSocket},
	// {"markdown", setup.Markdown},
	// {"templates", setup.Templates},
	// {"browse", setup.Browse},
}

type directive struct {
	name  string
	setup setupFunc
}

type setupFunc func(c *setup.Controller) (middleware.Middleware, error)
