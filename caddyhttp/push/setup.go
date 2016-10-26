package push

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("push", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Push middleware
func setup(c *caddy.Controller) error {
	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Middleware{Next: next, Rules: rules}
	})
}
