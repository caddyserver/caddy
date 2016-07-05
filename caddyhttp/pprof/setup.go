package pprof

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("pprof", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup returns a new instance of a pprof handler. It accepts no arguments or options.
func setup(c *caddy.Controller) error {
	found := false

	for c.Next() {
		if found {
			return c.Err("pprof can only be specified once")
		}
		if len(c.RemainingArgs()) != 0 {
			return c.ArgErr()
		}
		if c.NextBlock() {
			return c.ArgErr()
		}
		found = true
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return &Handler{Next: next, Mux: NewMux()}
	})

	return nil
}
