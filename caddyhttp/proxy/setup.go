package proxy

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("proxy", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new Proxy middleware instance.
func setup(c *caddy.Controller) error {
	upstreams, err := NewStaticUpstreams(c.Dispenser)
	if err != nil {
		return err
	}
	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Proxy{Next: next, Upstreams: upstreams}
	})
	return nil
}
