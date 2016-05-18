package bind

import (
	"github.com/mholt/caddy2"
	"github.com/mholt/caddy2/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin(caddy.Plugin{
		Name:       "bind",
		ServerType: "http",
		Action:     setupBind,
	})
}

func setupBind(c *caddy.Controller) error {
	config := httpserver.GetConfig(c.Key)
	for c.Next() {
		if !c.Args(&config.ListenHost) {
			return c.ArgErr()
		}
	}
	return nil
}
