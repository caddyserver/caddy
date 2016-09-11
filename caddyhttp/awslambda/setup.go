package awslambda

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("awslambda", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new AWS Lambda middleware instance.
func setup(c *caddy.Controller) error {
	configs, err := ParseConfigs(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Handler{
			Next:    next,
			Configs: configs,
		}
	})
	return nil
}
