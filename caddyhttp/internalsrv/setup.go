package internalsrv

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("internal", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// Internal configures a new Internal middleware instance.
func setup(c *caddy.Controller) error {
	paths, err := internalParse(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Internal{Next: next, Paths: paths}
	})

	return nil
}

func internalParse(c *caddy.Controller) ([]string, error) {
	var paths []string

	for c.Next() {
		if c.NextArg() {
			paths = append(paths, c.Val())
		}
		if c.NextArg() {
			return nil, c.ArgErr()
		}
	}

	return paths, nil
}
