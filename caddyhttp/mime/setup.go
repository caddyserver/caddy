package mime

import (
	"fmt"
	"strings"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("mime", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

// setup configures a new mime middleware instance.
func setup(c *caddy.Controller) error {
	configs, err := mimeParse(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Mime{Next: next, Configs: configs}
	})

	return nil
}

func mimeParse(c *caddy.Controller) (Config, error) {
	configs := Config{}

	for c.Next() {
		// At least one extension is required

		args := c.RemainingArgs()
		switch len(args) {
		case 2:
			if err := validateExt(configs, args[0]); err != nil {
				return configs, err
			}
			configs[args[0]] = args[1]
		case 1:
			return configs, c.ArgErr()
		case 0:
			for c.NextBlock() {
				ext := c.Val()
				if err := validateExt(configs, ext); err != nil {
					return configs, err
				}
				if !c.NextArg() {
					return configs, c.ArgErr()
				}
				configs[ext] = c.Val()
			}
		}

	}

	return configs, nil
}

// validateExt checks for valid file name extension.
func validateExt(configs Config, ext string) error {
	if !strings.HasPrefix(ext, ".") {
		return fmt.Errorf(`mime: invalid extension "%v" (must start with dot)`, ext)
	}
	if _, ok := configs[ext]; ok {
		return fmt.Errorf(`mime: duplicate extension "%v" found`, ext)
	}
	return nil
}
