package setup

import (
	"fmt"
	"strings"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/mime"
)

// Mime configures a new mime middleware instance.
func Mime(c *Controller) (middleware.Middleware, error) {
	configs, err := mimeParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return mime.Mime{Next: next, Configs: configs}
	}, nil
}

func mimeParse(c *Controller) (mime.Config, error) {
	configs := mime.Config{}

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
func validateExt(configs mime.Config, ext string) error {
	if !strings.HasPrefix(ext, ".") {
		return fmt.Errorf(`mime: invalid extension "%v" (must start with dot)`, ext)
	}
	if _, ok := configs[ext]; ok {
		return fmt.Errorf(`mime: duplicate extension "%v" found`, ext)
	}
	return nil
}
