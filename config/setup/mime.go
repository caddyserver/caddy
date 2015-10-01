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

func mimeParse(c *Controller) ([]mime.Config, error) {
	var configs []mime.Config

	for c.Next() {
		// At least one extension is required

		args := c.RemainingArgs()
		switch len(args) {
		case 2:
			if err := validateExt(args[0]); err != nil {
				return configs, err
			}
			configs = append(configs, mime.Config{Ext: args[0], ContentType: args[1]})
		case 1:
			return configs, c.ArgErr()
		case 0:
			for c.NextBlock() {
				ext := c.Val()
				if err := validateExt(ext); err != nil {
					return configs, err
				}
				if !c.NextArg() {
					return configs, c.ArgErr()
				}
				configs = append(configs, mime.Config{Ext: ext, ContentType: c.Val()})
			}
		}

	}

	return configs, nil
}

// validateExt checks for valid file name extension.
func validateExt(ext string) error {
	if !strings.HasPrefix(ext, ".") {
		return fmt.Errorf(`mime: invalid extension "%v" (must start with dot)`, ext)
	}
	return nil
}
