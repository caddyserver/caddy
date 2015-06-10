package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/inner"
)

// Internal configures a new Internal middleware instance.
func Internal(c *Controller) (middleware.Middleware, error) {
	paths, err := internalParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return inner.Internal{Next: next, Paths: paths}
	}, nil
}

func internalParse(c *Controller) ([]string, error) {
	var paths []string

	for c.Next() {
		if !c.NextArg() {
			return paths, c.ArgErr()
		}
		paths = append(paths, c.Val())
	}

	return paths, nil
}
