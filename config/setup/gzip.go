package setup

import (
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/gzip"
)

// Gzip configures a new gzip middleware instance.
func Gzip(c *Controller) (middleware.Middleware, error) {
	return func(next middleware.Handler) middleware.Handler {
		return gzip.Gzip{Next: next}
	}, nil
}
