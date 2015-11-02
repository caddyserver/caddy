package setup

import "github.com/mholt/caddy/middleware"

// BindHost sets the host to bind the listener to.
func BindHost(c *Controller) (middleware.Middleware, error) {
	for c.Next() {
		if !c.Args(&c.BindHost) {
			return nil, c.ArgErr()
		}
	}
	return nil, nil
}
