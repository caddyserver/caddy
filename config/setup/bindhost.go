package setup

import "github.com/mholt/caddy/middleware"

func BindHost(c *Controller) (middleware.Middleware, error) {
	for c.Next() {
		if !c.Args(&c.BindHost) {
			return nil, c.ArgErr()
		}
	}
	return nil, nil
}
