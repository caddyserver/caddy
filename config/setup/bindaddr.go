package setup

import "github.com/mholt/caddy/middleware"

func BindAddr(c *Controller) (middleware.Middleware, error) {
	for c.Next() {
		if !c.Args(&c.BindAddress) {
			return nil, c.ArgErr()
		}
	}
	return nil, nil
}
