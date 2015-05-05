package setup

import "github.com/mholt/caddy/middleware"

func TLS(c *Controller) (middleware.Middleware, error) {
	c.TLS.Enabled = c.Port != "http"

	for c.Next() {
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		c.TLS.Certificate = c.Val()

		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		c.TLS.Key = c.Val()
	}

	return nil, nil
}
