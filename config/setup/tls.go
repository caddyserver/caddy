package setup

import (
	"github.com/mholt/caddy/middleware"
	"log"
)

func TLS(c *Controller) (middleware.Middleware, error) {
	c.TLS.Enabled = true
	if c.Port == "http" {
		c.TLS.Enabled = false
		log.Printf("Warning: TLS was disabled on host http://%s."+
			" Make sure you are specifying https://%s in your config (if you haven't already)."+
			" If you meant to serve tls on port 80,"+
			" specify port 80 in your config (http://%s:80).", c.Host, c.Host, c.Host)
	}

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
