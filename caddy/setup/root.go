package setup

import (
	"log"
	"os"

	"github.com/mholt/caddy/middleware"
)

func Root(c *Controller) (middleware.Middleware, error) {
	for c.Next() {
		if !c.NextArg() {
			return nil, c.ArgErr()
		}
		c.Root = c.Val()
	}

	// Check if root path exists
	_, err := os.Stat(c.Root)
	if err != nil {
		if os.IsNotExist(err) {
			// Allow this, because the folder might appear later.
			// But make sure the user knows!
			log.Printf("Warning: Root path does not exist: %s", c.Root)
		} else {
			return nil, c.Errf("Unable to access root path '%s': %v", c.Root, err)
		}
	}

	return nil, nil
}
