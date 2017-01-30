package root

import (
	"log"
	"os"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func init() {
	caddy.RegisterPlugin("root", caddy.Plugin{
		ServerType: "http",
		Action:     setupRoot,
	})
}

func setupRoot(c *caddy.Controller) error {
	config := httpserver.GetConfig(c)

	for c.Next() {
		if !c.NextArg() {
			return c.ArgErr()
		}
		config.Root = c.Val()
		if c.NextArg() {
			// only one argument allowed
			return c.ArgErr()
		}
	}

	// Check if root path exists
	_, err := os.Stat(config.Root)
	if err != nil {
		if os.IsNotExist(err) {
			// Allow this, because the folder might appear later.
			// But make sure the user knows!
			log.Printf("[WARNING] Root path does not exist: %s", config.Root)
		} else {
			return c.Errf("Unable to access root path '%s': %v", config.Root, err)
		}
	}

	return nil
}
