package index

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
)

func init() {
	caddy.RegisterPlugin("index", caddy.Plugin{
		ServerType: "http",
		Action:     setupIndex,
	})
}

func setupIndex(c *caddy.Controller) error {
	var index []string

	for c.Next() {
		args := c.RemainingArgs()

		if len(args) == 0 {
			return c.Errf("Expected at least one index")
		}

		for _, in := range args {
			index = append(index, in)
		}

		staticfiles.IndexPages = index
	}

	return nil
}
