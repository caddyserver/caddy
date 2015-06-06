package setup

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/gzip"
)

// Gzip configures a new gzip middleware instance.
func Gzip(c *Controller) (middleware.Middleware, error) {
	configs, err := gzipParse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return gzip.Gzip{Next: next, Configs: configs}
	}, nil
}

func gzipParse(c *Controller) ([]gzip.Config, error) {
	var configs []gzip.Config

	for c.Next() {
		config := gzip.Config{}

		pathFilter := gzip.PathFilter{make(gzip.Set)}
		extFilter := gzip.DefaultExtFilter()

		// no extra args expected
		if len(c.RemainingArgs()) > 0 {
			return configs, c.ArgErr()
		}

		for c.NextBlock() {
			switch c.Val() {
			case "ext":
				exts := c.RemainingArgs()
				if len(exts) == 0 {
					return configs, c.ArgErr()
				}
				for _, e := range exts {
					if !strings.HasPrefix(e, ".") {
						return configs, fmt.Errorf(`Invalid extension %v. Should start with "."`, e)
					}
					extFilter.Exts.Add(e)
				}
			case "not":
				paths := c.RemainingArgs()
				if len(paths) == 0 {
					return configs, c.ArgErr()
				}
				for _, p := range paths {
					if !strings.HasPrefix(p, "/") {
						return configs, fmt.Errorf(`Invalid path %v. Should start with "/"`, p)
					}
					pathFilter.IgnoredPaths.Add(p)
					// Warn user if / is used
					if p == "/" {
						fmt.Println("Warning: Paths ignored by gzip includes wildcard(/). No request will be gzipped.\nRemoving gzip directive from Caddyfile is preferred if this is intended.")
					}
				}
			case "level":
				if !c.NextArg() {
					return configs, c.ArgErr()
				}
				level, _ := strconv.Atoi(c.Val())
				config.Level = level
			default:
				return configs, c.ArgErr()
			}
		}

		// put pathFilter in front to filter with path first
		config.Filters = []gzip.Filter{pathFilter, extFilter}

		configs = append(configs, config)
	}

	return configs, nil
}
