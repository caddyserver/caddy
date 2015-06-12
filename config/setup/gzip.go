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
		mimeFilter := gzip.MIMEFilter{make(gzip.Set)}
		extFilter := gzip.ExtFilter{make(gzip.Set)}

		// no extra args expected
		if len(c.RemainingArgs()) > 0 {
			return configs, c.ArgErr()
		}

		for c.NextBlock() {
			switch c.Val() {
			case "mimes":
				mimes := c.RemainingArgs()
				if len(mimes) == 0 {
					return configs, c.ArgErr()
				}
				for _, m := range mimes {
					if !gzip.ValidMIME(m) {
						return configs, fmt.Errorf("Invalid MIME %v.", m)
					}
					mimeFilter.Types.Add(m)
				}
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

		config.Filters = []gzip.Filter{}

		// if ignored paths are specified, put in front to filter with path first
		if len(pathFilter.IgnoredPaths) > 0 {
			config.Filters = []gzip.Filter{pathFilter}
		}

		// if mime types are specified, use it and ignore extensions
		if len(mimeFilter.Types) > 0 {
			config.Filters = append(config.Filters, mimeFilter)

			// if extensions are specified, use it
		} else if len(extFilter.Exts) > 0 {
			config.Filters = append(config.Filters, extFilter)

			// neither is specified, use default mime types
		} else {
			config.Filters = append(config.Filters, gzip.DefaultMIMEFilter())
		}

		configs = append(configs, config)
	}

	return configs, nil
}
