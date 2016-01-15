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

		// Request Filters
		pathFilter := gzip.PathFilter{IgnoredPaths: make(gzip.Set)}
		extFilter := gzip.ExtFilter{Exts: make(gzip.Set)}

		// Response Filters
		lengthFilter := gzip.LengthFilter(0)

		// No extra args expected
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
					if !strings.HasPrefix(e, ".") && e != gzip.ExtWildCard && e != "" {
						return configs, fmt.Errorf(`gzip: invalid extension "%v" (must start with dot)`, e)
					}
					extFilter.Exts.Add(e)
				}
			case "not":
				paths := c.RemainingArgs()
				if len(paths) == 0 {
					return configs, c.ArgErr()
				}
				for _, p := range paths {
					if p == "/" {
						return configs, fmt.Errorf(`gzip: cannot exclude path "/" - remove directive entirely instead`)
					}
					if !strings.HasPrefix(p, "/") {
						return configs, fmt.Errorf(`gzip: invalid path "%v" (must start with /)`, p)
					}
					pathFilter.IgnoredPaths.Add(p)
				}
			case "level":
				if !c.NextArg() {
					return configs, c.ArgErr()
				}
				level, _ := strconv.Atoi(c.Val())
				config.Level = level
			case "min_length":
				if !c.NextArg() {
					return configs, c.ArgErr()
				}
				length, err := strconv.ParseInt(c.Val(), 10, 64)
				if err != nil {
					return configs, err
				} else if length == 0 {
					return configs, fmt.Errorf(`gzip: min_length must be greater than 0`)
				}
				lengthFilter = gzip.LengthFilter(length)
			default:
				return configs, c.ArgErr()
			}
		}

		// Request Filters
		config.RequestFilters = []gzip.RequestFilter{}

		// If ignored paths are specified, put in front to filter with path first
		if len(pathFilter.IgnoredPaths) > 0 {
			config.RequestFilters = []gzip.RequestFilter{pathFilter}
		}

		// Then, if extensions are specified, use those to filter.
		// Otherwise, use default extensions filter.
		if len(extFilter.Exts) > 0 {
			config.RequestFilters = append(config.RequestFilters, extFilter)
		} else {
			config.RequestFilters = append(config.RequestFilters, gzip.DefaultExtFilter())
		}

		// Response Filters
		// If min_length is specified, use it.
		if int64(lengthFilter) != 0 {
			config.ResponseFilters = append(config.ResponseFilters, lengthFilter)
		}

		configs = append(configs, config)
	}

	return configs, nil
}
