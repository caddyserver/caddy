// Copyright 2015 Light Code Labs, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compress

import (
	"fmt"
	"strconv"
	"strings"

	"compress/gzip"

	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// setup configures a new gzip middleware instance.
func setup(c *caddy.Controller) error {
	configs, err := compressParse(c)
	if err != nil {
		return err
	}

	httpserver.GetConfig(c).AddMiddleware(func(next httpserver.Handler) httpserver.Handler {
		return Compress{Next: next, Configs: configs}
	})

	return nil
}

var compressionSchemes []string = []string{"gzip", "zstd"}

func compressParse(c *caddy.Controller) ([]Config, error) {
	var configs []Config

	for c.Next() {
		config := Config{}

		// Request Filters
		pathFilter := PathFilter{IgnoredPaths: make(Set)}
		extFilter := ExtFilter{Exts: make(Set)}

		// Response Filters
		lengthFilter := LengthFilter(0)

		// the compression scheme
		var scheme string
		if !c.NextArg() {
			scheme = "gzip"
		} else {
			scheme = c.Val()
			validScheme := false
			for _, s := range compressionSchemes {
				if scheme == s {
					validScheme = true
				}
			}
			if !validScheme {
				return configs, fmt.Errorf("compress: invalid or no compression scheme selected")
			}
		}

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
					if !strings.HasPrefix(e, ".") && e != ExtWildCard && e != "" {
						return configs, fmt.Errorf(`compress: invalid extension "%v" (must start with dot)`, e)
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
						return configs, fmt.Errorf(`compress: cannot exclude path "/" - remove directive entirely instead`)
					}
					if !strings.HasPrefix(p, "/") {
						return configs, fmt.Errorf(`compress: invalid path "%v" (must start with /)`, p)
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
				} else if length <= 0 {
					return configs, fmt.Errorf(`compress: min_length must be greater than 0`)
				}
				lengthFilter = LengthFilter(length)
			default:
				return configs, c.ArgErr()
			}
		}

		// Request Filters
		config.RequestFilters = []RequestFilter{}

		// If ignored paths are specified, put in front to filter with path first
		if len(pathFilter.IgnoredPaths) > 0 {
			config.RequestFilters = []RequestFilter{pathFilter}
		}

		// Then, if extensions are specified, use those to filter.
		// Otherwise, use default extensions filter.
		if len(extFilter.Exts) > 0 {
			config.RequestFilters = append(config.RequestFilters, extFilter)
		} else {
			config.RequestFilters = append(config.RequestFilters, DefaultExtFilter())
		}

		config.ResponseFilters = append(config.ResponseFilters, SkipCompressedFilter{})

		// Response Filters
		// If min_length is specified, use it.
		if int64(lengthFilter) != 0 {
			config.ResponseFilters = append(config.ResponseFilters, lengthFilter)
		}

		config.Scheme = scheme
		configs = append(configs, config)
		// why do we have multiple configs?! TODO_DARSHANIME
	}

	return configs, nil
}


func getWriter(c Config) (compressWriter, error) {
	switch c.Scheme {
	case "gzip":
		return getGzipWriter(c.Level), nil
	case "zstd":
		return getZstdWriter(c.Level), nil
	default:
		return nil, fmt.Errorf("No valid writer found")
	}
}

func putWriter(c Config, w compressWriter) {
	switch c.Scheme {
	case "gzip":
		gw := w.(*gzip.Writer)
		putGzipWriter(c.Level, gw)
	case "zstd":
		zw := w.(*zstdWriter)
		putZstdWriter(c.Level, zw)
	default:
		fmt.Println("in put writer, default case")
	}
}
