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

package tracing

import (
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/mholt/caddy/caddyhttp/tracing/zipkin"
)

func init() {
	caddy.RegisterPlugin("tracing", caddy.Plugin{
		ServerType: "http",
		Action:     setup,
	})
}

type config struct {
	backend string
	zipkin  zipkin.Config
}

func setup(c *caddy.Controller) (err error) {
	config, err := tracingParse(c)
	if err != nil {
		return
	}

	var mw func(next httpserver.Handler) httpserver.Handler
	switch config.backend {
	case "zipkin":
		mw, err = zipkin.MiddlewareMaker(config.zipkin)
		if err != nil {
			return
		}
	}

	httpserver.GetConfig(c).AddMiddleware(mw)
	return nil
}

func tracingParse(c *caddy.Controller) (*config, error) {
	cfg := &config{}
	for c.Next() {
		if c.NextArg() {
			cfg.backend = c.Val()
		}

		for c.NextBlock() {
			switch cfg.backend {
			case "zipkin":
				for c.NextArg() {
					switch c.Val() {
					case "service_name":
						c.NextArg()
						cfg.zipkin.LocalEndpointServiceName = c.Val()
					case "reporter":
						c.NextArg()
						cfg.zipkin.Reporter = c.Val()
					case "reporter_http_endpoint":
						c.NextArg()
						cfg.zipkin.ReporterHTTPEndpoint = c.Val()
					case "sampler":
						c.NextArg()
						cfg.zipkin.Sampler = c.Val()
					default:
						return nil, c.ArgErr()
					}
				}
			default:
				return nil, c.Errf("unknown backend '%s'", cfg.backend)
			}
		}

		if c.NextArg() {
			return nil, c.ArgErr()
		}
	}

	return cfg, nil
}
