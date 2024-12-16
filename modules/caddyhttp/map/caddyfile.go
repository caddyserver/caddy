// Copyright 2015 Matthew Holt and The Caddy Authors
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

package maphandler

import (
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("map", parseCaddyfile)
}

// parseCaddyfile sets up the map handler from Caddyfile tokens. Syntax:
//
//	map [<matcher>] <source> <destinations...> {
//	    [~]<input> <outputs...>
//	    default    <defaults...>
//	}
//
// If the input value is prefixed with a tilde (~), then the input will be parsed as a
// regular expression.
//
// The Caddyfile adapter treats outputs that are a literal hyphen (-) as a null/nil
// value. This is useful if you want to fall back to default for that particular output.
//
// The number of outputs for each mapping must not be more than the number of destinations.
// However, for convenience, there may be fewer outputs than destinations and any missing
// outputs will be filled in implicitly.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name

	var handler Handler

	// source
	if !h.NextArg() {
		return nil, h.ArgErr()
	}
	handler.Source = h.Val()

	// destinations
	handler.Destinations = h.RemainingArgs()
	if len(handler.Destinations) == 0 {
		return nil, h.Err("missing destination argument(s)")
	}
	for _, dest := range handler.Destinations {
		if shorthand := httpcaddyfile.WasReplacedPlaceholderShorthand(dest); shorthand != "" {
			return nil, h.Errf("destination %s conflicts with a Caddyfile placeholder shorthand", shorthand)
		}
	}

	// mappings
	for h.NextBlock(0) {
		// defaults are a special case
		if h.Val() == "default" {
			if len(handler.Defaults) > 0 {
				return nil, h.Err("defaults already defined")
			}
			handler.Defaults = h.RemainingArgs()
			for len(handler.Defaults) < len(handler.Destinations) {
				handler.Defaults = append(handler.Defaults, "")
			}
			continue
		}

		// every line maps an input value to one or more outputs
		in := h.Val()
		var outs []any
		for h.NextArg() {
			val := h.ScalarVal()
			if val == "-" {
				outs = append(outs, nil)
			} else {
				outs = append(outs, val)
			}
		}

		// cannot have more outputs than destinations
		if len(outs) > len(handler.Destinations) {
			return nil, h.Err("too many outputs")
		}

		// for convenience, can have fewer outputs than destinations, but the
		// underlying handler won't accept that, so we fill in nil values
		for len(outs) < len(handler.Destinations) {
			outs = append(outs, nil)
		}

		// create the mapping
		mapping := Mapping{Outputs: outs}
		if strings.HasPrefix(in, "~") {
			mapping.InputRegexp = in[1:]
		} else {
			mapping.Input = in
		}

		handler.Mappings = append(handler.Mappings, mapping)
	}
	return handler, nil
}
