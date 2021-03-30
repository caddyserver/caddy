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

package encode

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("encode", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	enc := new(Encode)
	err := enc.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     encode [<matcher>] <formats...> {
//         gzip           [<level>]
//         zstd
//         minimum_length <length>
//         prefer         <formats...>
//         # response matcher block
//         match {
//             status <code...>
//             header <field> [<value>]
//         }
//         # or response matcher single line syntax
//         match [header <field> [<value>]] | [status <code...>]
//     }
//
// Specifying the formats on the first line will use those formats' defaults.
func (enc *Encode) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	responseMatchers := make(map[string]caddyhttp.ResponseMatcher)
	for d.Next() {
		for _, arg := range d.RemainingArgs() {
			mod, err := caddy.GetModule("http.encoders." + arg)
			if err != nil {
				return d.Errf("finding encoder module '%s': %v", mod, err)
			}
			encoding, ok := mod.New().(Encoding)
			if !ok {
				return d.Errf("module %s is not an HTTP encoding", mod)
			}
			if enc.EncodingsRaw == nil {
				enc.EncodingsRaw = make(caddy.ModuleMap)
			}
			enc.EncodingsRaw[arg] = caddyconfig.JSON(encoding, nil)
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "minimum_length":
				if !d.NextArg() {
					return d.ArgErr()
				}
				minLength, err := strconv.Atoi(d.Val())
				if err != nil {
					return err
				}
				enc.MinLength = minLength
			case "prefer":
				var encs []string
				for d.NextArg() {
					encs = append(encs, d.Val())
				}
				if len(encs) == 0 {
					return d.ArgErr()
				}
				enc.Prefer = encs
			case "match":
				err := enc.parseNamedResponseMatcher(d.NewFromNextSegment(), responseMatchers)
				if err != nil {
					return err
				}
				matcher := responseMatchers["match"]
				enc.Matcher = &matcher
			default:
				name := d.Val()
				modID := "http.encoders." + name
				unm, err := caddyfile.UnmarshalModule(d, modID)
				if err != nil {
					return err
				}
				encoding, ok := unm.(Encoding)
				if !ok {
					return d.Errf("module %s is not an HTTP encoding; is %T", modID, unm)
				}
				if enc.EncodingsRaw == nil {
					enc.EncodingsRaw = make(caddy.ModuleMap)
				}
				enc.EncodingsRaw[name] = caddyconfig.JSON(encoding, nil)
			}
		}
	}

	return nil
}

// Parse the tokens of a named response matcher.
//
//     match {
//         header <field> [<value>]
//         status <code...>
//     }
//
// Or, single line syntax:
//
//     match [header <field> [<value>]] | [status <code...>]
//
func (enc *Encode) parseNamedResponseMatcher(d *caddyfile.Dispenser, matchers map[string]caddyhttp.ResponseMatcher) error {
	for d.Next() {
		definitionName := d.Val()

		if _, ok := matchers[definitionName]; ok {
			return d.Errf("matcher is defined more than once: %s", definitionName)
		}

		matcher := caddyhttp.ResponseMatcher{}
		for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
			switch d.Val() {
			case "header":
				if matcher.Headers == nil {
					matcher.Headers = http.Header{}
				}

				// reuse the header request matcher's unmarshaler
				headerMatcher := caddyhttp.MatchHeader(matcher.Headers)
				err := headerMatcher.UnmarshalCaddyfile(d.NewFromNextSegment())
				if err != nil {
					return err
				}

				matcher.Headers = http.Header(headerMatcher)
			case "status":
				if matcher.StatusCode == nil {
					matcher.StatusCode = []int{}
				}

				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}

				for _, arg := range args {
					if len(arg) == 3 && strings.HasSuffix(arg, "xx") {
						arg = arg[:1]
					}
					statusNum, err := strconv.Atoi(arg)
					if err != nil {
						return d.Errf("bad status value '%s': %v", arg, err)
					}
					matcher.StatusCode = append(matcher.StatusCode, statusNum)
				}
			default:
				return d.Errf("unrecognized response matcher %s", d.Val())
			}
		}

		matchers[definitionName] = matcher
	}
	return nil
}

// Interface guard
var _ caddyfile.Unmarshaler = (*Encode)(nil)
