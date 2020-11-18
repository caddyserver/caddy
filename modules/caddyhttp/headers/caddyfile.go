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

package headers

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterDirective("header", parseCaddyfile)
	httpcaddyfile.RegisterDirective("request_header", parseReqHdrCaddyfile)
}

// errBadOperation is returned when trying to use a header operation in an inappropriate context.
// For instance, when trying to use "?" operation (set default) with "header_down".
var errBadOperation = errors.New("this header operation cannot be used here")

// parseCaddyfile sets up the handler for response headers from
// Caddyfile tokens. Syntax:
//
//     header [<matcher>] [[+|-|?]<field> [<value|regexp>] [<replacement>]] {
//         [+]<field> [<value|regexp> [<replacement>]]
//         ?<field> <default_value>
//         -<field>
//         [defer]
//     }
//
// Either a block can be opened or a single header field can be configured
// in the first line, but not both in the same directive. Header operations
// are deferred to write-time if any headers are being deleted or if the
// 'defer' subdirective is used.
func parseCaddyfile(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	matcherSet, err := httpcaddyfile.ParseMatcher(h)
	if err != nil {
		return nil, err
	}

	deferred := false
	handlers := []Handler{}

	for h.Next() {
		// first see if headers are in the initial line
		var hasArgs bool
		if h.NextArg() {
			hdr := Handler{
				Response: &RespHeaderOps{
					HeaderOps: &HeaderOps{},
				},
			}

			hasArgs = true
			field := h.Val()
			var value, replacement string
			if h.NextArg() {
				value = h.Val()
			}
			if h.NextArg() {
				replacement = h.Val()
			}
			err := applyHeaderOp(
				hdr.Response.HeaderOps,
				hdr.Response,
				field,
				value,
				replacement,
			)
			if err != nil {
				return nil, h.Err(err.Error())
			}
			handlers = append(handlers, hdr)
		}

		// if not, they should be in a block
		for h.NextBlock(0) {
			hdr := Handler{
				Response: &RespHeaderOps{
					HeaderOps: &HeaderOps{},
				},
			}

			field := h.Val()
			if field == "defer" {
				deferred = true
				continue
			}
			if hasArgs {
				return nil, h.Err("cannot specify headers in both arguments and block")
			}
			var value, replacement string
			if h.NextArg() {
				value = h.Val()
			}
			if h.NextArg() {
				replacement = h.Val()
			}
			err := applyHeaderOp(
				hdr.Response.HeaderOps,
				hdr.Response,
				field,
				value,
				replacement,
			)
			if err != nil {
				return nil, h.Err(err.Error())
			}
			handlers = append(handlers, hdr)
		}
	}

	configValues := make([]httpcaddyfile.ConfigValue, 0, len(handlers))
	for _, hdr := range handlers {
		if deferred {
			hdr.Response.Deferred = true
		}

		configValues = append(configValues, h.NewRoute(matcherSet, hdr)...)
	}

	return configValues, nil
}

// parseReqHdrCaddyfile sets up the handler for request headers
// from Caddyfile tokens. Syntax:
//
//     request_header [<matcher>] [[+|-|?]<field> [<value|regexp>] [<replacement>]]
//
func parseReqHdrCaddyfile(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	matcherSet, err := httpcaddyfile.ParseMatcher(h)
	if err != nil {
		return nil, err
	}

	configValues := []httpcaddyfile.ConfigValue{}

	for h.Next() {
		if !h.NextArg() {
			return nil, h.ArgErr()
		}
		field := h.Val()

		hdr := Handler{
			Request: &HeaderOps{},
		}

		// sometimes it is habitual for users to suffix a field name with a colon,
		// as if they were writing a curl command or something; see
		// https://caddy.community/t/v2-reverse-proxy-please-add-cors-example-to-the-docs/7349
		field = strings.TrimSuffix(field, ":")

		var value, replacement string
		if h.NextArg() {
			value = h.Val()
		}
		if h.NextArg() {
			replacement = h.Val()
			if h.NextArg() {
				return nil, h.ArgErr()
			}
		}

		if hdr.Request == nil {
			hdr.Request = new(HeaderOps)
		}
		if err := CaddyfileHeaderOp(hdr.Request, field, value, replacement); err != nil {
			return nil, h.Err(err.Error())
		}

		configValues = append(configValues, h.NewRoute(matcherSet, hdr)...)

		if h.NextArg() {
			return nil, h.ArgErr()
		}
	}
	return configValues, nil
}

// CaddyfileHeaderOp applies a new header operation according to
// field, value, and replacement. The field can be prefixed with
// "+" or "-" to specify adding or removing; otherwise, the value
// will be set (overriding any previous value). If replacement is
// non-empty, value will be treated as a regular expression which
// will be used to search and then replacement will be used to
// complete the substring replacement; in that case, any + or -
// prefix to field will be ignored.
func CaddyfileHeaderOp(ops *HeaderOps, field, value, replacement string) error {
	return applyHeaderOp(ops, nil, field, value, replacement)
}

func applyHeaderOp(ops *HeaderOps, respHeaderOps *RespHeaderOps, field, value, replacement string) error {
	if strings.HasPrefix(field, "+") {
		if ops.Add == nil {
			ops.Add = make(http.Header)
		}
		ops.Add.Set(field[1:], value)
	} else if strings.HasPrefix(field, "-") {
		ops.Delete = append(ops.Delete, field[1:])
		if respHeaderOps != nil {
			respHeaderOps.Deferred = true
		}
	} else if strings.HasPrefix(field, "?") {
		if respHeaderOps == nil {
			return fmt.Errorf("%v: %w", field, errBadOperation)
		}

		if respHeaderOps.Require == nil {
			respHeaderOps.Require = &caddyhttp.ResponseMatcher{
				Headers: map[string][]string{
					field[1:]: nil,
				},
			}
		}
		respHeaderOps.Require.Headers[field[1:]] = nil

		if ops.Add == nil {
			ops.Add = make(http.Header)
		}
		ops.Add.Set(field[1:], value)
	} else if replacement == "" {
		if ops.Set == nil {
			ops.Set = make(http.Header)
		}
		ops.Set.Set(field, value)
	} else {
		if ops.Replace == nil {
			ops.Replace = make(map[string][]Replacement)
		}
		field = strings.TrimLeft(field, "+-?")
		ops.Replace[field] = append(
			ops.Replace[field],
			Replacement{
				SearchRegexp: value,
				Replace:      replacement,
			},
		)
	}

	return nil
}
