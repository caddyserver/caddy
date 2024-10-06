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
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterDirective("header", parseCaddyfile)
	httpcaddyfile.RegisterDirective("request_header", parseReqHdrCaddyfile)
}

// parseCaddyfile sets up the handler for response headers from
// Caddyfile tokens. Syntax:
//
//	header [<matcher>] [[+|-|?|>]<field> [<value|regexp>] [<replacement>]] {
//		[+]<field> [<value|regexp> [<replacement>]]
//		?<field> <default_value>
//		-<field>
//		><field>
//		[defer]
//	}
//
// Either a block can be opened or a single header field can be configured
// in the first line, but not both in the same directive. Header operations
// are deferred to write-time if any headers are being deleted or if the
// 'defer' subdirective is used. + appends a header value, - deletes a field,
// ? conditionally sets a value only if the header field is not already set,
// and > sets a field with defer enabled.
func parseCaddyfile(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	h.Next() // consume directive name
	matcherSet, err := h.ExtractMatcherSet()
	if err != nil {
		return nil, err
	}
	h.Next() // consume the directive name again (matcher parsing resets)

	makeHandler := func() Handler {
		return Handler{
			Response: &RespHeaderOps{
				HeaderOps: &HeaderOps{},
			},
		}
	}
	handler, handlerWithRequire := makeHandler(), makeHandler()

	// first see if headers are in the initial line
	var hasArgs bool
	if h.NextArg() {
		hasArgs = true
		field := h.Val()
		var value string
		var replacement *string
		if h.NextArg() {
			value = h.Val()
		}
		if h.NextArg() {
			arg := h.Val()
			replacement = &arg
		}
		err := applyHeaderOp(
			handler.Response.HeaderOps,
			handler.Response,
			field,
			value,
			replacement,
		)
		if err != nil {
			return nil, h.Err(err.Error())
		}
		if len(handler.Response.HeaderOps.Delete) > 0 {
			handler.Response.Deferred = true
		}
	}

	// if not, they should be in a block
	for h.NextBlock(0) {
		field := h.Val()
		if field == "defer" {
			handler.Response.Deferred = true
			continue
		}
		if field == "match" {
			responseMatchers := make(map[string]caddyhttp.ResponseMatcher)
			err := caddyhttp.ParseNamedResponseMatcher(h.NewFromNextSegment(), responseMatchers)
			if err != nil {
				return nil, err
			}
			matcher := responseMatchers["match"]
			handler.Response.Require = &matcher
			continue
		}
		if hasArgs {
			return nil, h.Err("cannot specify headers in both arguments and block") // because it would be weird
		}

		// sometimes it is habitual for users to suffix a field name with a colon,
		// as if they were writing a curl command or something; see
		// https://caddy.community/t/v2-reverse-proxy-please-add-cors-example-to-the-docs/7349/19
		field = strings.TrimSuffix(field, ":")

		var value string
		var replacement *string
		if h.NextArg() {
			value = h.Val()
		}
		if h.NextArg() {
			arg := h.Val()
			replacement = &arg
		}

		handlerToUse := handler
		if strings.HasPrefix(field, "?") {
			handlerToUse = handlerWithRequire
		}

		err := applyHeaderOp(
			handlerToUse.Response.HeaderOps,
			handlerToUse.Response,
			field,
			value,
			replacement,
		)
		if err != nil {
			return nil, h.Err(err.Error())
		}
	}

	var configValues []httpcaddyfile.ConfigValue
	if !reflect.DeepEqual(handler, makeHandler()) {
		configValues = append(configValues, h.NewRoute(matcherSet, handler)...)
	}
	if !reflect.DeepEqual(handlerWithRequire, makeHandler()) {
		configValues = append(configValues, h.NewRoute(matcherSet, handlerWithRequire)...)
	}

	return configValues, nil
}

// parseReqHdrCaddyfile sets up the handler for request headers
// from Caddyfile tokens. Syntax:
//
//	request_header [<matcher>] [[+|-]<field> [<value|regexp>] [<replacement>]]
func parseReqHdrCaddyfile(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	h.Next() // consume directive name
	matcherSet, err := h.ExtractMatcherSet()
	if err != nil {
		return nil, err
	}
	h.Next() // consume the directive name again (matcher parsing resets)

	configValues := []httpcaddyfile.ConfigValue{}

	if !h.NextArg() {
		return nil, h.ArgErr()
	}
	field := h.Val()

	hdr := Handler{
		Request: &HeaderOps{},
	}

	// sometimes it is habitual for users to suffix a field name with a colon,
	// as if they were writing a curl command or something; see
	// https://caddy.community/t/v2-reverse-proxy-please-add-cors-example-to-the-docs/7349/19
	field = strings.TrimSuffix(field, ":")

	var value string
	var replacement *string
	if h.NextArg() {
		value = h.Val()
	}
	if h.NextArg() {
		arg := h.Val()
		replacement = &arg
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
	return configValues, nil
}

// CaddyfileHeaderOp applies a new header operation according to
// field, value, and replacement. The field can be prefixed with
// "+" or "-" to specify adding or removing; otherwise, the value
// will be set (overriding any previous value). If replacement is
// non-nil, value will be treated as a regular expression which
// will be used to search and then replacement will be used to
// complete the substring replacement; in that case, any + or -
// prefix to field will be ignored.
func CaddyfileHeaderOp(ops *HeaderOps, field, value string, replacement *string) error {
	return applyHeaderOp(ops, nil, field, value, replacement)
}

func applyHeaderOp(ops *HeaderOps, respHeaderOps *RespHeaderOps, field, value string, replacement *string) error {
	switch {
	case strings.HasPrefix(field, "+"): // append
		if ops.Add == nil {
			ops.Add = make(http.Header)
		}
		ops.Add.Add(field[1:], value)

	case strings.HasPrefix(field, "-"): // delete
		ops.Delete = append(ops.Delete, field[1:])
		if respHeaderOps != nil {
			respHeaderOps.Deferred = true
		}

	case strings.HasPrefix(field, "?"): // default (conditional on not existing) - response headers only
		if respHeaderOps == nil {
			return fmt.Errorf("%v: the default header modifier ('?') can only be used on response headers; for conditional manipulation of request headers, use matchers", field)
		}
		if respHeaderOps.Require == nil {
			respHeaderOps.Require = &caddyhttp.ResponseMatcher{
				Headers: make(http.Header),
			}
		}
		field = strings.TrimPrefix(field, "?")
		respHeaderOps.Require.Headers[field] = nil
		if respHeaderOps.Set == nil {
			respHeaderOps.Set = make(http.Header)
		}
		respHeaderOps.Set.Set(field, value)

	case replacement != nil: // replace
		// allow defer shortcut for replace syntax
		if strings.HasPrefix(field, ">") && respHeaderOps != nil {
			respHeaderOps.Deferred = true
		}
		if ops.Replace == nil {
			ops.Replace = make(map[string][]Replacement)
		}
		field = strings.TrimLeft(field, "+-?>")
		ops.Replace[field] = append(
			ops.Replace[field],
			Replacement{
				SearchRegexp: value,
				Replace:      *replacement,
			},
		)

	case strings.HasPrefix(field, ">"): // set (overwrite) with defer
		if ops.Set == nil {
			ops.Set = make(http.Header)
		}
		ops.Set.Set(field[1:], value)
		if respHeaderOps != nil {
			respHeaderOps.Deferred = true
		}

	default: // set (overwrite)
		if ops.Set == nil {
			ops.Set = make(http.Header)
		}
		ops.Set.Set(field, value)
	}

	return nil
}
