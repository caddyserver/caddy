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

package caddyhttp

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// ResponseMatcher is a type which can determine if an
// HTTP response matches some criteria.
type ResponseMatcher struct {
	// If set, one of these status codes would be required.
	// A one-digit status can be used to represent all codes
	// in that class (e.g. 3 for all 3xx codes).
	StatusCode []int `json:"status_code,omitempty"`

	// If set, each header specified must be one of the
	// specified values, with the same logic used by the
	// request header matcher.
	Headers http.Header `json:"headers,omitempty"`
}

// Match returns true if the given statusCode and hdr match rm.
func (rm ResponseMatcher) Match(statusCode int, hdr http.Header) bool {
	if !rm.matchStatusCode(statusCode) {
		return false
	}
	return matchHeaders(hdr, rm.Headers, "", nil)
}

func (rm ResponseMatcher) matchStatusCode(statusCode int) bool {
	if rm.StatusCode == nil {
		return true
	}
	for _, code := range rm.StatusCode {
		if StatusCodeMatches(statusCode, code) {
			return true
		}
	}
	return false
}

// ParseNamedResponseMatcher parses the tokens of a named response matcher.
//
//     @name {
//         header <field> [<value>]
//         status <code...>
//     }
//
// Or, single line syntax:
//
//     @name [header <field> [<value>]] | [status <code...>]
//
func ParseNamedResponseMatcher(d *caddyfile.Dispenser, matchers map[string]ResponseMatcher) error {
	for d.Next() {
		definitionName := d.Val()

		if _, ok := matchers[definitionName]; ok {
			return d.Errf("matcher is defined more than once: %s", definitionName)
		}

		matcher := ResponseMatcher{}
		for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
			switch d.Val() {
			case "header":
				if matcher.Headers == nil {
					matcher.Headers = http.Header{}
				}

				// reuse the header request matcher's unmarshaler
				headerMatcher := MatchHeader(matcher.Headers)
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
