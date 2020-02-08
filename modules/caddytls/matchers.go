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

package caddytls

import (
	"crypto/tls"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(MatchServerName{})
	caddy.RegisterModule(new(MatchDefault))
}

// MatchServerName matches based on SNI.
type MatchServerName []string

// CaddyModule returns the Caddy module information.
func (MatchServerName) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.sni",
		New: func() caddy.Module { return new(MatchServerName) },
	}
}

// Match matches hello based on SNI.
func (m MatchServerName) Match(hello *tls.ClientHelloInfo) bool {
	for _, name := range m {
		// TODO: support wildcards (and regex?)
		if hello.ServerName == name {
			return true
		}
	}
	return false
}

// Interface guard
var _ ConnectionMatcher = (*MatchServerName)(nil)

// MatchDefault will tag the connection policy as default
type MatchDefault string

// CaddyModule returns the Caddy module information.
func (MatchDefault) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.handshake_match.default",
		New: func() caddy.Module { return new(MatchDefault) },
	}
}

// Match matches hello based on SNI.
func (m MatchDefault) Match(hello *tls.ClientHelloInfo) bool {
	// return false as this is a special case where we match against this last
	return false
}

var _ ConnectionMatcher = (*MatchDefault)(nil)
