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

// MatchServerName matches based on SNI.
type MatchServerName []string

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "tls.handshake_match.sni",
		New:  func() interface{} { return MatchServerName{} },
	})
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
