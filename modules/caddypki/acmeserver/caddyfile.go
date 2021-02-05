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

package acmeserver

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
)

func init() {
	httpcaddyfile.RegisterDirective("acme_server", parseACMEServer)
}

// parseACMEServer sets up an ACME server handler from Caddyfile tokens.
//
//     acme_server [<matcher>] {
//         ca <id>
//     }
//
func parseACMEServer(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}

	matcherSet, err := h.ExtractMatcherSet()
	if err != nil {
		return nil, err
	}

	var acmeServer Handler
	var ca *caddypki.CA

	for h.Next() {
		if h.NextArg() {
			return nil, h.ArgErr()
		}
		for h.NextBlock(0) {
			switch h.Val() {
			case "ca":
				if !h.AllArgs(&acmeServer.CA) {
					return nil, h.ArgErr()
				}
				if ca == nil {
					ca = new(caddypki.CA)
				}
				ca.ID = acmeServer.CA
			}
		}
	}

	configVals := h.NewRoute(matcherSet, acmeServer)

	if ca == nil {
		return configVals, nil
	}

	return append(configVals, httpcaddyfile.ConfigValue{
		Class: "pki.ca",
		Value: ca,
	}), nil
}
