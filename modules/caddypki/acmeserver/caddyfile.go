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
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
)

func init() {
	httpcaddyfile.RegisterDirective("acme_server", parseACMEServer)
}

// parseACMEServer sets up an ACME server handler from Caddyfile tokens.
//
//	acme_server [<matcher>] {
//		ca        <id>
//		lifetime  <duration>
//		resolvers <addresses...>
//	}
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
			case "lifetime":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}

				dur, err := caddy.ParseDuration(h.Val())
				if err != nil {
					return nil, err
				}

				if d := time.Duration(ca.IntermediateLifetime); d > 0 && dur > d {
					return nil, h.Errf("certificate lifetime (%s) exceeds intermediate certificate lifetime (%s)", dur, d)
				}

				acmeServer.Lifetime = caddy.Duration(dur)

			case "resolvers":
				acmeServer.Resolvers = h.RemainingArgs()
				if len(acmeServer.Resolvers) == 0 {
					return nil, h.Errf("must specify at least one resolver address")
				}
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
