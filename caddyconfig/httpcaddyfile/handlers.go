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

package httpcaddyfile

import (
	"encoding/json"
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func (st *ServerType) parseMatcherDefinitions(d *caddyfile.Dispenser) (map[string]map[string]json.RawMessage, error) {
	matchers := make(map[string]map[string]json.RawMessage)
	for d.Next() {
		definitionName := d.Val()
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			matcherName := d.Val()
			mod, err := caddy.GetModule("http.matchers." + matcherName)
			if err != nil {
				return nil, fmt.Errorf("getting matcher module '%s': %v", matcherName, err)
			}
			unm, ok := mod.New().(caddyfile.Unmarshaler)
			if !ok {
				return nil, fmt.Errorf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
			}
			err = unm.UnmarshalCaddyfile(d.NewFromNextTokens())
			if err != nil {
				return nil, err
			}
			rm, ok := unm.(caddyhttp.RequestMatcher)
			if !ok {
				return nil, fmt.Errorf("matcher module '%s' is not a request matcher", matcherName)
			}
			if _, ok := matchers[definitionName]; !ok {
				matchers[definitionName] = make(map[string]json.RawMessage)
			}
			matchers[definitionName][matcherName] = caddyconfig.JSON(rm, nil)
		}
	}
	return matchers, nil
}
