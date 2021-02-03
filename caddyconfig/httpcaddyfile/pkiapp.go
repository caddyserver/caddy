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
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
)

func (st ServerType) buildPKIApp(
	pairings []sbAddrAssociation,
	options map[string]interface{},
	warnings []caddyconfig.Warning,
) (*caddypki.PKI, []caddyconfig.Warning, error) {

	pkiApp := &caddypki.PKI{CAs: make(map[string]*caddypki.CA)}

	for _, p := range pairings {
		for _, sblock := range p.serverBlocks {
			// find all the CAs that were defined and add them to the app config
			for _, caCfgValue := range sblock.pile["pki.ca"] {
				ca := caCfgValue.Value.(*caddypki.CA)
				pkiApp.CAs[ca.ID] = ca
			}
		}
	}

	return pkiApp, warnings, nil
}
