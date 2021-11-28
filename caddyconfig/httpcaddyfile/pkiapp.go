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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
)

func init() {
	RegisterGlobalOption("pki", parsePKIApp)
}

// parsePKIApp parses the global log option. Syntax:
//
//     pki [id] {
//         name                     <name>
//         root_common_name         <name>
//         intermediate_common_name <name>
//     }
//
// When the CA ID is unspecified, 'local' is assumed.
//
func parsePKIApp(d *caddyfile.Dispenser, existingVal interface{}) (interface{}, error) {
	var pki *caddypki.PKI
	if existingVal != nil {
		unwrappedPki, ok := existingVal.(*caddypki.PKI)
		if !ok {
			return nil, d.Errf("failed to unwrap existing PKI value")
		}
		pki = unwrappedPki
	} else {
		pki = &caddypki.PKI{CAs: make(map[string]*caddypki.CA)}
	}

	pkiCa := new(caddypki.CA)
	for d.Next() {
		if d.NextArg() {
			pkiCa.ID = d.Val()
			if d.NextArg() {
				return nil, d.ArgErr()
			}
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "name":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				pkiCa.Name = d.Val()

			case "root_common_name":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				pkiCa.Name = d.Val()

			case "intermediate_common_name":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				pkiCa.Name = d.Val()

			default:
				return nil, d.Errf("unrecognized pki option '%s'", d.Val())
			}
		}
	}
	if pkiCa.ID == "" {
		pkiCa.ID = caddypki.DefaultCAID
	}

	pki.CAs[pkiCa.ID] = pkiCa

	return pki, nil
}

func (st ServerType) buildPKIApp(
	pairings []sbAddrAssociation,
	options map[string]interface{},
	warnings []caddyconfig.Warning,
) (*caddypki.PKI, []caddyconfig.Warning, error) {

	skipInstallTrust := false
	if _, ok := options["skip_install_trust"]; ok {
		skipInstallTrust = true
	}
	falseBool := false

	// Load the PKI app configured via global options
	var pkiApp *caddypki.PKI
	unwrappedPki, ok := options["pki"].(*caddypki.PKI)
	if ok {
		pkiApp = unwrappedPki
	} else {
		pkiApp = &caddypki.PKI{CAs: make(map[string]*caddypki.CA)}
	}
	for _, ca := range pkiApp.CAs {
		if skipInstallTrust {
			ca.InstallTrust = &falseBool
		}
		pkiApp.CAs[ca.ID] = ca
	}

	// Add in the CAs configured via directives
	for _, p := range pairings {
		for _, sblock := range p.serverBlocks {
			// find all the CAs that were defined and add them to the app config
			// i.e. from any "acme_server" directives
			for _, caCfgValue := range sblock.pile["pki.ca"] {
				ca := caCfgValue.Value.(*caddypki.CA)
				if skipInstallTrust {
					ca.InstallTrust = &falseBool
				}

				// the CA might already exist from global options, so
				// don't overwrite it in that case
				if _, ok := pkiApp.CAs[ca.ID]; !ok {
					pkiApp.CAs[ca.ID] = ca
				}
			}
		}
	}

	// if there was no CAs defined in any of the servers,
	// and we were requested to not install trust, then
	// add one for the default/local CA to do so
	if len(pkiApp.CAs) == 0 && skipInstallTrust {
		ca := new(caddypki.CA)
		ca.ID = caddypki.DefaultCAID
		ca.InstallTrust = &falseBool
		pkiApp.CAs[ca.ID] = ca
	}

	return pkiApp, warnings, nil
}
