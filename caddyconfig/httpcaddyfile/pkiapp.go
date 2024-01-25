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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
)

func init() {
	RegisterGlobalOption("pki", parsePKIApp)
}

// parsePKIApp parses the global log option. Syntax:
//
//	pki {
//	    ca [<id>] {
//	        name                  <name>
//	        root_cn               <name>
//	        intermediate_cn       <name>
//	        intermediate_lifetime <duration>
//	        root {
//	            cert   <path>
//	            key    <path>
//	            format <format>
//	        }
//	        intermediate {
//	            cert   <path>
//	            key    <path>
//	            format <format>
//	        }
//	    }
//	}
//
// When the CA ID is unspecified, 'local' is assumed.
func parsePKIApp(d *caddyfile.Dispenser, existingVal any) (any, error) {
	d.Next() // consume app name

	pki := &caddypki.PKI{
		CAs: make(map[string]*caddypki.CA),
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "ca":
			pkiCa := new(caddypki.CA)
			if d.NextArg() {
				pkiCa.ID = d.Val()
				if d.NextArg() {
					return nil, d.ArgErr()
				}
			}
			if pkiCa.ID == "" {
				pkiCa.ID = caddypki.DefaultCAID
			}

			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "name":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					pkiCa.Name = d.Val()

				case "root_cn":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					pkiCa.RootCommonName = d.Val()

				case "intermediate_cn":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					pkiCa.IntermediateCommonName = d.Val()

				case "intermediate_lifetime":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					dur, err := caddy.ParseDuration(d.Val())
					if err != nil {
						return nil, err
					}
					pkiCa.IntermediateLifetime = caddy.Duration(dur)

				case "root":
					if pkiCa.Root == nil {
						pkiCa.Root = new(caddypki.KeyPair)
					}
					for nesting := d.Nesting(); d.NextBlock(nesting); {
						switch d.Val() {
						case "cert":
							if !d.NextArg() {
								return nil, d.ArgErr()
							}
							pkiCa.Root.Certificate = d.Val()

						case "key":
							if !d.NextArg() {
								return nil, d.ArgErr()
							}
							pkiCa.Root.PrivateKey = d.Val()

						case "format":
							if !d.NextArg() {
								return nil, d.ArgErr()
							}
							pkiCa.Root.Format = d.Val()

						default:
							return nil, d.Errf("unrecognized pki ca root option '%s'", d.Val())
						}
					}

				case "intermediate":
					if pkiCa.Intermediate == nil {
						pkiCa.Intermediate = new(caddypki.KeyPair)
					}
					for nesting := d.Nesting(); d.NextBlock(nesting); {
						switch d.Val() {
						case "cert":
							if !d.NextArg() {
								return nil, d.ArgErr()
							}
							pkiCa.Intermediate.Certificate = d.Val()

						case "key":
							if !d.NextArg() {
								return nil, d.ArgErr()
							}
							pkiCa.Intermediate.PrivateKey = d.Val()

						case "format":
							if !d.NextArg() {
								return nil, d.ArgErr()
							}
							pkiCa.Intermediate.Format = d.Val()

						default:
							return nil, d.Errf("unrecognized pki ca intermediate option '%s'", d.Val())
						}
					}

				default:
					return nil, d.Errf("unrecognized pki ca option '%s'", d.Val())
				}
			}

			pki.CAs[pkiCa.ID] = pkiCa

		default:
			return nil, d.Errf("unrecognized pki option '%s'", d.Val())
		}
	}
	return pki, nil
}

func (st ServerType) buildPKIApp(
	pairings []sbAddrAssociation,
	options map[string]any,
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
