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
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/acme"
)

func init() {
	RegisterGlobalOption("debug", parseOptTrue)
	RegisterGlobalOption("http_port", parseOptHTTPPort)
	RegisterGlobalOption("https_port", parseOptHTTPSPort)
	RegisterGlobalOption("grace_period", parseOptDuration)
	RegisterGlobalOption("default_sni", parseOptSingleString)
	RegisterGlobalOption("order", parseOptOrder)
	RegisterGlobalOption("storage", parseOptStorage)
	RegisterGlobalOption("storage_clean_interval", parseOptDuration)
	RegisterGlobalOption("acme_ca", parseOptSingleString)
	RegisterGlobalOption("acme_ca_root", parseOptSingleString)
	RegisterGlobalOption("acme_dns", parseOptACMEDNS)
	RegisterGlobalOption("acme_eab", parseOptACMEEAB)
	RegisterGlobalOption("cert_issuer", parseOptCertIssuer)
	RegisterGlobalOption("skip_install_trust", parseOptTrue)
	RegisterGlobalOption("email", parseOptSingleString)
	RegisterGlobalOption("admin", parseOptAdmin)
	RegisterGlobalOption("on_demand_tls", parseOptOnDemand)
	RegisterGlobalOption("local_certs", parseOptTrue)
	RegisterGlobalOption("key_type", parseOptSingleString)
	RegisterGlobalOption("auto_https", parseOptAutoHTTPS)
	RegisterGlobalOption("servers", parseServerOptions)
	RegisterGlobalOption("ocsp_stapling", parseOCSPStaplingOptions)
	RegisterGlobalOption("log", parseLogOptions)
	RegisterGlobalOption("preferred_chains", parseOptPreferredChains)
}

func parseOptTrue(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) { return true, nil }

func parseOptHTTPPort(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	var httpPort int
	for d.Next() {
		var httpPortStr string
		if !d.AllArgs(&httpPortStr) {
			return 0, d.ArgErr()
		}
		var err error
		httpPort, err = strconv.Atoi(httpPortStr)
		if err != nil {
			return 0, d.Errf("converting port '%s' to integer value: %v", httpPortStr, err)
		}
	}
	return httpPort, nil
}

func parseOptHTTPSPort(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	var httpsPort int
	for d.Next() {
		var httpsPortStr string
		if !d.AllArgs(&httpsPortStr) {
			return 0, d.ArgErr()
		}
		var err error
		httpsPort, err = strconv.Atoi(httpsPortStr)
		if err != nil {
			return 0, d.Errf("converting port '%s' to integer value: %v", httpsPortStr, err)
		}
	}
	return httpsPort, nil
}

func parseOptOrder(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	newOrder := directiveOrder

	for d.Next() {
		// get directive name
		if !d.Next() {
			return nil, d.ArgErr()
		}
		dirName := d.Val()
		if _, ok := registeredDirectives[dirName]; !ok {
			return nil, d.Errf("%s is not a registered directive", dirName)
		}

		// get positional token
		if !d.Next() {
			return nil, d.ArgErr()
		}
		pos := d.Val()

		// if directive exists, first remove it
		for i, d := range newOrder {
			if d == dirName {
				newOrder = append(newOrder[:i], newOrder[i+1:]...)
				break
			}
		}

		// act on the positional
		switch pos {
		case "first":
			newOrder = append([]string{dirName}, newOrder...)
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			directiveOrder = newOrder
			return newOrder, nil
		case "last":
			newOrder = append(newOrder, dirName)
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			directiveOrder = newOrder
			return newOrder, nil
		case "before":
		case "after":
		default:
			return nil, d.Errf("unknown positional '%s'", pos)
		}

		// get name of other directive
		if !d.NextArg() {
			return nil, d.ArgErr()
		}
		otherDir := d.Val()
		if d.NextArg() {
			return nil, d.ArgErr()
		}

		// insert directive into proper position
		for i, d := range newOrder {
			if d == otherDir {
				if pos == "before" {
					newOrder = append(newOrder[:i], append([]string{dirName}, newOrder[i:]...)...)
				} else if pos == "after" {
					newOrder = append(newOrder[:i+1], append([]string{dirName}, newOrder[i+1:]...)...)
				}
				break
			}
		}
	}

	directiveOrder = newOrder

	return newOrder, nil
}

func parseOptStorage(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	if !d.Next() { // consume option name
		return nil, d.ArgErr()
	}
	if !d.Next() { // get storage module name
		return nil, d.ArgErr()
	}
	modID := "caddy.storage." + d.Val()
	unm, err := caddyfile.UnmarshalModule(d, modID)
	if err != nil {
		return nil, err
	}
	storage, ok := unm.(caddy.StorageConverter)
	if !ok {
		return nil, d.Errf("module %s is not a caddy.StorageConverter", modID)
	}
	return storage, nil
}

func parseOptDuration(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	if !d.Next() { // consume option name
		return nil, d.ArgErr()
	}
	if !d.Next() { // get duration value
		return nil, d.ArgErr()
	}
	dur, err := caddy.ParseDuration(d.Val())
	if err != nil {
		return nil, err
	}
	return caddy.Duration(dur), nil
}

func parseOptACMEDNS(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	if !d.Next() { // consume option name
		return nil, d.ArgErr()
	}
	if !d.Next() { // get DNS module name
		return nil, d.ArgErr()
	}
	modID := "dns.providers." + d.Val()
	unm, err := caddyfile.UnmarshalModule(d, modID)
	if err != nil {
		return nil, err
	}
	prov, ok := unm.(certmagic.ACMEDNSProvider)
	if !ok {
		return nil, d.Errf("module %s (%T) is not a certmagic.ACMEDNSProvider", modID, unm)
	}
	return prov, nil
}

func parseOptACMEEAB(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	eab := new(acme.EAB)
	for d.Next() {
		if d.NextArg() {
			return nil, d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "key_id":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				eab.KeyID = d.Val()

			case "mac_key":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				eab.MACKey = d.Val()

			default:
				return nil, d.Errf("unrecognized parameter '%s'", d.Val())
			}
		}
	}
	return eab, nil
}

func parseOptCertIssuer(d *caddyfile.Dispenser, existing interface{}) (interface{}, error) {
	var issuers []certmagic.Issuer
	if existing != nil {
		issuers = existing.([]certmagic.Issuer)
	}
	for d.Next() { // consume option name
		if !d.Next() { // get issuer module name
			return nil, d.ArgErr()
		}
		modID := "tls.issuance." + d.Val()
		unm, err := caddyfile.UnmarshalModule(d, modID)
		if err != nil {
			return nil, err
		}
		iss, ok := unm.(certmagic.Issuer)
		if !ok {
			return nil, d.Errf("module %s (%T) is not a certmagic.Issuer", modID, unm)
		}
		issuers = append(issuers, iss)
	}
	return issuers, nil
}

func parseOptSingleString(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	d.Next() // consume parameter name
	if !d.Next() {
		return "", d.ArgErr()
	}
	val := d.Val()
	if d.Next() {
		return "", d.ArgErr()
	}
	return val, nil
}

func parseOptAdmin(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	adminCfg := new(caddy.AdminConfig)
	for d.Next() {
		if d.NextArg() {
			listenAddress := d.Val()
			if listenAddress == "off" {
				adminCfg.Disabled = true
				if d.Next() { // Do not accept any remaining options including block
					return nil, d.Err("No more option is allowed after turning off admin config")
				}
			} else {
				adminCfg.Listen = listenAddress
				if d.NextArg() { // At most 1 arg is allowed
					return nil, d.ArgErr()
				}
			}
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "enforce_origin":
				adminCfg.EnforceOrigin = true

			case "origins":
				adminCfg.Origins = d.RemainingArgs()

			default:
				return nil, d.Errf("unrecognized parameter '%s'", d.Val())
			}
		}
	}
	if adminCfg.Listen == "" && !adminCfg.Disabled {
		adminCfg.Listen = caddy.DefaultAdminListen
	}
	return adminCfg, nil
}

func parseOptOnDemand(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	var ond *caddytls.OnDemandConfig
	for d.Next() {
		if d.NextArg() {
			return nil, d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "ask":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				if ond == nil {
					ond = new(caddytls.OnDemandConfig)
				}
				ond.Ask = d.Val()

			case "interval":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return nil, err
				}
				if ond == nil {
					ond = new(caddytls.OnDemandConfig)
				}
				if ond.RateLimit == nil {
					ond.RateLimit = new(caddytls.RateLimit)
				}
				ond.RateLimit.Interval = caddy.Duration(dur)

			case "burst":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				burst, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, err
				}
				if ond == nil {
					ond = new(caddytls.OnDemandConfig)
				}
				if ond.RateLimit == nil {
					ond.RateLimit = new(caddytls.RateLimit)
				}
				ond.RateLimit.Burst = burst

			default:
				return nil, d.Errf("unrecognized parameter '%s'", d.Val())
			}
		}
	}
	if ond == nil {
		return nil, d.Err("expected at least one config parameter for on_demand_tls")
	}
	return ond, nil
}

func parseOptAutoHTTPS(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	d.Next() // consume parameter name
	if !d.Next() {
		return "", d.ArgErr()
	}
	val := d.Val()
	if d.Next() {
		return "", d.ArgErr()
	}
	if val != "off" && val != "disable_redirects" && val != "ignore_loaded_certs" {
		return "", d.Errf("auto_https must be one of 'off', 'disable_redirects' or 'ignore_loaded_certs'")
	}
	return val, nil
}

func parseServerOptions(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	return unmarshalCaddyfileServerOptions(d)
}

func parseOCSPStaplingOptions(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	d.Next() // consume option name
	var val string
	if !d.AllArgs(&val) {
		return nil, d.ArgErr()
	}
	if val != "off" {
		return nil, d.Errf("invalid argument '%s'", val)
	}
	return certmagic.OCSPConfig{
		DisableStapling: val == "off",
	}, nil
}

// parseLogOptions parses the global log option. Syntax:
//
//     log [name] {
//         output  <writer_module> ...
//         format  <encoder_module> ...
//         level   <level>
//         include <namespaces...>
//         exclude <namespaces...>
//     }
//
// When the name argument is unspecified, this directive modifies the default
// logger.
//
func parseLogOptions(d *caddyfile.Dispenser, existingVal interface{}) (interface{}, error) {
	currentNames := make(map[string]struct{})
	if existingVal != nil {
		innerVals, ok := existingVal.([]ConfigValue)
		if !ok {
			return nil, d.Errf("existing log values of unexpected type: %T", existingVal)
		}
		for _, rawVal := range innerVals {
			val, ok := rawVal.Value.(namedCustomLog)
			if !ok {
				return nil, d.Errf("existing log value of unexpected type: %T", existingVal)
			}
			currentNames[val.name] = struct{}{}
		}
	}

	var warnings []caddyconfig.Warning
	// Call out the same parser that handles server-specific log configuration.
	configValues, err := parseLogHelper(
		Helper{
			Dispenser: d,
			warnings:  &warnings,
		},
		currentNames,
	)
	if err != nil {
		return nil, err
	}
	if len(warnings) > 0 {
		return nil, d.Errf("warnings found in parsing global log options: %+v", warnings)
	}

	return configValues, nil
}

func parseOptPreferredChains(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	d.Next()
	return caddytls.ParseCaddyfilePreferredChainsOptions(d)
}
