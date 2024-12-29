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
	"slices"
	"strconv"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	RegisterGlobalOption("debug", parseOptTrue)
	RegisterGlobalOption("http_port", parseOptHTTPPort)
	RegisterGlobalOption("https_port", parseOptHTTPSPort)
	RegisterGlobalOption("default_bind", parseOptDefaultBind)
	RegisterGlobalOption("grace_period", parseOptDuration)
	RegisterGlobalOption("shutdown_delay", parseOptDuration)
	RegisterGlobalOption("default_sni", parseOptSingleString)
	RegisterGlobalOption("fallback_sni", parseOptSingleString)
	RegisterGlobalOption("order", parseOptOrder)
	RegisterGlobalOption("storage", parseOptStorage)
	RegisterGlobalOption("storage_check", parseStorageCheck)
	RegisterGlobalOption("storage_clean_interval", parseStorageCleanInterval)
	RegisterGlobalOption("renew_interval", parseOptDuration)
	RegisterGlobalOption("ocsp_interval", parseOptDuration)
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
	RegisterGlobalOption("metrics", parseMetricsOptions)
	RegisterGlobalOption("servers", parseServerOptions)
	RegisterGlobalOption("ocsp_stapling", parseOCSPStaplingOptions)
	RegisterGlobalOption("cert_lifetime", parseOptDuration)
	RegisterGlobalOption("log", parseLogOptions)
	RegisterGlobalOption("preferred_chains", parseOptPreferredChains)
	RegisterGlobalOption("persist_config", parseOptPersistConfig)
}

func parseOptTrue(d *caddyfile.Dispenser, _ any) (any, error) { return true, nil }

func parseOptHTTPPort(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name
	var httpPort int
	var httpPortStr string
	if !d.AllArgs(&httpPortStr) {
		return 0, d.ArgErr()
	}
	var err error
	httpPort, err = strconv.Atoi(httpPortStr)
	if err != nil {
		return 0, d.Errf("converting port '%s' to integer value: %v", httpPortStr, err)
	}
	return httpPort, nil
}

func parseOptHTTPSPort(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name
	var httpsPort int
	var httpsPortStr string
	if !d.AllArgs(&httpsPortStr) {
		return 0, d.ArgErr()
	}
	var err error
	httpsPort, err = strconv.Atoi(httpsPortStr)
	if err != nil {
		return 0, d.Errf("converting port '%s' to integer value: %v", httpsPortStr, err)
	}
	return httpsPort, nil
}

func parseOptOrder(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name

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
	pos := Positional(d.Val())

	// if directive already had an order, drop it
	newOrder := slices.DeleteFunc(directiveOrder, func(d string) bool {
		return d == dirName
	})

	// act on the positional; if it's First or Last, we're done right away
	switch pos {
	case First:
		newOrder = append([]string{dirName}, newOrder...)
		if d.NextArg() {
			return nil, d.ArgErr()
		}
		directiveOrder = newOrder
		return newOrder, nil

	case Last:
		newOrder = append(newOrder, dirName)
		if d.NextArg() {
			return nil, d.ArgErr()
		}
		directiveOrder = newOrder
		return newOrder, nil

	// if it's Before or After, continue
	case Before:
	case After:

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

	// get the position of the target directive
	targetIndex := slices.Index(newOrder, otherDir)
	if targetIndex == -1 {
		return nil, d.Errf("directive '%s' not found", otherDir)
	}
	// if we're inserting after, we need to increment the index to go after
	if pos == After {
		targetIndex++
	}
	// insert the directive into the new order
	newOrder = slices.Insert(newOrder, targetIndex, dirName)

	directiveOrder = newOrder

	return newOrder, nil
}

func parseOptStorage(d *caddyfile.Dispenser, _ any) (any, error) {
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

func parseStorageCheck(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name
	if !d.Next() {
		return "", d.ArgErr()
	}
	val := d.Val()
	if d.Next() {
		return "", d.ArgErr()
	}
	if val != "off" {
		return "", d.Errf("storage_check must be 'off'")
	}
	return val, nil
}

func parseStorageCleanInterval(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name
	if !d.Next() {
		return "", d.ArgErr()
	}
	val := d.Val()
	if d.Next() {
		return "", d.ArgErr()
	}
	if val == "off" {
		return false, nil
	}
	dur, err := caddy.ParseDuration(d.Val())
	if err != nil {
		return nil, d.Errf("failed to parse storage_clean_interval, must be a duration or 'off' %w", err)
	}
	return caddy.Duration(dur), nil
}

func parseOptDuration(d *caddyfile.Dispenser, _ any) (any, error) {
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

func parseOptACMEDNS(d *caddyfile.Dispenser, _ any) (any, error) {
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
	prov, ok := unm.(certmagic.DNSProvider)
	if !ok {
		return nil, d.Errf("module %s (%T) is not a certmagic.DNSProvider", modID, unm)
	}
	return prov, nil
}

func parseOptACMEEAB(d *caddyfile.Dispenser, _ any) (any, error) {
	eab := new(acme.EAB)
	d.Next() // consume option name
	if d.NextArg() {
		return nil, d.ArgErr()
	}
	for d.NextBlock(0) {
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
	return eab, nil
}

func parseOptCertIssuer(d *caddyfile.Dispenser, existing any) (any, error) {
	d.Next() // consume option name

	var issuers []certmagic.Issuer
	if existing != nil {
		issuers = existing.([]certmagic.Issuer)
	}

	// get issuer module name
	if !d.Next() {
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
	return issuers, nil
}

func parseOptSingleString(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name
	if !d.Next() {
		return "", d.ArgErr()
	}
	val := d.Val()
	if d.Next() {
		return "", d.ArgErr()
	}
	return val, nil
}

func parseOptDefaultBind(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name

	var addresses, protocols []string
	addresses = d.RemainingArgs()

	if len(addresses) == 0 {
		addresses = append(addresses, "")
	}

	for d.NextBlock(0) {
		switch d.Val() {
		case "protocols":
			protocols = d.RemainingArgs()
			if len(protocols) == 0 {
				return nil, d.Errf("protocols requires one or more arguments")
			}
		default:
			return nil, d.Errf("unknown subdirective: %s", d.Val())
		}
	}

	return []ConfigValue{{Class: "bind", Value: addressesWithProtocols{
		addresses: addresses,
		protocols: protocols,
	}}}, nil
}

func parseOptAdmin(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name

	adminCfg := new(caddy.AdminConfig)
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
	for d.NextBlock(0) {
		switch d.Val() {
		case "enforce_origin":
			adminCfg.EnforceOrigin = true

		case "origins":
			adminCfg.Origins = d.RemainingArgs()

		default:
			return nil, d.Errf("unrecognized parameter '%s'", d.Val())
		}
	}
	if adminCfg.Listen == "" && !adminCfg.Disabled {
		adminCfg.Listen = caddy.DefaultAdminListen
	}
	return adminCfg, nil
}

func parseOptOnDemand(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name
	if d.NextArg() {
		return nil, d.ArgErr()
	}

	var ond *caddytls.OnDemandConfig

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "ask":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			if ond == nil {
				ond = new(caddytls.OnDemandConfig)
			}
			if ond.PermissionRaw != nil {
				return nil, d.Err("on-demand TLS permission module (or 'ask') already specified")
			}
			perm := caddytls.PermissionByHTTP{Endpoint: d.Val()}
			ond.PermissionRaw = caddyconfig.JSONModuleObject(perm, "module", "http", nil)

		case "permission":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			if ond == nil {
				ond = new(caddytls.OnDemandConfig)
			}
			if ond.PermissionRaw != nil {
				return nil, d.Err("on-demand TLS permission module (or 'ask') already specified")
			}
			modName := d.Val()
			modID := "tls.permission." + modName
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return nil, err
			}
			perm, ok := unm.(caddytls.OnDemandPermission)
			if !ok {
				return nil, d.Errf("module %s (%T) is not an on-demand TLS permission module", modID, unm)
			}
			ond.PermissionRaw = caddyconfig.JSONModuleObject(perm, "module", modName, nil)

		case "interval":
			return nil, d.Errf("the on_demand_tls 'interval' option is no longer supported, remove it from your config")

		case "burst":
			return nil, d.Errf("the on_demand_tls 'burst' option is no longer supported, remove it from your config")

		default:
			return nil, d.Errf("unrecognized parameter '%s'", d.Val())
		}
	}
	if ond == nil {
		return nil, d.Err("expected at least one config parameter for on_demand_tls")
	}
	return ond, nil
}

func parseOptPersistConfig(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name
	if !d.Next() {
		return "", d.ArgErr()
	}
	val := d.Val()
	if d.Next() {
		return "", d.ArgErr()
	}
	if val != "off" {
		return "", d.Errf("persist_config must be 'off'")
	}
	return val, nil
}

func parseOptAutoHTTPS(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next() // consume option name
	val := d.RemainingArgs()
	if len(val) == 0 {
		return "", d.ArgErr()
	}
	for _, v := range val {
		switch v {
		case "off":
		case "disable_redirects":
		case "disable_certs":
		case "ignore_loaded_certs":
		case "prefer_wildcard":
			break

		default:
			return "", d.Errf("auto_https must be one of 'off', 'disable_redirects', 'disable_certs', 'ignore_loaded_certs', or 'prefer_wildcard'")
		}
	}
	return val, nil
}

func unmarshalCaddyfileMetricsOptions(d *caddyfile.Dispenser) (any, error) {
	d.Next() // consume option name
	metrics := new(caddyhttp.Metrics)
	for d.NextBlock(0) {
		switch d.Val() {
		case "per_host":
			metrics.PerHost = true
		default:
			return nil, d.Errf("unrecognized servers option '%s'", d.Val())
		}
	}
	return metrics, nil
}

func parseMetricsOptions(d *caddyfile.Dispenser, _ any) (any, error) {
	return unmarshalCaddyfileMetricsOptions(d)
}

func parseServerOptions(d *caddyfile.Dispenser, _ any) (any, error) {
	return unmarshalCaddyfileServerOptions(d)
}

func parseOCSPStaplingOptions(d *caddyfile.Dispenser, _ any) (any, error) {
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
//	log [name] {
//	    output  <writer_module> ...
//	    format  <encoder_module> ...
//	    level   <level>
//	    include <namespaces...>
//	    exclude <namespaces...>
//	}
//
// When the name argument is unspecified, this directive modifies the default
// logger.
func parseLogOptions(d *caddyfile.Dispenser, existingVal any) (any, error) {
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

func parseOptPreferredChains(d *caddyfile.Dispenser, _ any) (any, error) {
	d.Next()
	return caddytls.ParseCaddyfilePreferredChainsOptions(d)
}
