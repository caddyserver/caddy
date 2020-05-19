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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	RegisterGlobalOption("debug", parseOptTrue)
	RegisterGlobalOption("http_port", parseOptHTTPPort)
	RegisterGlobalOption("https_port", parseOptHTTPSPort)
	RegisterGlobalOption("default_sni", parseOptSingleString)
	RegisterGlobalOption("order", parseOptOrder)
	RegisterGlobalOption("experimental_http3", parseOptTrue)
	RegisterGlobalOption("storage", parseOptStorage)
	RegisterGlobalOption("acme_ca", parseOptSingleString)
	RegisterGlobalOption("acme_dns", parseOptSingleString)
	RegisterGlobalOption("acme_ca_root", parseOptSingleString)
	RegisterGlobalOption("email", parseOptSingleString)
	RegisterGlobalOption("admin", parseOptAdmin)
	RegisterGlobalOption("on_demand_tls", parseOptOnDemand)
	RegisterGlobalOption("local_certs", parseOptTrue)
	RegisterGlobalOption("key_type", parseOptSingleString)
	RegisterGlobalOption("auto_https", parseOptAutoHTTPS)
}

func parseOptTrue(d *caddyfile.Dispenser) (interface{}, error) {
	return true, nil
}

func parseOptHTTPPort(d *caddyfile.Dispenser) (interface{}, error) {
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

func parseOptHTTPSPort(d *caddyfile.Dispenser) (interface{}, error) {
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

func parseOptOrder(d *caddyfile.Dispenser) (interface{}, error) {
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

func parseOptStorage(d *caddyfile.Dispenser) (interface{}, error) {
	if !d.Next() { // consume option name
		return nil, d.ArgErr()
	}
	if !d.Next() { // get storage module name
		return nil, d.ArgErr()
	}
	modName := d.Val()
	mod, err := caddy.GetModule("caddy.storage." + modName)
	if err != nil {
		return nil, d.Errf("getting storage module '%s': %v", modName, err)
	}
	unm, ok := mod.New().(caddyfile.Unmarshaler)
	if !ok {
		return nil, d.Errf("storage module '%s' is not a Caddyfile unmarshaler", mod.ID)
	}
	err = unm.UnmarshalCaddyfile(d.NewFromNextSegment())
	if err != nil {
		return nil, err
	}
	storage, ok := unm.(caddy.StorageConverter)
	if !ok {
		return nil, d.Errf("module %s is not a StorageConverter", mod.ID)
	}
	return storage, nil
}

func parseOptSingleString(d *caddyfile.Dispenser) (interface{}, error) {
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

func parseOptAdmin(d *caddyfile.Dispenser) (interface{}, error) {
	if d.Next() {
		var listenAddress string
		if !d.AllArgs(&listenAddress) {
			return "", d.ArgErr()
		}
		if listenAddress == "" {
			listenAddress = caddy.DefaultAdminListen
		}
		return listenAddress, nil
	}
	return "", nil
}

func parseOptOnDemand(d *caddyfile.Dispenser) (interface{}, error) {
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

func parseOptAutoHTTPS(d *caddyfile.Dispenser) (interface{}, error) {
	d.Next() // consume parameter name
	if !d.Next() {
		return "", d.ArgErr()
	}
	val := d.Val()
	if d.Next() {
		return "", d.ArgErr()
	}
	if val != "off" && val != "disable_redirects" {
		return "", d.Errf("auto_https must be either 'off' or 'disable_redirects'")
	}
	return val, nil
}
