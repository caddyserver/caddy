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

package caddyauth

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("basicauth", parseCaddyfile) // deprecated
	httpcaddyfile.RegisterHandlerDirective("basic_auth", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	basic_auth [<matcher>] [<hash_algorithm> [<realm>]] {
//	    <username> <hashed_password>
//	    ...
//	}
//
// If no hash algorithm is supplied, bcrypt will be assumed.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name

	// "basicauth" is deprecated, replaced by "basic_auth"
	if h.Val() == "basicauth" {
		caddy.Log().Named("config.adapter.caddyfile").Warn("the 'basicauth' directive is deprecated, please use 'basic_auth' instead!")
	}

	var ba HTTPBasicAuth
	ba.HashCache = new(Cache)

	var cmp Comparer
	args := h.RemainingArgs()

	var hashName string
	switch len(args) {
	case 0:
		hashName = "bcrypt"
	case 1:
		hashName = args[0]
	case 2:
		hashName = args[0]
		ba.Realm = args[1]
	default:
		return nil, h.ArgErr()
	}

	switch hashName {
	case "bcrypt":
		cmp = BcryptHash{}
	default:
		return nil, h.Errf("unrecognized hash algorithm: %s", hashName)
	}

	ba.HashRaw = caddyconfig.JSONModuleObject(cmp, "algorithm", hashName, nil)

	for h.NextBlock(0) {
		username := h.Val()

		var b64Pwd string
		h.Args(&b64Pwd)
		if h.NextArg() {
			return nil, h.ArgErr()
		}

		if username == "" || b64Pwd == "" {
			return nil, h.Err("username and password cannot be empty or missing")
		}

		ba.AccountList = append(ba.AccountList, Account{
			Username: username,
			Password: b64Pwd,
		})
	}

	return Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"http_basic": caddyconfig.JSON(ba, nil),
		},
	}, nil
}
