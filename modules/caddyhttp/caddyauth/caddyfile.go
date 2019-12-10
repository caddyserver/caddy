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
	"encoding/base64"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("basicauth", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     basicauth [<matcher>] [<hash_algorithm>] {
//         <username> <hashed_password_base64> [<salt_base64>]
//         ...
//     }
//
// If no hash algorithm is supplied, bcrypt will be assumed.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ba HTTPBasicAuth

	for h.Next() {
		var cmp Comparer
		args := h.RemainingArgs()

		var hashName string
		switch len(args) {
		case 0:
			hashName = "bcrypt"
		case 1:
			hashName = args[0]
		default:
			return nil, h.ArgErr()
		}

		switch hashName {
		case "bcrypt":
			cmp = BcryptHash{}
		case "scrypt":
			cmp = ScryptHash{}
		default:
			return nil, h.Errf("unrecognized hash algorithm: %s", hashName)
		}

		ba.HashRaw = caddyconfig.JSONModuleObject(cmp, "algorithm", hashName, nil)

		for h.NextBlock(0) {
			username := h.Val()

			var b64Pwd, b64Salt string
			h.Args(&b64Pwd, &b64Salt)
			if h.NextArg() {
				return nil, h.ArgErr()
			}

			if username == "" || b64Pwd == "" {
				return nil, h.Err("username and password cannot be empty or missing")
			}

			pwd, err := base64.StdEncoding.DecodeString(b64Pwd)
			if err != nil {
				return nil, h.Errf("decoding password: %v", err)
			}
			var salt []byte
			if b64Salt != "" {
				salt, err = base64.StdEncoding.DecodeString(b64Salt)
				if err != nil {
					return nil, h.Errf("decoding salt: %v", err)
				}
			}

			ba.AccountList = append(ba.AccountList, Account{
				Username: username,
				Password: pwd,
				Salt:     salt,
			})
		}
	}

	return Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"http_basic": caddyconfig.JSON(ba, nil),
		},
	}, nil
}
