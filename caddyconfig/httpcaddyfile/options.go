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

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func parseHTTPPort(d *caddyfile.Dispenser) (int, error) {
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

func parseHTTPSPort(d *caddyfile.Dispenser) (int, error) {
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

func parseHandlerOrder(d *caddyfile.Dispenser) ([]string, error) {
	if !d.Next() {
		return nil, d.ArgErr()
	}
	order := d.RemainingArgs()
	if len(order) == 1 && order[0] == "appearance" {
		return []string{"appearance"}, nil
	}
	if len(order) > 0 && d.NextBlock() {
		return nil, d.Err("cannot open block if there are arguments")
	}
	for d.NextBlock() {
		order = append(order, d.Val())
		if d.NextArg() {
			return nil, d.ArgErr()
		}
	}
	if len(order) == 0 {
		return nil, d.ArgErr()
	}
	return order, nil
}
