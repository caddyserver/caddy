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
	"fmt"
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func parseOptHTTPPort(d *caddyfile.Dispenser) (int, error) {
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

func parseOptHTTPSPort(d *caddyfile.Dispenser) (int, error) {
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

func parseOptExperimentalHTTP3(d *caddyfile.Dispenser) (bool, error) {
	return true, nil
}

func parseOptHandlerOrder(d *caddyfile.Dispenser) ([]string, error) {
	if !d.Next() {
		return nil, d.ArgErr()
	}
	order := d.RemainingArgs()
	if len(order) == 1 && order[0] == "appearance" {
		return []string{"appearance"}, nil
	}
	if len(order) > 0 && d.NextBlock(0) {
		return nil, d.Err("cannot open block if there are arguments")
	}
	for d.NextBlock(0) {
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

func parseOptStorage(d *caddyfile.Dispenser) (caddy.StorageConverter, error) {
	if !d.Next() {
		return nil, d.ArgErr()
	}
	args := d.RemainingArgs()
	if len(args) != 1 {
		return nil, d.ArgErr()
	}
	modName := args[0]
	mod, err := caddy.GetModule("caddy.storage." + modName)
	if err != nil {
		return nil, fmt.Errorf("getting storage module '%s': %v", modName, err)
	}
	unm, ok := mod.New().(caddyfile.Unmarshaler)
	if !ok {
		return nil, fmt.Errorf("storage module '%s' is not a Caddyfile unmarshaler", mod.Name)
	}
	err = unm.UnmarshalCaddyfile(d.NewFromNextTokens())
	if err != nil {
		return nil, err
	}
	storage, ok := unm.(caddy.StorageConverter)
	if !ok {
		return nil, fmt.Errorf("module %s is not a StorageConverter", mod.Name)
	}
	return storage, nil
}

func parseOptACMECA(d *caddyfile.Dispenser) (string, error) {
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

func parseOptEmail(d *caddyfile.Dispenser) (string, error) {
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

func parseOptAdmin(d *caddyfile.Dispenser) (string, error) {
	if d.Next() {
		var listenAddress string
		d.AllArgs(&listenAddress)

		if listenAddress == "" {
			listenAddress = caddy.DefaultAdminListen
		}

		return listenAddress, nil
	}
	return "", nil
}
