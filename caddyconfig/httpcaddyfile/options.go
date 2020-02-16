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

func parseDefaultSNI(d *caddyfile.Dispenser) (string, error) {
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

func parseOptExperimentalHTTP3(d *caddyfile.Dispenser) (bool, error) {
	return true, nil
}

func parseOptOrder(d *caddyfile.Dispenser) ([]string, error) {
	newOrder := directiveOrder

	for d.Next() {
		// get directive name
		if !d.Next() {
			return nil, d.ArgErr()
		}
		dirName := d.Val()
		if _, ok := registeredDirectives[dirName]; !ok {
			return nil, fmt.Errorf("%s is not a registered directive", dirName)
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
			return nil, fmt.Errorf("unknown positional '%s'", pos)
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
		return nil, fmt.Errorf("storage module '%s' is not a Caddyfile unmarshaler", mod.ID)
	}
	err = unm.UnmarshalCaddyfile(d.NewFromNextSegment())
	if err != nil {
		return nil, err
	}
	storage, ok := unm.(caddy.StorageConverter)
	if !ok {
		return nil, fmt.Errorf("module %s is not a StorageConverter", mod.ID)
	}
	return storage, nil
}

func parseOptACME(d *caddyfile.Dispenser) (string, error) {
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
