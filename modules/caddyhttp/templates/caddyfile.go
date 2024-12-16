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

package templates

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("templates", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	templates [<matcher>] {
//	    mime <types...>
//	    between <open_delim> <close_delim>
//	    root <path>
//	}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name
	t := new(Templates)
	for h.NextBlock(0) {
		switch h.Val() {
		case "mime":
			t.MIMETypes = h.RemainingArgs()
			if len(t.MIMETypes) == 0 {
				return nil, h.ArgErr()
			}
		case "between":
			t.Delimiters = h.RemainingArgs()
			if len(t.Delimiters) != 2 {
				return nil, h.ArgErr()
			}
		case "root":
			if !h.Args(&t.FileRoot) {
				return nil, h.ArgErr()
			}
		case "extensions":
			if h.NextArg() {
				return nil, h.ArgErr()
			}
			if t.ExtensionsRaw != nil {
				return nil, h.Err("extensions already specified")
			}
			for nesting := h.Nesting(); h.NextBlock(nesting); {
				extensionModuleName := h.Val()
				modID := "http.handlers.templates.functions." + extensionModuleName
				unm, err := caddyfile.UnmarshalModule(h.Dispenser, modID)
				if err != nil {
					return nil, err
				}
				cf, ok := unm.(CustomFunctions)
				if !ok {
					return nil, h.Errf("module %s (%T) does not provide template functions", modID, unm)
				}
				if t.ExtensionsRaw == nil {
					t.ExtensionsRaw = make(caddy.ModuleMap)
				}
				t.ExtensionsRaw[extensionModuleName] = caddyconfig.JSON(cf, nil)
			}
		}
	}
	return t, nil
}
