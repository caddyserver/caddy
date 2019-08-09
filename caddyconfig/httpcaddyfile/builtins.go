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
	"encoding/json"
	"fmt"
	"html"
	"net/http"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func (st *ServerType) parseRoot(
	tkns []caddyfile.Token,
	matcherDefs map[string]map[string]json.RawMessage,
	warnings *[]caddyconfig.Warning,
) ([]caddyhttp.Route, error) {
	var routes []caddyhttp.Route

	matchersAndTokens, err := st.tokensToMatcherSets(tkns, matcherDefs, warnings)
	if err != nil {
		return nil, err
	}

	for _, mst := range matchersAndTokens {
		d := caddyfile.NewDispenser("Caddyfile", mst.tokens)

		var root string
		for d.Next() {
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			root = d.Val()
			if d.NextArg() {
				return nil, d.ArgErr()
			}
		}

		varsHandler := caddyhttp.VarsMiddleware{"root": root}
		route := caddyhttp.Route{
			Handle: []json.RawMessage{
				caddyconfig.JSONModuleObject(varsHandler, "handler", "vars", warnings),
			},
		}
		if mst.matcherSet != nil {
			route.MatcherSets = []map[string]json.RawMessage{mst.matcherSet}
		}

		routes = append(routes, route)
	}

	return routes, nil
}

func (st *ServerType) parseRedir(
	tkns []caddyfile.Token,
	matcherDefs map[string]map[string]json.RawMessage,
	warnings *[]caddyconfig.Warning,
) ([]caddyhttp.Route, error) {
	var routes []caddyhttp.Route

	matchersAndTokens, err := st.tokensToMatcherSets(tkns, matcherDefs, warnings)
	if err != nil {
		return nil, err
	}

	for _, mst := range matchersAndTokens {
		var route caddyhttp.Route

		d := caddyfile.NewDispenser("Caddyfile", mst.tokens)

		for d.Next() {
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			to := d.Val()

			var code string
			if d.NextArg() {
				code = d.Val()
			}
			if code == "permanent" {
				code = "301"
			}
			if code == "temporary" || code == "" {
				code = "307"
			}
			var body string
			if code == "meta" {
				// Script tag comes first since that will better imitate a redirect in the browser's
				// history, but the meta tag is a fallback for most non-JS clients.
				const metaRedir = `<!DOCTYPE html>
<html>
	<head>
		<title>Redirecting...</title>
		<script>window.location.replace("%s");</script>
		<meta http-equiv="refresh" content="0; URL='%s'">
	</head>
	<body>Redirecting to <a href="%s">%s</a>...</body>
</html>
`
				safeTo := html.EscapeString(to)
				body = fmt.Sprintf(metaRedir, safeTo, safeTo, safeTo, safeTo)
			}

			handler := caddyhttp.StaticResponse{
				StatusCode: caddyhttp.WeakString(code),
				Headers:    http.Header{"Location": []string{to}},
				Body:       body,
			}

			route.Handle = append(route.Handle,
				caddyconfig.JSONModuleObject(handler, "handler", "static_response", warnings))
		}

		if mst.matcherSet != nil {
			route.MatcherSets = []map[string]json.RawMessage{mst.matcherSet}
		}

		routes = append(routes, route)
	}

	return routes, nil
}

func (st *ServerType) parseTLSAutomationManager(d *caddyfile.Dispenser) (caddytls.ACMEManagerMaker, error) {
	var m caddytls.ACMEManagerMaker

	for d.Next() {
		firstLine := d.RemainingArgs()
		if len(firstLine) == 1 && firstLine[0] != "off" {
			m.Email = firstLine[0]
		}

		var hasBlock bool
		for d.NextBlock() {
			hasBlock = true
			switch d.Val() {
			case "ca":
				arg := d.RemainingArgs()
				if len(arg) != 1 {
					return m, d.ArgErr()
				}
				m.CA = arg[0]
				// TODO: other properties
			}
		}

		// a naked tls directive is not allowed
		if len(firstLine) == 0 && !hasBlock {
			return m, d.ArgErr()
		}
	}

	return m, nil
}

func (st *ServerType) parseTLSCerts(d *caddyfile.Dispenser) (map[string]caddytls.CertificateLoader, error) {
	var fileLoader caddytls.FileLoader
	var folderLoader caddytls.FolderLoader

	for d.Next() {
		// file loader
		firstLine := d.RemainingArgs()
		if len(firstLine) == 2 {
			fileLoader = append(fileLoader, caddytls.CertKeyFilePair{
				Certificate: firstLine[0],
				Key:         firstLine[1],
				// TODO: tags, for enterprise module's certificate selection
			})
		}

		// folder loader
		for d.NextBlock() {
			if d.Val() == "load" {
				folderLoader = append(folderLoader, d.RemainingArgs()...)
			}
		}
	}

	// put configured loaders into the map
	loaders := make(map[string]caddytls.CertificateLoader)
	if len(fileLoader) > 0 {
		loaders["load_files"] = fileLoader
	}
	if len(folderLoader) > 0 {
		loaders["load_folders"] = folderLoader
	}

	return loaders, nil
}

func (st *ServerType) parseTLSConnPolicy(d *caddyfile.Dispenser) (*caddytls.ConnectionPolicy, error) {
	cp := new(caddytls.ConnectionPolicy)

	for d.Next() {
		for d.NextBlock() {
			switch d.Val() {
			case "protocols":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return nil, d.SyntaxErr("one or two protocols")
				}
				if len(args) > 0 {
					if _, ok := caddytls.SupportedProtocols[args[0]]; !ok {
						return nil, d.Errf("Wrong protocol name or protocol not supported: '%s'", args[0])
					}
					cp.ProtocolMin = args[0]
				}
				if len(args) > 1 {
					if _, ok := caddytls.SupportedProtocols[args[1]]; !ok {
						return nil, d.Errf("Wrong protocol name or protocol not supported: '%s'", args[1])
					}
					cp.ProtocolMax = args[1]
				}
			case "ciphers":
				for d.NextArg() {
					if _, ok := caddytls.SupportedCipherSuites[d.Val()]; !ok {
						return nil, d.Errf("Wrong cipher suite name or cipher suite not supported: '%s'", d.Val())
					}
					cp.CipherSuites = append(cp.CipherSuites, d.Val())
				}
			case "curves":
				for d.NextArg() {
					if _, ok := caddytls.SupportedCurves[d.Val()]; !ok {
						return nil, d.Errf("Wrong curve name or curve not supported: '%s'", d.Val())
					}
					cp.Curves = append(cp.Curves, d.Val())
				}
			case "alpn":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return nil, d.ArgErr()
				}
				cp.ALPN = args
			}
		}
	}

	return cp, nil
}
