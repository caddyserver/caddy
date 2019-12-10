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
	"reflect"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	RegisterDirective("bind", parseBind)
	RegisterDirective("root", parseRoot)
	RegisterDirective("tls", parseTLS)
	RegisterHandlerDirective("redir", parseRedir)
	RegisterHandlerDirective("respond", parseRespond)
}

func parseBind(h Helper) ([]ConfigValue, error) {
	var lnHosts []string
	for h.Next() {
		lnHosts = append(lnHosts, h.RemainingArgs()...)
	}
	return h.NewBindAddresses(lnHosts), nil
}

func parseRoot(h Helper) ([]ConfigValue, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}

	matcherSet, ok, err := h.MatcherToken()
	if err != nil {
		return nil, err
	}
	if !ok {
		// no matcher token; oops
		h.Dispenser.Prev()
	}

	if !h.NextArg() {
		return nil, h.ArgErr()
	}
	root := h.Val()
	if h.NextArg() {
		return nil, h.ArgErr()
	}

	varsHandler := caddyhttp.VarsMiddleware{"root": root}
	route := caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(varsHandler, "handler", "vars", nil),
		},
	}
	if matcherSet != nil {
		route.MatcherSetsRaw = []caddy.ModuleMap{matcherSet}
	}

	return h.NewVarsRoute(route), nil
}

func parseTLS(h Helper) ([]ConfigValue, error) {
	var configVals []ConfigValue

	cp := new(caddytls.ConnectionPolicy)
	var fileLoader caddytls.FileLoader
	var folderLoader caddytls.FolderLoader
	var mgr caddytls.ACMEManagerMaker
	var off bool

	// fill in global defaults, if configured
	if email := h.Option("email"); email != nil {
		mgr.Email = email.(string)
	}
	if acmeCA := h.Option("acme_ca"); acmeCA != nil {
		mgr.CA = acmeCA.(string)
	}

	for h.Next() {
		// file certificate loader
		firstLine := h.RemainingArgs()
		switch len(firstLine) {
		case 0:
		case 1:
			if firstLine[0] == "off" {
				off = true
			} else {
				mgr.Email = firstLine[0]
			}
		case 2:
			fileLoader = append(fileLoader, caddytls.CertKeyFilePair{
				Certificate: firstLine[0],
				Key:         firstLine[1],
				// TODO: add tags, for enterprise module's certificate selection
			})
		default:
			return nil, h.ArgErr()
		}

		var hasBlock bool
		for h.NextBlock(0) {
			hasBlock = true

			switch h.Val() {
			// connection policy
			case "protocols":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.SyntaxErr("one or two protocols")
				}
				if len(args) > 0 {
					if _, ok := caddytls.SupportedProtocols[args[0]]; !ok {
						return nil, h.Errf("Wrong protocol name or protocol not supported: '%s'", args[0])
					}
					cp.ProtocolMin = args[0]
				}
				if len(args) > 1 {
					if _, ok := caddytls.SupportedProtocols[args[1]]; !ok {
						return nil, h.Errf("Wrong protocol name or protocol not supported: '%s'", args[1])
					}
					cp.ProtocolMax = args[1]
				}
			case "ciphers":
				for h.NextArg() {
					if _, ok := caddytls.SupportedCipherSuites[h.Val()]; !ok {
						return nil, h.Errf("Wrong cipher suite name or cipher suite not supported: '%s'", h.Val())
					}
					cp.CipherSuites = append(cp.CipherSuites, h.Val())
				}
			case "curves":
				for h.NextArg() {
					if _, ok := caddytls.SupportedCurves[h.Val()]; !ok {
						return nil, h.Errf("Wrong curve name or curve not supported: '%s'", h.Val())
					}
					cp.Curves = append(cp.Curves, h.Val())
				}
			case "alpn":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.ArgErr()
				}
				cp.ALPN = args

			// certificate folder loader
			case "load":
				folderLoader = append(folderLoader, h.RemainingArgs()...)

			// automation policy
			case "ca":
				arg := h.RemainingArgs()
				if len(arg) != 1 {
					return nil, h.ArgErr()
				}
				mgr.CA = arg[0]

			default:
				return nil, h.Errf("unknown subdirective: %s", h.Val())
			}
		}

		// a naked tls directive is not allowed
		if len(firstLine) == 0 && !hasBlock {
			return nil, h.ArgErr()
		}
	}

	// connection policy
	configVals = append(configVals, ConfigValue{
		Class: "tls.connection_policy",
		Value: cp,
	})

	// certificate loaders
	if len(fileLoader) > 0 {
		configVals = append(configVals, ConfigValue{
			Class: "tls.certificate_loader",
			Value: fileLoader,
		})
	}
	if len(folderLoader) > 0 {
		configVals = append(configVals, ConfigValue{
			Class: "tls.certificate_loader",
			Value: folderLoader,
		})
	}

	// automation policy
	if off {
		configVals = append(configVals, ConfigValue{
			Class: "tls.off",
			Value: true,
		})
	} else if !reflect.DeepEqual(mgr, caddytls.ACMEManagerMaker{}) {
		configVals = append(configVals, ConfigValue{
			Class: "tls.automation_manager",
			Value: mgr,
		})
	}

	return configVals, nil
}

func parseRedir(h Helper) (caddyhttp.MiddlewareHandler, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}

	if !h.NextArg() {
		return nil, h.ArgErr()
	}
	to := h.Val()

	var code string
	if h.NextArg() {
		code = h.Val()
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

	return caddyhttp.StaticResponse{
		StatusCode: caddyhttp.WeakString(code),
		Headers:    http.Header{"Location": []string{to}},
		Body:       body,
	}, nil
}

func parseRespond(h Helper) (caddyhttp.MiddlewareHandler, error) {
	sr := new(caddyhttp.StaticResponse)
	err := sr.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return sr, nil
}
