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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"html"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap/zapcore"
)

func init() {
	RegisterDirective("bind", parseBind)
	RegisterDirective("tls", parseTLS)
	RegisterHandlerDirective("root", parseRoot)
	RegisterHandlerDirective("redir", parseRedir)
	RegisterHandlerDirective("respond", parseRespond)
	RegisterHandlerDirective("route", parseRoute)
	RegisterHandlerDirective("handle", parseHandle)
	RegisterDirective("handle_errors", parseHandleErrors)
	RegisterDirective("log", parseLog)
}

// parseBind parses the bind directive. Syntax:
//
//     bind <addresses...>
//
func parseBind(h Helper) ([]ConfigValue, error) {
	var lnHosts []string
	for h.Next() {
		lnHosts = append(lnHosts, h.RemainingArgs()...)
	}
	return h.NewBindAddresses(lnHosts), nil
}

// parseTLS parses the tls directive. Syntax:
//
//     tls [<email>|internal]|[<cert_file> <key_file>] {
//         protocols <min> [<max>]
//         ciphers   <cipher_suites...>
//         curves    <curves...>
//         client_auth {
//             mode                   [request|require|verify_if_given|require_and_verify]
//             trusted_ca_cert        <base64_der>
//             trusted_ca_cert_file   <filename>
//             trusted_leaf_cert      <base64_der>
//             trusted_leaf_cert_file <filename>
//         }
//         alpn      <values...>
//         load      <paths...>
//         ca        <acme_ca_endpoint>
//         ca_root   <pem_file>
//         dns       <provider_name> [...]
//         on_demand
//         eab    <key_id> <mac_key>
//         issuer <module_name> [...]
//     }
//
func parseTLS(h Helper) ([]ConfigValue, error) {
	cp := new(caddytls.ConnectionPolicy)
	var fileLoader caddytls.FileLoader
	var folderLoader caddytls.FolderLoader
	var certSelector caddytls.CustomCertSelectionPolicy
	var acmeIssuer *caddytls.ACMEIssuer
	var autoPolicy *caddytls.AutomationPolicy
	var internalIssuer *caddytls.InternalIssuer
	var issuers []certmagic.Issuer
	var onDemand bool

	for h.Next() {
		// file certificate loader
		firstLine := h.RemainingArgs()
		switch len(firstLine) {
		case 0:
		case 1:
			if firstLine[0] == "internal" {
				internalIssuer = new(caddytls.InternalIssuer)
			} else if !strings.Contains(firstLine[0], "@") {
				return nil, h.Err("single argument must either be 'internal' or an email address")
			} else {
				if acmeIssuer == nil {
					acmeIssuer = new(caddytls.ACMEIssuer)
				}
				acmeIssuer.Email = firstLine[0]
			}

		case 2:
			certFilename := firstLine[0]
			keyFilename := firstLine[1]

			// tag this certificate so if multiple certs match, specifically
			// this one that the user has provided will be used, see #2588:
			// https://github.com/caddyserver/caddy/issues/2588 ... but we
			// must be careful about how we do this; being careless will
			// lead to failed handshakes
			//
			// we need to remember which cert files we've seen, since we
			// must load each cert only once; otherwise, they each get a
			// different tag... since a cert loaded twice has the same
			// bytes, it will overwrite the first one in the cache, and
			// only the last cert (and its tag) will survive, so a any conn
			// policy that is looking for any tag but the last one to be
			// loaded won't find it, and TLS handshakes will fail (see end)
			// of issue #3004)
			//
			// tlsCertTags maps certificate filenames to their tag.
			// This is used to remember which tag is used for each
			// certificate files, since we need to avoid loading
			// the same certificate files more than once, overwriting
			// previous tags
			tlsCertTags, ok := h.State["tlsCertTags"].(map[string]string)
			if !ok {
				tlsCertTags = make(map[string]string)
				h.State["tlsCertTags"] = tlsCertTags
			}

			tag, ok := tlsCertTags[certFilename]
			if !ok {
				// haven't seen this cert file yet, let's give it a tag
				// and add a loader for it
				tag = fmt.Sprintf("cert%d", len(tlsCertTags))
				fileLoader = append(fileLoader, caddytls.CertKeyFilePair{
					Certificate: certFilename,
					Key:         keyFilename,
					Tags:        []string{tag},
				})
				// remember this for next time we see this cert file
				tlsCertTags[certFilename] = tag
			}
			certSelector.AnyTag = append(certSelector.AnyTag, tag)

		default:
			return nil, h.ArgErr()
		}

		var hasBlock bool
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			hasBlock = true

			switch h.Val() {
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
					if !caddytls.CipherSuiteNameSupported(h.Val()) {
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

			case "client_auth":
				cp.ClientAuthentication = &caddytls.ClientAuthentication{}
				for nesting := h.Nesting(); h.NextBlock(nesting); {
					subdir := h.Val()
					switch subdir {
					case "mode":
						if !h.Args(&cp.ClientAuthentication.Mode) {
							return nil, h.ArgErr()
						}
						if h.NextArg() {
							return nil, h.ArgErr()
						}

					case "trusted_ca_cert",
						"trusted_leaf_cert":
						if !h.NextArg() {
							return nil, h.ArgErr()
						}
						if subdir == "trusted_ca_cert" {
							cp.ClientAuthentication.TrustedCACerts = append(cp.ClientAuthentication.TrustedCACerts, h.Val())
						} else {
							cp.ClientAuthentication.TrustedLeafCerts = append(cp.ClientAuthentication.TrustedLeafCerts, h.Val())
						}

					case "trusted_ca_cert_file",
						"trusted_leaf_cert_file":
						if !h.NextArg() {
							return nil, h.ArgErr()
						}
						filename := h.Val()
						certDataPEM, err := ioutil.ReadFile(filename)
						if err != nil {
							return nil, err
						}
						block, _ := pem.Decode(certDataPEM)
						if block == nil || block.Type != "CERTIFICATE" {
							return nil, h.Errf("no CERTIFICATE pem block found in %s", h.Val())
						}
						if subdir == "trusted_ca_cert_file" {
							cp.ClientAuthentication.TrustedCACerts = append(cp.ClientAuthentication.TrustedCACerts,
								base64.StdEncoding.EncodeToString(block.Bytes))
						} else {
							cp.ClientAuthentication.TrustedLeafCerts = append(cp.ClientAuthentication.TrustedLeafCerts,
								base64.StdEncoding.EncodeToString(block.Bytes))
						}

					default:
						return nil, h.Errf("unknown subdirective for client_auth: %s", subdir)
					}
				}

			case "alpn":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.ArgErr()
				}
				cp.ALPN = args

			case "load":
				folderLoader = append(folderLoader, h.RemainingArgs()...)

			case "ca":
				arg := h.RemainingArgs()
				if len(arg) != 1 {
					return nil, h.ArgErr()
				}
				if acmeIssuer == nil {
					acmeIssuer = new(caddytls.ACMEIssuer)
				}
				acmeIssuer.CA = arg[0]

			case "key_type":
				arg := h.RemainingArgs()
				if len(arg) != 1 {
					return nil, h.ArgErr()
				}
				if autoPolicy == nil {
					autoPolicy = new(caddytls.AutomationPolicy)
				}
				autoPolicy.KeyType = arg[0]

			case "eab":
				arg := h.RemainingArgs()
				if len(arg) != 2 {
					return nil, h.ArgErr()
				}
				if acmeIssuer == nil {
					acmeIssuer = new(caddytls.ACMEIssuer)
				}
				acmeIssuer.ExternalAccount = &acme.EAB{
					KeyID:  arg[0],
					MACKey: arg[1],
				}

			case "issuer":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				modName := h.Val()
				mod, err := caddy.GetModule("tls.issuance." + modName)
				if err != nil {
					return nil, h.Errf("getting issuer module '%s': %v", modName, err)
				}
				unm, ok := mod.New().(caddyfile.Unmarshaler)
				if !ok {
					return nil, h.Errf("issuer module '%s' is not a Caddyfile unmarshaler", mod.ID)
				}
				err = unm.UnmarshalCaddyfile(h.NewFromNextSegment())
				if err != nil {
					return nil, err
				}
				issuer, ok := unm.(certmagic.Issuer)
				if !ok {
					return nil, h.Errf("module %s is not a certmagic.Issuer", mod.ID)
				}
				issuers = append(issuers, issuer)

			case "dns":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				provName := h.Val()
				if acmeIssuer == nil {
					acmeIssuer = new(caddytls.ACMEIssuer)
				}
				if acmeIssuer.Challenges == nil {
					acmeIssuer.Challenges = new(caddytls.ChallengesConfig)
					acmeIssuer.Challenges.DNS = new(caddytls.DNSChallengeConfig)
				}
				dnsProvModule, err := caddy.GetModule("dns.providers." + provName)
				if err != nil {
					return nil, h.Errf("getting DNS provider module named '%s': %v", provName, err)
				}
				dnsProvModuleInstance := dnsProvModule.New()
				if unm, ok := dnsProvModuleInstance.(caddyfile.Unmarshaler); ok {
					err = unm.UnmarshalCaddyfile(h.NewFromNextSegment())
					if err != nil {
						return nil, err
					}
				}
				acmeIssuer.Challenges.DNS.ProviderRaw = caddyconfig.JSONModuleObject(dnsProvModuleInstance, "name", provName, h.warnings)

			case "ca_root":
				arg := h.RemainingArgs()
				if len(arg) != 1 {
					return nil, h.ArgErr()
				}
				if acmeIssuer == nil {
					acmeIssuer = new(caddytls.ACMEIssuer)
				}
				acmeIssuer.TrustedRootsPEMFiles = append(acmeIssuer.TrustedRootsPEMFiles, arg[0])

			case "on_demand":
				if h.NextArg() {
					return nil, h.ArgErr()
				}
				onDemand = true

			default:
				return nil, h.Errf("unknown subdirective: %s", h.Val())
			}
		}

		// a naked tls directive is not allowed
		if len(firstLine) == 0 && !hasBlock {
			return nil, h.ArgErr()
		}
	}

	// begin building the final config values
	configVals := []ConfigValue{}

	// certificate loaders
	if len(fileLoader) > 0 {
		configVals = append(configVals, ConfigValue{
			Class: "tls.cert_loader",
			Value: fileLoader,
		})
	}
	if len(folderLoader) > 0 {
		configVals = append(configVals, ConfigValue{
			Class: "tls.cert_loader",
			Value: folderLoader,
		})
	}

	if len(issuers) > 0 && (acmeIssuer != nil || internalIssuer != nil) {
		// some tls subdirectives are shortcuts that implicitly configure issuers, and the
		// user can also configure issuers explicitly using the issuer subdirective; the
		// logic to support both would likely be complex, or at least unintuitive
		return nil, h.Err("cannot mix issuer subdirective (explicit issuers) with other issuer-specific subdirectives (implicit issuers)")
	}
	for _, issuer := range issuers {
		configVals = append(configVals, ConfigValue{
			Class: "tls.cert_issuer",
			Value: issuer,
		})
	}
	if acmeIssuer != nil {
		configVals = append(configVals, ConfigValue{
			Class: "tls.cert_issuer",
			Value: disambiguateACMEIssuer(acmeIssuer),
		})
	}
	if internalIssuer != nil {
		configVals = append(configVals, ConfigValue{
			Class: "tls.cert_issuer",
			Value: internalIssuer,
		})
	}

	if autoPolicy != nil {
		configVals = append(configVals, ConfigValue{
			Class: "tls.key_type",
			Value: autoPolicy.KeyType,
		})
	}

	// on-demand TLS
	if onDemand {
		configVals = append(configVals, ConfigValue{
			Class: "tls.on_demand",
			Value: true,
		})
	}

	// custom certificate selection
	if len(certSelector.AnyTag) > 0 {
		cp.CertSelection = &certSelector
	}

	// connection policy -- always add one, to ensure that TLS
	// is enabled, because this directive was used (this is
	// needed, for instance, when a site block has a key of
	// just ":5000" - i.e. no hostname, and only on-demand TLS
	// is enabled)
	configVals = append(configVals, ConfigValue{
		Class: "tls.connection_policy",
		Value: cp,
	})

	return configVals, nil
}

// parseRoot parses the root directive. Syntax:
//
//     root [<matcher>] <path>
//
func parseRoot(h Helper) (caddyhttp.MiddlewareHandler, error) {
	var root string
	for h.Next() {
		if !h.NextArg() {
			return nil, h.ArgErr()
		}
		root = h.Val()
		if h.NextArg() {
			return nil, h.ArgErr()
		}
	}
	return caddyhttp.VarsMiddleware{"root": root}, nil
}

// parseRedir parses the redir directive. Syntax:
//
//     redir [<matcher>] <to> [<code>]
//
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
		code = "302"
	}
	var body string
	if code == "html" {
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

// parseRespond parses the respond directive.
func parseRespond(h Helper) (caddyhttp.MiddlewareHandler, error) {
	sr := new(caddyhttp.StaticResponse)
	err := sr.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return sr, nil
}

// parseRoute parses the route directive.
func parseRoute(h Helper) (caddyhttp.MiddlewareHandler, error) {
	sr := new(caddyhttp.Subroute)

	allResults, err := parseSegmentAsConfig(h)
	if err != nil {
		return nil, err
	}

	for _, result := range allResults {
		switch handler := result.Value.(type) {
		case caddyhttp.Route:
			sr.Routes = append(sr.Routes, handler)
		case caddyhttp.Subroute:
			// directives which return a literal subroute instead of a route
			// means they intend to keep those handlers together without
			// them being reordered; we're doing that anyway since we're in
			// the route directive, so just append its handlers
			sr.Routes = append(sr.Routes, handler.Routes...)
		default:
			return nil, h.Errf("%s directive returned something other than an HTTP route or subroute: %#v (only handler directives can be used in routes)", result.directive, result.Value)
		}
	}

	return sr, nil
}

func parseHandle(h Helper) (caddyhttp.MiddlewareHandler, error) {
	return ParseSegmentAsSubroute(h)
}

func parseHandleErrors(h Helper) ([]ConfigValue, error) {
	subroute, err := ParseSegmentAsSubroute(h)
	if err != nil {
		return nil, err
	}
	return []ConfigValue{
		{
			Class: "error_route",
			Value: subroute,
		},
	}, nil
}

// parseLog parses the log directive. Syntax:
//
//     log {
//         output <writer_module> ...
//         format <encoder_module> ...
//         level  <level>
//     }
//
func parseLog(h Helper) ([]ConfigValue, error) {
	var configValues []ConfigValue
	for h.Next() {
		// log does not currently support any arguments
		if h.NextArg() {
			return nil, h.ArgErr()
		}

		cl := new(caddy.CustomLog)

		for h.NextBlock(0) {
			switch h.Val() {
			case "output":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				moduleName := h.Val()

				// can't use the usual caddyfile.Unmarshaler flow with the
				// standard writers because they are in the caddy package
				// (because they are the default) and implementing that
				// interface there would unfortunately create circular import
				var wo caddy.WriterOpener
				switch moduleName {
				case "stdout":
					wo = caddy.StdoutWriter{}
				case "stderr":
					wo = caddy.StderrWriter{}
				case "discard":
					wo = caddy.DiscardWriter{}
				default:
					mod, err := caddy.GetModule("caddy.logging.writers." + moduleName)
					if err != nil {
						return nil, h.Errf("getting log writer module named '%s': %v", moduleName, err)
					}
					unm, ok := mod.New().(caddyfile.Unmarshaler)
					if !ok {
						return nil, h.Errf("log writer module '%s' is not a Caddyfile unmarshaler", mod)
					}
					err = unm.UnmarshalCaddyfile(h.NewFromNextSegment())
					if err != nil {
						return nil, err
					}
					wo, ok = unm.(caddy.WriterOpener)
					if !ok {
						return nil, h.Errf("module %s is not a WriterOpener", mod)
					}
				}
				cl.WriterRaw = caddyconfig.JSONModuleObject(wo, "output", moduleName, h.warnings)

			case "format":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				moduleName := h.Val()
				mod, err := caddy.GetModule("caddy.logging.encoders." + moduleName)
				if err != nil {
					return nil, h.Errf("getting log encoder module named '%s': %v", moduleName, err)
				}
				unm, ok := mod.New().(caddyfile.Unmarshaler)
				if !ok {
					return nil, h.Errf("log encoder module '%s' is not a Caddyfile unmarshaler", mod)
				}
				err = unm.UnmarshalCaddyfile(h.NewFromNextSegment())
				if err != nil {
					return nil, err
				}
				enc, ok := unm.(zapcore.Encoder)
				if !ok {
					return nil, h.Errf("module %s is not a zapcore.Encoder", mod)
				}
				cl.EncoderRaw = caddyconfig.JSONModuleObject(enc, "format", moduleName, h.warnings)

			case "level":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				cl.Level = h.Val()
				if h.NextArg() {
					return nil, h.ArgErr()
				}

			default:
				return nil, h.Errf("unrecognized subdirective: %s", h.Val())
			}
		}

		var val namedCustomLog
		if !reflect.DeepEqual(cl, new(caddy.CustomLog)) {
			logCounter, ok := h.State["logCounter"].(int)
			if !ok {
				logCounter = 0
			}
			val.name = fmt.Sprintf("log%d", logCounter)
			cl.Include = []string{"http.log.access." + val.name}
			val.log = cl
			logCounter++
			h.State["logCounter"] = logCounter
		}
		configValues = append(configValues, ConfigValue{
			Class: "custom_log",
			Value: val,
		})
	}
	return configValues, nil
}
