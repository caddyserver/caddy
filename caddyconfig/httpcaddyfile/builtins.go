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
	"strconv"
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
	RegisterHandlerDirective("abort", parseAbort)
	RegisterHandlerDirective("error", parseError)
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
	var keyType string
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
			// only the last cert (and its tag) will survive, so any conn
			// policy that is looking for any tag other than the last one
			// to be loaded won't find it, and TLS handshakes will fail
			// (see end of issue #3004)
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
				keyType = arg[0]

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
				modID := "tls.issuance." + modName
				unm, err := caddyfile.UnmarshalModule(h.Dispenser, modID)
				if err != nil {
					return nil, err
				}
				issuer, ok := unm.(certmagic.Issuer)
				if !ok {
					return nil, h.Errf("module %s (%T) is not a certmagic.Issuer", modID, unm)
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
				}
				if acmeIssuer.Challenges.DNS == nil {
					acmeIssuer.Challenges.DNS = new(caddytls.DNSChallengeConfig)
				}
				modID := "dns.providers." + provName
				unm, err := caddyfile.UnmarshalModule(h.Dispenser, modID)
				if err != nil {
					return nil, err
				}
				acmeIssuer.Challenges.DNS.ProviderRaw = caddyconfig.JSONModuleObject(unm, "name", provName, h.warnings)

			case "resolvers":
				args := h.RemainingArgs()
				if len(args) == 0 {
					return nil, h.ArgErr()
				}
				if acmeIssuer == nil {
					acmeIssuer = new(caddytls.ACMEIssuer)
				}
				if acmeIssuer.Challenges == nil {
					acmeIssuer.Challenges = new(caddytls.ChallengesConfig)
				}
				if acmeIssuer.Challenges.DNS == nil {
					acmeIssuer.Challenges.DNS = new(caddytls.DNSChallengeConfig)
				}
				acmeIssuer.Challenges.DNS.Resolvers = args

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

	// some tls subdirectives are shortcuts that implicitly configure issuers, and the
	// user can also configure issuers explicitly using the issuer subdirective; the
	// logic to support both would likely be complex, or at least unintuitive
	if len(issuers) > 0 && (acmeIssuer != nil || internalIssuer != nil) {
		return nil, h.Err("cannot mix issuer subdirective (explicit issuers) with other issuer-specific subdirectives (implicit issuers)")
	}
	if acmeIssuer != nil && internalIssuer != nil {
		return nil, h.Err("cannot create both ACME and internal certificate issuers")
	}

	// now we should either have: explicitly-created issuers, or an implicitly-created
	// ACME or internal issuer, or no issuers at all
	switch {
	case len(issuers) > 0:
		for _, issuer := range issuers {
			configVals = append(configVals, ConfigValue{
				Class: "tls.cert_issuer",
				Value: issuer,
			})
		}

	case acmeIssuer != nil:
		// implicit ACME issuers (from various subdirectives) - use defaults; there might be more than one
		defaultIssuers := caddytls.DefaultIssuers()

		// if a CA endpoint was set, override multiple implicit issuers since it's a specific one
		if acmeIssuer.CA != "" {
			defaultIssuers = []certmagic.Issuer{acmeIssuer}
		}

		for _, issuer := range defaultIssuers {
			switch iss := issuer.(type) {
			case *caddytls.ACMEIssuer:
				issuer = acmeIssuer
			case *caddytls.ZeroSSLIssuer:
				iss.ACMEIssuer = acmeIssuer
			}
			configVals = append(configVals, ConfigValue{
				Class: "tls.cert_issuer",
				Value: issuer,
			})
		}

	case internalIssuer != nil:
		configVals = append(configVals, ConfigValue{
			Class: "tls.cert_issuer",
			Value: internalIssuer,
		})
	}

	// certificate key type
	if keyType != "" {
		configVals = append(configVals, ConfigValue{
			Class: "tls.key_type",
			Value: keyType,
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

	var body string
	switch code {
	case "permanent":
		code = "301"
	case "temporary", "":
		code = "302"
	case "html":
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
		code = "302"
	default:
		codeInt, err := strconv.Atoi(code)
		if err != nil {
			return nil, h.Errf("Not a supported redir code type or not valid integer: '%s'", code)
		}
		if codeInt < 300 || codeInt > 399 {
			return nil, h.Errf("Redir code not in the 3xx range: '%v'", codeInt)
		}
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

// parseAbort parses the abort directive.
func parseAbort(h Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive
	for h.Next() || h.NextBlock(0) {
		return nil, h.ArgErr()
	}
	return &caddyhttp.StaticResponse{Abort: true}, nil
}

// parseError parses the error directive.
func parseError(h Helper) (caddyhttp.MiddlewareHandler, error) {
	se := new(caddyhttp.StaticError)
	err := se.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return se, nil
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
	return parseLogHelper(h, nil)
}

// parseLogHelper is used both for the parseLog directive within Server Blocks,
// as well as the global "log" option for configuring loggers at the global
// level. The parseAsGlobalOption parameter is used to distinguish any differing logic
// between the two.
func parseLogHelper(h Helper, globalLogNames map[string]struct{}) ([]ConfigValue, error) {
	// When the globalLogNames parameter is passed in, we make
	// modifications to the parsing behavior.
	parseAsGlobalOption := globalLogNames != nil

	var configValues []ConfigValue
	for h.Next() {
		// Logic below expects that a name is always present when a
		// global option is being parsed.
		var globalLogName string
		if parseAsGlobalOption {
			if h.NextArg() {
				globalLogName = h.Val()

				// Only a single argument is supported.
				if h.NextArg() {
					return nil, h.ArgErr()
				}
			} else {
				// If there is no log name specified, we
				// reference the default logger. See the
				// setupNewDefault function in the logging
				// package for where this is configured.
				globalLogName = "default"
			}

			// Verify this name is unused.
			_, used := globalLogNames[globalLogName]
			if used {
				return nil, h.Err("duplicate global log option for: " + globalLogName)
			}
			globalLogNames[globalLogName] = struct{}{}
		} else {
			// No arguments are supported for the server block log directive
			if h.NextArg() {
				return nil, h.ArgErr()
			}
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
					modID := "caddy.logging.writers." + moduleName
					unm, err := caddyfile.UnmarshalModule(h.Dispenser, modID)
					if err != nil {
						return nil, err
					}
					var ok bool
					wo, ok = unm.(caddy.WriterOpener)
					if !ok {
						return nil, h.Errf("module %s (%T) is not a WriterOpener", modID, unm)
					}
				}
				cl.WriterRaw = caddyconfig.JSONModuleObject(wo, "output", moduleName, h.warnings)

			case "format":
				if !h.NextArg() {
					return nil, h.ArgErr()
				}
				moduleName := h.Val()
				moduleID := "caddy.logging.encoders." + moduleName
				unm, err := caddyfile.UnmarshalModule(h.Dispenser, moduleID)
				if err != nil {
					return nil, err
				}
				enc, ok := unm.(zapcore.Encoder)
				if !ok {
					return nil, h.Errf("module %s (%T) is not a zapcore.Encoder", moduleID, unm)
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

			case "include":
				// This configuration is only allowed in the global options
				if !parseAsGlobalOption {
					return nil, h.ArgErr()
				}
				for h.NextArg() {
					cl.Include = append(cl.Include, h.Val())
				}

			case "exclude":
				// This configuration is only allowed in the global options
				if !parseAsGlobalOption {
					return nil, h.ArgErr()
				}
				for h.NextArg() {
					cl.Exclude = append(cl.Exclude, h.Val())
				}

			default:
				return nil, h.Errf("unrecognized subdirective: %s", h.Val())
			}
		}

		var val namedCustomLog
		// Skip handling of empty logging configs
		if !reflect.DeepEqual(cl, new(caddy.CustomLog)) {
			if parseAsGlobalOption {
				// Use indicated name for global log options
				val.name = globalLogName
				val.log = cl
			} else {
				// Construct a log name for server log streams
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
		}
		configValues = append(configValues, ConfigValue{
			Class: "custom_log",
			Value: val,
		})
	}
	return configValues, nil
}
