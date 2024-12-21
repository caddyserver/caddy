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
	"html"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	RegisterDirective("bind", parseBind)
	RegisterDirective("tls", parseTLS)
	RegisterHandlerDirective("fs", parseFilesystem)
	RegisterDirective("root", parseRoot)
	RegisterHandlerDirective("vars", parseVars)
	RegisterHandlerDirective("redir", parseRedir)
	RegisterHandlerDirective("respond", parseRespond)
	RegisterHandlerDirective("abort", parseAbort)
	RegisterHandlerDirective("error", parseError)
	RegisterHandlerDirective("route", parseRoute)
	RegisterHandlerDirective("handle", parseHandle)
	RegisterDirective("handle_errors", parseHandleErrors)
	RegisterHandlerDirective("invoke", parseInvoke)
	RegisterDirective("log", parseLog)
	RegisterHandlerDirective("skip_log", parseLogSkip)
	RegisterHandlerDirective("log_skip", parseLogSkip)
	RegisterHandlerDirective("log_name", parseLogName)
}

// parseBind parses the bind directive. Syntax:
//
//		bind <addresses...> [{
//	   protocols [h1|h2|h2c|h3] [...]
//	 }]
func parseBind(h Helper) ([]ConfigValue, error) {
	h.Next() // consume directive name
	var addresses, protocols []string
	addresses = h.RemainingArgs()

	for h.NextBlock(0) {
		switch h.Val() {
		case "protocols":
			protocols = h.RemainingArgs()
			if len(protocols) == 0 {
				return nil, h.Errf("protocols requires one or more arguments")
			}
		default:
			return nil, h.Errf("unknown subdirective: %s", h.Val())
		}
	}

	return []ConfigValue{{Class: "bind", Value: addressesWithProtocols{
		addresses: addresses,
		protocols: protocols,
	}}}, nil
}

// parseTLS parses the tls directive. Syntax:
//
//	tls [<email>|internal|force_automate]|[<cert_file> <key_file>] {
//	    protocols <min> [<max>]
//	    ciphers   <cipher_suites...>
//	    curves    <curves...>
//	    client_auth {
//	        mode                   [request|require|verify_if_given|require_and_verify]
//	        trust_pool			   <module_name> [...]
//	        trusted_leaf_cert      <base64_der>
//	        trusted_leaf_cert_file <filename>
//	    }
//	    alpn                          <values...>
//	    load                          <paths...>
//	    ca                            <acme_ca_endpoint>
//	    ca_root                       <pem_file>
//	    key_type                      [ed25519|p256|p384|rsa2048|rsa4096]
//	    dns                           <provider_name> [...]
//	    propagation_delay             <duration>
//	    propagation_timeout           <duration>
//	    resolvers                     <dns_servers...>
//	    dns_ttl                       <duration>
//	    dns_challenge_override_domain <domain>
//	    on_demand
//	    reuse_private_keys
//	    force_automate
//	    eab                           <key_id> <mac_key>
//	    issuer                        <module_name> [...]
//	    get_certificate               <module_name> [...]
//	    insecure_secrets_log          <log_file>
//	}
func parseTLS(h Helper) ([]ConfigValue, error) {
	h.Next() // consume directive name

	cp := new(caddytls.ConnectionPolicy)
	var fileLoader caddytls.FileLoader
	var folderLoader caddytls.FolderLoader
	var certSelector caddytls.CustomCertSelectionPolicy
	var acmeIssuer *caddytls.ACMEIssuer
	var keyType string
	var internalIssuer *caddytls.InternalIssuer
	var issuers []certmagic.Issuer
	var certManagers []certmagic.Manager
	var onDemand bool
	var reusePrivateKeys bool
	var forceAutomate bool

	firstLine := h.RemainingArgs()
	switch len(firstLine) {
	case 0:
	case 1:
		if firstLine[0] == "internal" {
			internalIssuer = new(caddytls.InternalIssuer)
		} else if firstLine[0] == "force_automate" {
			forceAutomate = true
		} else if !strings.Contains(firstLine[0], "@") {
			return nil, h.Err("single argument must either be 'internal', 'force_automate', or an email address")
		} else {
			acmeIssuer = &caddytls.ACMEIssuer{
				Email: firstLine[0],
			}
		}

	case 2:
		// file certificate loader
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
	for h.NextBlock(0) {
		hasBlock = true

		switch h.Val() {
		case "protocols":
			args := h.RemainingArgs()
			if len(args) == 0 {
				return nil, h.Errf("protocols requires one or two arguments")
			}
			if len(args) > 0 {
				if _, ok := caddytls.SupportedProtocols[args[0]]; !ok {
					return nil, h.Errf("wrong protocol name or protocol not supported: '%s'", args[0])
				}
				cp.ProtocolMin = args[0]
			}
			if len(args) > 1 {
				if _, ok := caddytls.SupportedProtocols[args[1]]; !ok {
					return nil, h.Errf("wrong protocol name or protocol not supported: '%s'", args[1])
				}
				cp.ProtocolMax = args[1]
			}

		case "ciphers":
			for h.NextArg() {
				if !caddytls.CipherSuiteNameSupported(h.Val()) {
					return nil, h.Errf("wrong cipher suite name or cipher suite not supported: '%s'", h.Val())
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
			if err := cp.ClientAuthentication.UnmarshalCaddyfile(h.NewFromNextSegment()); err != nil {
				return nil, err
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

		case "get_certificate":
			if !h.NextArg() {
				return nil, h.ArgErr()
			}
			modName := h.Val()
			modID := "tls.get_certificate." + modName
			unm, err := caddyfile.UnmarshalModule(h.Dispenser, modID)
			if err != nil {
				return nil, err
			}
			certManager, ok := unm.(certmagic.Manager)
			if !ok {
				return nil, h.Errf("module %s (%T) is not a certmagic.CertificateManager", modID, unm)
			}
			certManagers = append(certManagers, certManager)

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

		case "propagation_delay":
			arg := h.RemainingArgs()
			if len(arg) != 1 {
				return nil, h.ArgErr()
			}
			delayStr := arg[0]
			delay, err := caddy.ParseDuration(delayStr)
			if err != nil {
				return nil, h.Errf("invalid propagation_delay duration %s: %v", delayStr, err)
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
			acmeIssuer.Challenges.DNS.PropagationDelay = caddy.Duration(delay)

		case "propagation_timeout":
			arg := h.RemainingArgs()
			if len(arg) != 1 {
				return nil, h.ArgErr()
			}
			timeoutStr := arg[0]
			var timeout time.Duration
			if timeoutStr == "-1" {
				timeout = time.Duration(-1)
			} else {
				var err error
				timeout, err = caddy.ParseDuration(timeoutStr)
				if err != nil {
					return nil, h.Errf("invalid propagation_timeout duration %s: %v", timeoutStr, err)
				}
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
			acmeIssuer.Challenges.DNS.PropagationTimeout = caddy.Duration(timeout)

		case "dns_ttl":
			arg := h.RemainingArgs()
			if len(arg) != 1 {
				return nil, h.ArgErr()
			}
			ttlStr := arg[0]
			ttl, err := caddy.ParseDuration(ttlStr)
			if err != nil {
				return nil, h.Errf("invalid dns_ttl duration %s: %v", ttlStr, err)
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
			acmeIssuer.Challenges.DNS.TTL = caddy.Duration(ttl)

		case "dns_challenge_override_domain":
			arg := h.RemainingArgs()
			if len(arg) != 1 {
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
			acmeIssuer.Challenges.DNS.OverrideDomain = arg[0]

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

		case "reuse_private_keys":
			if h.NextArg() {
				return nil, h.ArgErr()
			}
			reusePrivateKeys = true

		case "insecure_secrets_log":
			if !h.NextArg() {
				return nil, h.ArgErr()
			}
			cp.InsecureSecretsLog = h.Val()

		default:
			return nil, h.Errf("unknown subdirective: %s", h.Val())
		}
	}

	// a naked tls directive is not allowed
	if len(firstLine) == 0 && !hasBlock {
		return nil, h.ArgErr()
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
		defaultIssuers := caddytls.DefaultIssuers(acmeIssuer.Email)

		// if an ACME CA endpoint was set, the user expects to use that specific one,
		// not any others that may be defaults, so replace all defaults with that ACME CA
		if acmeIssuer.CA != "" {
			defaultIssuers = []certmagic.Issuer{acmeIssuer}
		}

		for _, issuer := range defaultIssuers {
			// apply settings from the implicitly-configured ACMEIssuer to any
			// default ACMEIssuers, but preserve each default issuer's CA endpoint,
			// because, for example, if you configure the DNS challenge, it should
			// apply to any of the default ACMEIssuers, but you don't want to trample
			// out their unique CA endpoints
			if iss, ok := issuer.(*caddytls.ACMEIssuer); ok && iss != nil {
				acmeCopy := *acmeIssuer
				acmeCopy.CA = iss.CA
				issuer = &acmeCopy
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
	for _, certManager := range certManagers {
		configVals = append(configVals, ConfigValue{
			Class: "tls.cert_manager",
			Value: certManager,
		})
	}

	// reuse private keys TLS
	if reusePrivateKeys {
		configVals = append(configVals, ConfigValue{
			Class: "tls.reuse_private_keys",
			Value: true,
		})
	}

	// if enabled, the names in the site addresses will be
	// added to the automation policies
	if forceAutomate {
		configVals = append(configVals, ConfigValue{
			Class: "tls.force_automate",
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
//	root [<matcher>] <path>
func parseRoot(h Helper) ([]ConfigValue, error) {
	h.Next() // consume directive name

	// count the tokens to determine what to do
	argsCount := h.CountRemainingArgs()
	if argsCount == 0 {
		return nil, h.Errf("too few arguments; must have at least a root path")
	}
	if argsCount > 2 {
		return nil, h.Errf("too many arguments; should only be a matcher and a path")
	}

	// with only one arg, assume it's a root path with no matcher token
	if argsCount == 1 {
		if !h.NextArg() {
			return nil, h.ArgErr()
		}
		return h.NewRoute(nil, caddyhttp.VarsMiddleware{"root": h.Val()}), nil
	}

	// parse the matcher token into a matcher set
	userMatcherSet, err := h.ExtractMatcherSet()
	if err != nil {
		return nil, err
	}
	h.Next() // consume directive name again, matcher parsing does a reset

	// advance to the root path
	if !h.NextArg() {
		return nil, h.ArgErr()
	}
	// make the route with the matcher
	return h.NewRoute(userMatcherSet, caddyhttp.VarsMiddleware{"root": h.Val()}), nil
}

// parseFilesystem parses the fs directive. Syntax:
//
//	fs <filesystem>
func parseFilesystem(h Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name
	if !h.NextArg() {
		return nil, h.ArgErr()
	}
	if h.NextArg() {
		return nil, h.ArgErr()
	}
	return caddyhttp.VarsMiddleware{"fs": h.Val()}, nil
}

// parseVars parses the vars directive. See its UnmarshalCaddyfile method for syntax.
func parseVars(h Helper) (caddyhttp.MiddlewareHandler, error) {
	v := new(caddyhttp.VarsMiddleware)
	err := v.UnmarshalCaddyfile(h.Dispenser)
	return v, err
}

// parseRedir parses the redir directive. Syntax:
//
//	redir [<matcher>] <to> [<code>]
//
// <code> can be "permanent" for 301, "temporary" for 302 (default),
// a placeholder, or any number in the 3xx range or 401. The special
// code "html" can be used to redirect only browser clients (will
// respond with HTTP 200 and no Location header; redirect is performed
// with JS and a meta tag).
func parseRedir(h Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name
	if !h.NextArg() {
		return nil, h.ArgErr()
	}
	to := h.Val()

	var code string
	if h.NextArg() {
		code = h.Val()
	}

	var body string
	var hdr http.Header
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
		hdr = http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}
		code = "200" // don't redirect non-browser clients

	default:
		// Allow placeholders for the code
		if strings.HasPrefix(code, "{") {
			break
		}
		// Try to validate as an integer otherwise
		codeInt, err := strconv.Atoi(code)
		if err != nil {
			return nil, h.Errf("Not a supported redir code type or not valid integer: '%s'", code)
		}
		// Sometimes, a 401 with Location header is desirable because
		// requests made with XHR will "eat" the 3xx redirect; so if
		// the intent was to redirect to an auth page, a 3xx won't
		// work. Responding with 401 allows JS code to read the
		// Location header and do a window.location redirect manually.
		// see https://stackoverflow.com/a/2573589/846934
		// see https://github.com/oauth2-proxy/oauth2-proxy/issues/1522
		if codeInt < 300 || (codeInt > 399 && codeInt != 401) {
			return nil, h.Errf("Redir code not in the 3xx range or 401: '%v'", codeInt)
		}
	}

	// don't redirect non-browser clients
	if code != "200" {
		hdr = http.Header{"Location": []string{to}}
	}

	return caddyhttp.StaticResponse{
		StatusCode: caddyhttp.WeakString(code),
		Headers:    hdr,
		Body:       body,
	}, nil
}

// parseRespond parses the respond directive.
func parseRespond(h Helper) (caddyhttp.MiddlewareHandler, error) {
	sr := new(caddyhttp.StaticResponse)
	err := sr.UnmarshalCaddyfile(h.Dispenser)
	return sr, err
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
	return se, err
}

// parseRoute parses the route directive.
func parseRoute(h Helper) (caddyhttp.MiddlewareHandler, error) {
	allResults, err := parseSegmentAsConfig(h)
	if err != nil {
		return nil, err
	}

	for _, result := range allResults {
		switch result.Value.(type) {
		case caddyhttp.Route, caddyhttp.Subroute:
		default:
			return nil, h.Errf("%s directive returned something other than an HTTP route or subroute: %#v (only handler directives can be used in routes)", result.directive, result.Value)
		}
	}

	return buildSubroute(allResults, h.groupCounter, false)
}

func parseHandle(h Helper) (caddyhttp.MiddlewareHandler, error) {
	return ParseSegmentAsSubroute(h)
}

func parseHandleErrors(h Helper) ([]ConfigValue, error) {
	h.Next() // consume directive name

	expression := ""
	args := h.RemainingArgs()
	if len(args) > 0 {
		codes := []string{}
		for _, val := range args {
			if len(val) != 3 {
				return nil, h.Errf("bad status value '%s'", val)
			}
			if strings.HasSuffix(val, "xx") {
				val = val[:1]
				_, err := strconv.Atoi(val)
				if err != nil {
					return nil, h.Errf("bad status value '%s': %v", val, err)
				}
				if expression != "" {
					expression += " || "
				}
				expression += fmt.Sprintf("{http.error.status_code} >= %s00 && {http.error.status_code} <= %s99", val, val)
				continue
			}
			_, err := strconv.Atoi(val)
			if err != nil {
				return nil, h.Errf("bad status value '%s': %v", val, err)
			}
			codes = append(codes, val)
		}
		if len(codes) > 0 {
			if expression != "" {
				expression += " || "
			}
			expression += "{http.error.status_code} in [" + strings.Join(codes, ", ") + "]"
		}
		// Reset cursor position to get ready for ParseSegmentAsSubroute
		h.Reset()
		h.Next()
		h.RemainingArgs()
		h.Prev()
	} else {
		// If no arguments present reset the cursor position to get ready for ParseSegmentAsSubroute
		h.Prev()
	}

	handler, err := ParseSegmentAsSubroute(h)
	if err != nil {
		return nil, err
	}
	subroute, ok := handler.(*caddyhttp.Subroute)
	if !ok {
		return nil, h.Errf("segment was not parsed as a subroute")
	}

	if expression != "" {
		statusMatcher := caddy.ModuleMap{
			"expression": h.JSON(caddyhttp.MatchExpression{Expr: expression}),
		}
		for i := range subroute.Routes {
			subroute.Routes[i].MatcherSetsRaw = []caddy.ModuleMap{statusMatcher}
		}
	}
	return []ConfigValue{
		{
			Class: "error_route",
			Value: subroute,
		},
	}, nil
}

// parseInvoke parses the invoke directive.
func parseInvoke(h Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive
	if !h.NextArg() {
		return nil, h.ArgErr()
	}
	for h.Next() || h.NextBlock(0) {
		return nil, h.ArgErr()
	}

	// remember that we're invoking this name
	// to populate the server with these named routes
	if h.State[namedRouteKey] == nil {
		h.State[namedRouteKey] = map[string]struct{}{}
	}
	h.State[namedRouteKey].(map[string]struct{})[h.Val()] = struct{}{}

	// return the handler
	return &caddyhttp.Invoke{Name: h.Val()}, nil
}

// parseLog parses the log directive. Syntax:
//
//	log <logger_name> {
//	    hostnames <hostnames...>
//	    output <writer_module> ...
//	    core   <core_module> ...
//	    format <encoder_module> ...
//	    level  <level>
//	}
func parseLog(h Helper) ([]ConfigValue, error) {
	return parseLogHelper(h, nil)
}

// parseLogHelper is used both for the parseLog directive within Server Blocks,
// as well as the global "log" option for configuring loggers at the global
// level. The parseAsGlobalOption parameter is used to distinguish any differing logic
// between the two.
func parseLogHelper(h Helper, globalLogNames map[string]struct{}) ([]ConfigValue, error) {
	h.Next() // consume option name

	// When the globalLogNames parameter is passed in, we make
	// modifications to the parsing behavior.
	parseAsGlobalOption := globalLogNames != nil

	var configValues []ConfigValue

	// Logic below expects that a name is always present when a
	// global option is being parsed; or an optional override
	// is supported for access logs.
	var logName string

	if parseAsGlobalOption {
		if h.NextArg() {
			logName = h.Val()

			// Only a single argument is supported.
			if h.NextArg() {
				return nil, h.ArgErr()
			}
		} else {
			// If there is no log name specified, we
			// reference the default logger. See the
			// setupNewDefault function in the logging
			// package for where this is configured.
			logName = caddy.DefaultLoggerName
		}

		// Verify this name is unused.
		_, used := globalLogNames[logName]
		if used {
			return nil, h.Err("duplicate global log option for: " + logName)
		}
		globalLogNames[logName] = struct{}{}
	} else {
		// An optional override of the logger name can be provided;
		// otherwise a default will be used, like "log0", "log1", etc.
		if h.NextArg() {
			logName = h.Val()

			// Only a single argument is supported.
			if h.NextArg() {
				return nil, h.ArgErr()
			}
		}
	}

	cl := new(caddy.CustomLog)

	// allow overriding the current site block's hostnames for this logger;
	// this is useful for setting up loggers per subdomain in a site block
	// with a wildcard domain
	customHostnames := []string{}
	noHostname := false
	for h.NextBlock(0) {
		switch h.Val() {
		case "hostnames":
			if parseAsGlobalOption {
				return nil, h.Err("hostnames is not allowed in the log global options")
			}
			args := h.RemainingArgs()
			if len(args) == 0 {
				return nil, h.ArgErr()
			}
			customHostnames = append(customHostnames, args...)

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

		case "sampling":
			d := h.Dispenser.NewFromNextSegment()
			for d.NextArg() {
				// consume any tokens on the same line, if any.
			}

			sampling := &caddy.LogSampling{}
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				subdir := d.Val()
				switch subdir {
				case "interval":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					interval, err := time.ParseDuration(d.Val() + "ns")
					if err != nil {
						return nil, d.Errf("failed to parse interval: %v", err)
					}
					sampling.Interval = interval
				case "first":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					first, err := strconv.Atoi(d.Val())
					if err != nil {
						return nil, d.Errf("failed to parse first: %v", err)
					}
					sampling.First = first
				case "thereafter":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					thereafter, err := strconv.Atoi(d.Val())
					if err != nil {
						return nil, d.Errf("failed to parse thereafter: %v", err)
					}
					sampling.Thereafter = thereafter
				default:
					return nil, d.Errf("unrecognized subdirective: %s", subdir)
				}
			}

			cl.Sampling = sampling

		case "core":
			if !h.NextArg() {
				return nil, h.ArgErr()
			}
			moduleName := h.Val()
			moduleID := "caddy.logging.cores." + moduleName
			unm, err := caddyfile.UnmarshalModule(h.Dispenser, moduleID)
			if err != nil {
				return nil, err
			}
			core, ok := unm.(zapcore.Core)
			if !ok {
				return nil, h.Errf("module %s (%T) is not a zapcore.Core", moduleID, unm)
			}
			cl.CoreRaw = caddyconfig.JSONModuleObject(core, "module", moduleName, h.warnings)

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
			if !parseAsGlobalOption {
				return nil, h.Err("include is not allowed in the log directive")
			}
			for h.NextArg() {
				cl.Include = append(cl.Include, h.Val())
			}

		case "exclude":
			if !parseAsGlobalOption {
				return nil, h.Err("exclude is not allowed in the log directive")
			}
			for h.NextArg() {
				cl.Exclude = append(cl.Exclude, h.Val())
			}

		case "no_hostname":
			if h.NextArg() {
				return nil, h.ArgErr()
			}
			noHostname = true

		default:
			return nil, h.Errf("unrecognized subdirective: %s", h.Val())
		}
	}

	var val namedCustomLog
	val.hostnames = customHostnames
	val.noHostname = noHostname
	isEmptyConfig := reflect.DeepEqual(cl, new(caddy.CustomLog))

	// Skip handling of empty logging configs

	if parseAsGlobalOption {
		// Use indicated name for global log options
		val.name = logName
	} else {
		if logName != "" {
			val.name = logName
		} else if !isEmptyConfig {
			// Construct a log name for server log streams
			logCounter, ok := h.State["logCounter"].(int)
			if !ok {
				logCounter = 0
			}
			val.name = fmt.Sprintf("log%d", logCounter)
			logCounter++
			h.State["logCounter"] = logCounter
		}
		if val.name != "" {
			cl.Include = []string{"http.log.access." + val.name}
		}
	}
	if !isEmptyConfig {
		val.log = cl
	}
	configValues = append(configValues, ConfigValue{
		Class: "custom_log",
		Value: val,
	})
	return configValues, nil
}

// parseLogSkip parses the log_skip directive. Syntax:
//
//	log_skip [<matcher>]
func parseLogSkip(h Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name

	// "skip_log" is deprecated, replaced by "log_skip"
	if h.Val() == "skip_log" {
		caddy.Log().Named("config.adapter.caddyfile").Warn("the 'skip_log' directive is deprecated, please use 'log_skip' instead!")
	}

	if h.NextArg() {
		return nil, h.ArgErr()
	}
	return caddyhttp.VarsMiddleware{"log_skip": true}, nil
}

// parseLogName parses the log_name directive. Syntax:
//
//	log_name <names...>
func parseLogName(h Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next() // consume directive name
	return caddyhttp.VarsMiddleware{
		caddyhttp.AccessLoggerNameVarKey: h.RemainingArgs(),
	}, nil
}
