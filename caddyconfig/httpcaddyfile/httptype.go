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
	"log"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddyconfig.RegisterAdapter("caddyfile", caddyfile.Adapter{ServerType: ServerType{}})
}

// App represents the configuration for a non-standard
// Caddy app module (e.g. third-party plugin) which was
// parsed from a global options block.
type App struct {
	// The JSON key for the app being configured
	Name string

	// The raw app config as JSON
	Value json.RawMessage
}

// ServerType can set up a config from an HTTP Caddyfile.
type ServerType struct {
}

// Setup makes a config from the tokens.
func (st ServerType) Setup(inputServerBlocks []caddyfile.ServerBlock,
	options map[string]interface{}) (*caddy.Config, []caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning
	gc := counter{new(int)}
	state := make(map[string]interface{})

	// load all the server blocks and associate them with a "pile"
	// of config values; also prohibit duplicate keys because they
	// can make a config confusing if more than one server block is
	// chosen to handle a request - we actually will make each
	// server block's route terminal so that only one will run
	sbKeys := make(map[string]struct{})
	originalServerBlocks := make([]serverBlock, 0, len(inputServerBlocks))
	for i, sblock := range inputServerBlocks {
		for j, k := range sblock.Keys {
			if j == 0 && strings.HasPrefix(k, "@") {
				return nil, warnings, fmt.Errorf("cannot define a matcher outside of a site block: '%s'", k)
			}
			if _, ok := sbKeys[k]; ok {
				return nil, warnings, fmt.Errorf("duplicate site address not allowed: '%s' in %v (site block %d, key %d)", k, sblock.Keys, i, j)
			}
			sbKeys[k] = struct{}{}
		}
		originalServerBlocks = append(originalServerBlocks, serverBlock{
			block: sblock,
			pile:  make(map[string][]ConfigValue),
		})
	}

	// apply any global options
	var err error
	originalServerBlocks, err = st.evaluateGlobalOptionsBlock(originalServerBlocks, options)
	if err != nil {
		return nil, warnings, err
	}

	// replace shorthand placeholders (which are
	// convenient when writing a Caddyfile) with
	// their actual placeholder identifiers or
	// variable names
	replacer := strings.NewReplacer(
		"{dir}", "{http.request.uri.path.dir}",
		"{file}", "{http.request.uri.path.file}",
		"{host}", "{http.request.host}",
		"{hostport}", "{http.request.hostport}",
		"{port}", "{http.request.port}",
		"{method}", "{http.request.method}",
		"{path}", "{http.request.uri.path}",
		"{query}", "{http.request.uri.query}",
		"{remote}", "{http.request.remote}",
		"{remote_host}", "{http.request.remote.host}",
		"{remote_port}", "{http.request.remote.port}",
		"{scheme}", "{http.request.scheme}",
		"{uri}", "{http.request.uri}",
		"{tls_cipher}", "{http.request.tls.cipher_suite}",
		"{tls_version}", "{http.request.tls.version}",
		"{tls_client_fingerprint}", "{http.request.tls.client.fingerprint}",
		"{tls_client_issuer}", "{http.request.tls.client.issuer}",
		"{tls_client_serial}", "{http.request.tls.client.serial}",
		"{tls_client_subject}", "{http.request.tls.client.subject}",
		"{tls_client_certificate_pem}", "{http.request.tls.client.certificate_pem}",
	)

	// these are placeholders that allow a user-defined final
	// parameters, but we still want to provide a shorthand
	// for those, so we use a regexp to replace
	regexpReplacements := []struct {
		search  *regexp.Regexp
		replace string
	}{
		{regexp.MustCompile(`{query\.([\w-]*)}`), "{http.request.uri.query.$1}"},
		{regexp.MustCompile(`{labels\.([\w-]*)}`), "{http.request.host.labels.$1}"},
		{regexp.MustCompile(`{header\.([\w-]*)}`), "{http.request.header.$1}"},
		{regexp.MustCompile(`{path\.([\w-]*)}`), "{http.request.uri.path.$1}"},
		{regexp.MustCompile(`{re\.([\w-]*)\.([\w-]*)}`), "{http.regexp.$1.$2}"},
	}

	for _, sb := range originalServerBlocks {
		for _, segment := range sb.block.Segments {
			for i := 0; i < len(segment); i++ {
				// simple string replacements
				segment[i].Text = replacer.Replace(segment[i].Text)
				// complex regexp replacements
				for _, r := range regexpReplacements {
					segment[i].Text = r.search.ReplaceAllString(segment[i].Text, r.replace)
				}
			}
		}

		if len(sb.block.Keys) == 0 {
			return nil, warnings, fmt.Errorf("server block without any key is global configuration, and if used, it must be first")
		}

		// extract matcher definitions
		matcherDefs := make(map[string]caddy.ModuleMap)
		for _, segment := range sb.block.Segments {
			if dir := segment.Directive(); strings.HasPrefix(dir, matcherPrefix) {
				d := sb.block.DispenseDirective(dir)
				err := parseMatcherDefinitions(d, matcherDefs)
				if err != nil {
					return nil, warnings, err
				}
			}
		}

		// evaluate each directive ("segment") in this block
		for _, segment := range sb.block.Segments {
			dir := segment.Directive()

			if strings.HasPrefix(dir, matcherPrefix) {
				// matcher definitions were pre-processed
				continue
			}

			dirFunc, ok := registeredDirectives[dir]
			if !ok {
				tkn := segment[0]
				return nil, warnings, fmt.Errorf("%s:%d: unrecognized directive: %s", tkn.File, tkn.Line, dir)
			}

			h := Helper{
				Dispenser:    caddyfile.NewDispenser(segment),
				options:      options,
				warnings:     &warnings,
				matcherDefs:  matcherDefs,
				parentBlock:  sb.block,
				groupCounter: gc,
				State:        state,
			}

			results, err := dirFunc(h)
			if err != nil {
				return nil, warnings, fmt.Errorf("parsing caddyfile tokens for '%s': %v", dir, err)
			}

			// As a special case, we want "handle_path" to be sorted
			// at the same level as "handle", so we force them to use
			// the same directive name after their parsing is complete.
			// See https://github.com/caddyserver/caddy/issues/3675#issuecomment-678042377
			if dir == "handle_path" {
				dir = "handle"
			}

			for _, result := range results {
				result.directive = dir
				sb.pile[result.Class] = append(sb.pile[result.Class], result)
			}
		}
	}

	// map
	sbmap, err := st.mapAddressToServerBlocks(originalServerBlocks, options)
	if err != nil {
		return nil, warnings, err
	}

	// reduce
	pairings := st.consolidateAddrMappings(sbmap)

	// each pairing of listener addresses to list of server
	// blocks is basically a server definition
	servers, err := st.serversFromPairings(pairings, options, &warnings, gc)
	if err != nil {
		return nil, warnings, err
	}

	// now that each server is configured, make the HTTP app
	httpApp := caddyhttp.App{
		HTTPPort:    tryInt(options["http_port"], &warnings),
		HTTPSPort:   tryInt(options["https_port"], &warnings),
		GracePeriod: tryDuration(options["grace_period"], &warnings),
		Servers:     servers,
	}

	// then make the TLS app
	tlsApp, warnings, err := st.buildTLSApp(pairings, options, warnings)
	if err != nil {
		return nil, warnings, err
	}

	// then make the PKI app
	pkiApp, warnings, err := st.buildPKIApp(pairings, options, warnings)
	if err != nil {
		return nil, warnings, err
	}

	// extract any custom logs, and enforce configured levels
	var customLogs []namedCustomLog
	var hasDefaultLog bool
	addCustomLog := func(ncl namedCustomLog) {
		if ncl.name == "" {
			return
		}
		if ncl.name == "default" {
			hasDefaultLog = true
		}
		if _, ok := options["debug"]; ok && ncl.log.Level == "" {
			ncl.log.Level = "DEBUG"
		}
		customLogs = append(customLogs, ncl)
	}
	// Apply global log options, when set
	if options["log"] != nil {
		for _, logValue := range options["log"].([]ConfigValue) {
			addCustomLog(logValue.Value.(namedCustomLog))
		}
	}
	// Apply server-specific log options
	for _, p := range pairings {
		for _, sb := range p.serverBlocks {
			for _, clVal := range sb.pile["custom_log"] {
				addCustomLog(clVal.Value.(namedCustomLog))
			}
		}
	}

	if !hasDefaultLog {
		// if the default log was not customized, ensure we
		// configure it with any applicable options
		if _, ok := options["debug"]; ok {
			customLogs = append(customLogs, namedCustomLog{
				name: "default",
				log:  &caddy.CustomLog{Level: "DEBUG"},
			})
		}
	}

	// annnd the top-level config, then we're done!
	cfg := &caddy.Config{AppsRaw: make(caddy.ModuleMap)}

	// loop through the configured options, and if any of
	// them are an httpcaddyfile App, then we insert them
	// into the config as raw Caddy apps
	for _, opt := range options {
		if app, ok := opt.(App); ok {
			cfg.AppsRaw[app.Name] = app.Value
		}
	}

	// insert the standard Caddy apps into the config
	if len(httpApp.Servers) > 0 {
		cfg.AppsRaw["http"] = caddyconfig.JSON(httpApp, &warnings)
	}
	if !reflect.DeepEqual(tlsApp, &caddytls.TLS{CertificatesRaw: make(caddy.ModuleMap)}) {
		cfg.AppsRaw["tls"] = caddyconfig.JSON(tlsApp, &warnings)
	}
	if !reflect.DeepEqual(pkiApp, &caddypki.PKI{CAs: make(map[string]*caddypki.CA)}) {
		cfg.AppsRaw["pki"] = caddyconfig.JSON(pkiApp, &warnings)
	}
	if storageCvtr, ok := options["storage"].(caddy.StorageConverter); ok {
		cfg.StorageRaw = caddyconfig.JSONModuleObject(storageCvtr,
			"module",
			storageCvtr.(caddy.Module).CaddyModule().ID.Name(),
			&warnings)
	}
	if adminConfig, ok := options["admin"].(*caddy.AdminConfig); ok && adminConfig != nil {
		cfg.Admin = adminConfig
	}
	if len(customLogs) > 0 {
		if cfg.Logging == nil {
			cfg.Logging = &caddy.Logging{
				Logs: make(map[string]*caddy.CustomLog),
			}
		}
		for _, ncl := range customLogs {
			if ncl.name != "" {
				cfg.Logging.Logs[ncl.name] = ncl.log
			}
			// most users seem to prefer not writing access logs
			// to the default log when they are directed to a
			// file or have any other special customization
			if ncl.name != "default" && len(ncl.log.Include) > 0 {
				defaultLog, ok := cfg.Logging.Logs["default"]
				if !ok {
					defaultLog = new(caddy.CustomLog)
					cfg.Logging.Logs["default"] = defaultLog
				}
				defaultLog.Exclude = append(defaultLog.Exclude, ncl.log.Include...)
			}
		}
	}

	return cfg, warnings, nil
}

// evaluateGlobalOptionsBlock evaluates the global options block,
// which is expected to be the first server block if it has zero
// keys. It returns the updated list of server blocks with the
// global options block removed, and updates options accordingly.
func (ServerType) evaluateGlobalOptionsBlock(serverBlocks []serverBlock, options map[string]interface{}) ([]serverBlock, error) {
	if len(serverBlocks) == 0 || len(serverBlocks[0].block.Keys) > 0 {
		return serverBlocks, nil
	}

	for _, segment := range serverBlocks[0].block.Segments {
		opt := segment.Directive()
		var val interface{}
		var err error
		disp := caddyfile.NewDispenser(segment)

		optFunc, ok := registeredGlobalOptions[opt]
		if !ok {
			tkn := segment[0]
			return nil, fmt.Errorf("%s:%d: unrecognized global option: %s", tkn.File, tkn.Line, opt)
		}

		val, err = optFunc(disp, options[opt])
		if err != nil {
			return nil, fmt.Errorf("parsing caddyfile tokens for '%s': %v", opt, err)
		}

		// As a special case, fold multiple "servers" options together
		// in an array instead of overwriting a possible existing value
		if opt == "servers" {
			existingOpts, ok := options[opt].([]serverOptions)
			if !ok {
				existingOpts = []serverOptions{}
			}
			serverOpts, ok := val.(serverOptions)
			if !ok {
				return nil, fmt.Errorf("unexpected type from 'servers' global options: %T", val)
			}
			options[opt] = append(existingOpts, serverOpts)
			continue
		}
		// Additionally, fold multiple "log" options together into an
		// array so that multiple loggers can be configured.
		if opt == "log" {
			existingOpts, ok := options[opt].([]ConfigValue)
			if !ok {
				existingOpts = []ConfigValue{}
			}
			logOpts, ok := val.([]ConfigValue)
			if !ok {
				return nil, fmt.Errorf("unexpected type from 'log' global options: %T", val)
			}
			options[opt] = append(existingOpts, logOpts...)
			continue
		}

		options[opt] = val
	}

	// If we got "servers" options, we'll sort them by their listener address
	if serverOpts, ok := options["servers"].([]serverOptions); ok {
		sort.Slice(serverOpts, func(i, j int) bool {
			return len(serverOpts[i].ListenerAddress) > len(serverOpts[j].ListenerAddress)
		})

		// Reject the config if there are duplicate listener address
		seen := make(map[string]bool)
		for _, entry := range serverOpts {
			if _, alreadySeen := seen[entry.ListenerAddress]; alreadySeen {
				return nil, fmt.Errorf("cannot have 'servers' global options with duplicate listener addresses: %s", entry.ListenerAddress)
			}
			seen[entry.ListenerAddress] = true
		}
	}

	return serverBlocks[1:], nil
}

// serversFromPairings creates the servers for each pairing of addresses
// to server blocks. Each pairing is essentially a server definition.
func (st *ServerType) serversFromPairings(
	pairings []sbAddrAssociation,
	options map[string]interface{},
	warnings *[]caddyconfig.Warning,
	groupCounter counter,
) (map[string]*caddyhttp.Server, error) {
	servers := make(map[string]*caddyhttp.Server)
	defaultSNI := tryString(options["default_sni"], warnings)

	httpPort := strconv.Itoa(caddyhttp.DefaultHTTPPort)
	if hp, ok := options["http_port"].(int); ok {
		httpPort = strconv.Itoa(hp)
	}
	httpsPort := strconv.Itoa(caddyhttp.DefaultHTTPSPort)
	if hsp, ok := options["https_port"].(int); ok {
		httpsPort = strconv.Itoa(hsp)
	}
	autoHTTPS := "on"
	if ah, ok := options["auto_https"].(string); ok {
		autoHTTPS = ah
	}

	for i, p := range pairings {
		srv := &caddyhttp.Server{
			Listen: p.addresses,
		}

		// handle the auto_https global option
		if autoHTTPS != "on" {
			srv.AutoHTTPS = new(caddyhttp.AutoHTTPSConfig)
			if autoHTTPS == "off" {
				srv.AutoHTTPS.Disabled = true
			}
			if autoHTTPS == "disable_redirects" {
				srv.AutoHTTPS.DisableRedir = true
			}
			if autoHTTPS == "ignore_loaded_certs" {
				srv.AutoHTTPS.IgnoreLoadedCerts = true
			}
		}

		// sort server blocks by their keys; this is important because
		// only the first matching site should be evaluated, and we should
		// attempt to match most specific site first (host and path), in
		// case their matchers overlap; we do this somewhat naively by
		// descending sort by length of host then path
		sort.SliceStable(p.serverBlocks, func(i, j int) bool {
			// TODO: we could pre-process the specificities for efficiency,
			// but I don't expect many blocks will have THAT many keys...
			var iLongestPath, jLongestPath string
			var iLongestHost, jLongestHost string
			var iWildcardHost, jWildcardHost bool
			for _, addr := range p.serverBlocks[i].keys {
				if strings.Contains(addr.Host, "*") || addr.Host == "" {
					iWildcardHost = true
				}
				if specificity(addr.Host) > specificity(iLongestHost) {
					iLongestHost = addr.Host
				}
				if specificity(addr.Path) > specificity(iLongestPath) {
					iLongestPath = addr.Path
				}
			}
			for _, addr := range p.serverBlocks[j].keys {
				if strings.Contains(addr.Host, "*") || addr.Host == "" {
					jWildcardHost = true
				}
				if specificity(addr.Host) > specificity(jLongestHost) {
					jLongestHost = addr.Host
				}
				if specificity(addr.Path) > specificity(jLongestPath) {
					jLongestPath = addr.Path
				}
			}
			// catch-all blocks (blocks with no hostname) should always go
			// last, even after blocks with wildcard hosts
			if specificity(iLongestHost) == 0 {
				return false
			}
			if specificity(jLongestHost) == 0 {
				return true
			}
			if iWildcardHost != jWildcardHost {
				// site blocks that have a key with a wildcard in the hostname
				// must always be less specific than blocks without one; see
				// https://github.com/caddyserver/caddy/issues/3410
				return jWildcardHost && !iWildcardHost
			}
			if specificity(iLongestHost) == specificity(jLongestHost) {
				return len(iLongestPath) > len(jLongestPath)
			}
			return specificity(iLongestHost) > specificity(jLongestHost)
		})

		var hasCatchAllTLSConnPolicy, addressQualifiesForTLS bool
		autoHTTPSWillAddConnPolicy := autoHTTPS != "off"

		// if a catch-all server block (one which accepts all hostnames) exists in this pairing,
		// we need to know that so that we can configure logs properly (see #3878)
		var catchAllSblockExists bool
		for _, sblock := range p.serverBlocks {
			if len(sblock.hostsFromKeys(false)) == 0 {
				catchAllSblockExists = true
			}
		}

		// create a subroute for each site in the server block
		for _, sblock := range p.serverBlocks {
			matcherSetsEnc, err := st.compileEncodedMatcherSets(sblock)
			if err != nil {
				return nil, fmt.Errorf("server block %v: compiling matcher sets: %v", sblock.block.Keys, err)
			}

			hosts := sblock.hostsFromKeys(false)

			// emit warnings if user put unspecified IP addresses; they probably want the bind directive
			for _, h := range hosts {
				if h == "0.0.0.0" || h == "::" {
					log.Printf("[WARNING] Site block has unspecified IP address %s which only matches requests having that Host header; you probably want the 'bind' directive to configure the socket", h)
				}
			}

			// tls: connection policies
			if cpVals, ok := sblock.pile["tls.connection_policy"]; ok {
				// tls connection policies
				for _, cpVal := range cpVals {
					cp := cpVal.Value.(*caddytls.ConnectionPolicy)

					// make sure the policy covers all hostnames from the block
					for _, h := range hosts {
						if h == defaultSNI {
							hosts = append(hosts, "")
							cp.DefaultSNI = defaultSNI
							break
						}
					}

					if len(hosts) > 0 {
						cp.MatchersRaw = caddy.ModuleMap{
							"sni": caddyconfig.JSON(hosts, warnings), // make sure to match all hosts, not just auto-HTTPS-qualified ones
						}
					} else {
						cp.DefaultSNI = defaultSNI
					}

					// only append this policy if it actually changes something
					if !cp.SettingsEmpty() {
						srv.TLSConnPolicies = append(srv.TLSConnPolicies, cp)
						hasCatchAllTLSConnPolicy = len(hosts) == 0
					}
				}
			}

			for _, addr := range sblock.keys {
				// if server only uses HTTPS port, auto-HTTPS will not apply
				if listenersUseAnyPortOtherThan(srv.Listen, httpPort) {
					// exclude any hosts that were defined explicitly with "http://"
					// in the key from automated cert management (issue #2998)
					if addr.Scheme == "http" && addr.Host != "" {
						if srv.AutoHTTPS == nil {
							srv.AutoHTTPS = new(caddyhttp.AutoHTTPSConfig)
						}
						if !sliceContains(srv.AutoHTTPS.Skip, addr.Host) {
							srv.AutoHTTPS.Skip = append(srv.AutoHTTPS.Skip, addr.Host)
						}
					}
				}

				// we'll need to remember if the address qualifies for auto-HTTPS, so we
				// can add a TLS conn policy if necessary
				if addr.Scheme == "https" ||
					(addr.Scheme != "http" && addr.Host != "" && addr.Port != httpPort) {
					addressQualifiesForTLS = true
				}
				// predict whether auto-HTTPS will add the conn policy for us; if so, we
				// may not need to add one for this server
				autoHTTPSWillAddConnPolicy = autoHTTPSWillAddConnPolicy &&
					(addr.Port == httpsPort || (addr.Port != httpPort && addr.Host != ""))
			}

			// Look for any config values that provide listener wrappers on the server block
			for _, listenerConfig := range sblock.pile["listener_wrapper"] {
				listenerWrapper, ok := listenerConfig.Value.(caddy.ListenerWrapper)
				if !ok {
					return nil, fmt.Errorf("config for a listener wrapper did not provide a value that implements caddy.ListenerWrapper")
				}
				jsonListenerWrapper := caddyconfig.JSONModuleObject(
					listenerWrapper,
					"wrapper",
					listenerWrapper.(caddy.Module).CaddyModule().ID.Name(),
					warnings)
				srv.ListenerWrappersRaw = append(srv.ListenerWrappersRaw, jsonListenerWrapper)
			}

			// set up each handler directive, making sure to honor directive order
			dirRoutes := sblock.pile["route"]
			siteSubroute, err := buildSubroute(dirRoutes, groupCounter)
			if err != nil {
				return nil, err
			}

			// add the site block's route(s) to the server
			srv.Routes = appendSubrouteToRouteList(srv.Routes, siteSubroute, matcherSetsEnc, p, warnings)

			// if error routes are defined, add those too
			if errorSubrouteVals, ok := sblock.pile["error_route"]; ok {
				if srv.Errors == nil {
					srv.Errors = new(caddyhttp.HTTPErrorConfig)
				}
				for _, val := range errorSubrouteVals {
					sr := val.Value.(*caddyhttp.Subroute)
					srv.Errors.Routes = appendSubrouteToRouteList(srv.Errors.Routes, sr, matcherSetsEnc, p, warnings)
				}
			}

			// add log associations
			// see https://github.com/caddyserver/caddy/issues/3310
			sblockLogHosts := sblock.hostsFromKeys(true)
			for _, cval := range sblock.pile["custom_log"] {
				ncl := cval.Value.(namedCustomLog)
				if srv.Logs == nil {
					srv.Logs = new(caddyhttp.ServerLogConfig)
				}
				if sblock.hasHostCatchAllKey() {
					// all requests for hosts not able to be listed should use
					// this log because it's a catch-all-hosts server block
					srv.Logs.DefaultLoggerName = ncl.name
				} else {
					// map each host to the user's desired logger name
					for _, h := range sblockLogHosts {
						// if the custom logger name is non-empty, add it to the map;
						// otherwise, only map to an empty logger name if this or
						// another site block on this server has a catch-all host (in
						// which case only requests with mapped hostnames will be
						// access-logged, so it'll be necessary to add them to the
						// map even if they use default logger)
						if ncl.name != "" || catchAllSblockExists {
							if srv.Logs.LoggerNames == nil {
								srv.Logs.LoggerNames = make(map[string]string)
							}
							srv.Logs.LoggerNames[h] = ncl.name
						}
					}
				}
			}
			if srv.Logs != nil && len(sblock.pile["custom_log"]) == 0 {
				// server has access logs enabled, but this server block does not
				// enable access logs; therefore, all hosts of this server block
				// should not be access-logged
				if len(hosts) == 0 {
					// if the server block has a catch-all-hosts key, then we should
					// not log reqs to any host unless it appears in the map
					srv.Logs.SkipUnmappedHosts = true
				}
				srv.Logs.SkipHosts = append(srv.Logs.SkipHosts, sblockLogHosts...)
			}
		}

		// a server cannot (natively) serve both HTTP and HTTPS at the
		// same time, so make sure the configuration isn't in conflict
		err := detectConflictingSchemes(srv, p.serverBlocks, options)
		if err != nil {
			return nil, err
		}

		// a catch-all TLS conn policy is necessary to ensure TLS can
		// be offered to all hostnames of the server; even though only
		// one policy is needed to enable TLS for the server, that
		// policy might apply to only certain TLS handshakes; but when
		// using the Caddyfile, user would expect all handshakes to at
		// least have a matching connection policy, so here we append a
		// catch-all/default policy if there isn't one already (it's
		// important that it goes at the end) - see issue #3004:
		// https://github.com/caddyserver/caddy/issues/3004
		// TODO: maybe a smarter way to handle this might be to just make the
		// auto-HTTPS logic at provision-time detect if there is any connection
		// policy missing for any HTTPS-enabled hosts, if so, add it... maybe?
		if addressQualifiesForTLS &&
			!hasCatchAllTLSConnPolicy &&
			(len(srv.TLSConnPolicies) > 0 || !autoHTTPSWillAddConnPolicy || defaultSNI != "") {
			srv.TLSConnPolicies = append(srv.TLSConnPolicies, &caddytls.ConnectionPolicy{DefaultSNI: defaultSNI})
		}

		// tidy things up a bit
		srv.TLSConnPolicies, err = consolidateConnPolicies(srv.TLSConnPolicies)
		if err != nil {
			return nil, fmt.Errorf("consolidating TLS connection policies for server %d: %v", i, err)
		}
		srv.Routes = consolidateRoutes(srv.Routes)

		servers[fmt.Sprintf("srv%d", i)] = srv
	}

	err := applyServerOptions(servers, options, warnings)
	if err != nil {
		return nil, err
	}

	return servers, nil
}

func detectConflictingSchemes(srv *caddyhttp.Server, serverBlocks []serverBlock, options map[string]interface{}) error {
	httpPort := strconv.Itoa(caddyhttp.DefaultHTTPPort)
	if hp, ok := options["http_port"].(int); ok {
		httpPort = strconv.Itoa(hp)
	}
	httpsPort := strconv.Itoa(caddyhttp.DefaultHTTPSPort)
	if hsp, ok := options["https_port"].(int); ok {
		httpsPort = strconv.Itoa(hsp)
	}

	var httpOrHTTPS string
	checkAndSetHTTP := func(addr Address) error {
		if httpOrHTTPS == "HTTPS" {
			errMsg := fmt.Errorf("server listening on %v is configured for HTTPS and cannot natively multiplex HTTP and HTTPS: %s",
				srv.Listen, addr.Original)
			if addr.Scheme == "" && addr.Host == "" {
				errMsg = fmt.Errorf("%s (try specifying https:// in the address)", errMsg)
			}
			return errMsg
		}
		if len(srv.TLSConnPolicies) > 0 {
			// any connection policies created for an HTTP server
			// is a logical conflict, as it would enable HTTPS
			return fmt.Errorf("server listening on %v is HTTP, but attempts to configure TLS connection policies", srv.Listen)
		}
		httpOrHTTPS = "HTTP"
		return nil
	}
	checkAndSetHTTPS := func(addr Address) error {
		if httpOrHTTPS == "HTTP" {
			return fmt.Errorf("server listening on %v is configured for HTTP and cannot natively multiplex HTTP and HTTPS: %s",
				srv.Listen, addr.Original)
		}
		httpOrHTTPS = "HTTPS"
		return nil
	}

	for _, sblock := range serverBlocks {
		for _, addr := range sblock.keys {
			if addr.Scheme == "http" || addr.Port == httpPort {
				if err := checkAndSetHTTP(addr); err != nil {
					return err
				}
			} else if addr.Scheme == "https" || addr.Port == httpsPort || len(srv.TLSConnPolicies) > 0 {
				if err := checkAndSetHTTPS(addr); err != nil {
					return err
				}
			} else if addr.Host == "" {
				if err := checkAndSetHTTP(addr); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// consolidateConnPolicies sorts any catch-all policy to the end, removes empty TLS connection
// policies, and combines equivalent ones for a cleaner overall output.
func consolidateConnPolicies(cps caddytls.ConnectionPolicies) (caddytls.ConnectionPolicies, error) {
	// catch-all policies (those without any matcher) should be at the
	// end, otherwise it nullifies any more specific policies
	sort.SliceStable(cps, func(i, j int) bool {
		return cps[j].MatchersRaw == nil && cps[i].MatchersRaw != nil
	})

	for i := 0; i < len(cps); i++ {
		// compare it to the others
		for j := 0; j < len(cps); j++ {
			if j == i {
				continue
			}

			// if they're exactly equal in every way, just keep one of them
			if reflect.DeepEqual(cps[i], cps[j]) {
				cps = append(cps[:j], cps[j+1:]...)
				i--
				break
			}

			// if they have the same matcher, try to reconcile each field: either they must
			// be identical, or we have to be able to combine them safely
			if reflect.DeepEqual(cps[i].MatchersRaw, cps[j].MatchersRaw) {
				if len(cps[i].ALPN) > 0 &&
					len(cps[j].ALPN) > 0 &&
					!reflect.DeepEqual(cps[i].ALPN, cps[j].ALPN) {
					return nil, fmt.Errorf("two policies with same match criteria have conflicting ALPN: %v vs. %v",
						cps[i].ALPN, cps[j].ALPN)
				}
				if len(cps[i].CipherSuites) > 0 &&
					len(cps[j].CipherSuites) > 0 &&
					!reflect.DeepEqual(cps[i].CipherSuites, cps[j].CipherSuites) {
					return nil, fmt.Errorf("two policies with same match criteria have conflicting cipher suites: %v vs. %v",
						cps[i].CipherSuites, cps[j].CipherSuites)
				}
				if cps[i].ClientAuthentication == nil &&
					cps[j].ClientAuthentication != nil &&
					!reflect.DeepEqual(cps[i].ClientAuthentication, cps[j].ClientAuthentication) {
					return nil, fmt.Errorf("two policies with same match criteria have conflicting client auth configuration: %+v vs. %+v",
						cps[i].ClientAuthentication, cps[j].ClientAuthentication)
				}
				if len(cps[i].Curves) > 0 &&
					len(cps[j].Curves) > 0 &&
					!reflect.DeepEqual(cps[i].Curves, cps[j].Curves) {
					return nil, fmt.Errorf("two policies with same match criteria have conflicting curves: %v vs. %v",
						cps[i].Curves, cps[j].Curves)
				}
				if cps[i].DefaultSNI != "" &&
					cps[j].DefaultSNI != "" &&
					cps[i].DefaultSNI != cps[j].DefaultSNI {
					return nil, fmt.Errorf("two policies with same match criteria have conflicting default SNI: %s vs. %s",
						cps[i].DefaultSNI, cps[j].DefaultSNI)
				}
				if cps[i].ProtocolMin != "" &&
					cps[j].ProtocolMin != "" &&
					cps[i].ProtocolMin != cps[j].ProtocolMin {
					return nil, fmt.Errorf("two policies with same match criteria have conflicting min protocol: %s vs. %s",
						cps[i].ProtocolMin, cps[j].ProtocolMin)
				}
				if cps[i].ProtocolMax != "" &&
					cps[j].ProtocolMax != "" &&
					cps[i].ProtocolMax != cps[j].ProtocolMax {
					return nil, fmt.Errorf("two policies with same match criteria have conflicting max protocol: %s vs. %s",
						cps[i].ProtocolMax, cps[j].ProtocolMax)
				}
				if cps[i].CertSelection != nil && cps[j].CertSelection != nil {
					// merging fields other than AnyTag is not implemented
					if !reflect.DeepEqual(cps[i].CertSelection.SerialNumber, cps[j].CertSelection.SerialNumber) ||
						!reflect.DeepEqual(cps[i].CertSelection.SubjectOrganization, cps[j].CertSelection.SubjectOrganization) ||
						cps[i].CertSelection.PublicKeyAlgorithm != cps[j].CertSelection.PublicKeyAlgorithm ||
						!reflect.DeepEqual(cps[i].CertSelection.AllTags, cps[j].CertSelection.AllTags) {
						return nil, fmt.Errorf("two policies with same match criteria have conflicting cert selections: %+v vs. %+v",
							cps[i].CertSelection, cps[j].CertSelection)
					}
				}

				// by now we've decided that we can merge the two -- we'll keep i and drop j

				if len(cps[i].ALPN) == 0 && len(cps[j].ALPN) > 0 {
					cps[i].ALPN = cps[j].ALPN
				}
				if len(cps[i].CipherSuites) == 0 && len(cps[j].CipherSuites) > 0 {
					cps[i].CipherSuites = cps[j].CipherSuites
				}
				if cps[i].ClientAuthentication == nil && cps[j].ClientAuthentication != nil {
					cps[i].ClientAuthentication = cps[j].ClientAuthentication
				}
				if len(cps[i].Curves) == 0 && len(cps[j].Curves) > 0 {
					cps[i].Curves = cps[j].Curves
				}
				if cps[i].DefaultSNI == "" && cps[j].DefaultSNI != "" {
					cps[i].DefaultSNI = cps[j].DefaultSNI
				}
				if cps[i].ProtocolMin == "" && cps[j].ProtocolMin != "" {
					cps[i].ProtocolMin = cps[j].ProtocolMin
				}
				if cps[i].ProtocolMax == "" && cps[j].ProtocolMax != "" {
					cps[i].ProtocolMax = cps[j].ProtocolMax
				}

				if cps[i].CertSelection == nil && cps[j].CertSelection != nil {
					// if j is the only one with a policy, move it over to i
					cps[i].CertSelection = cps[j].CertSelection
				} else if cps[i].CertSelection != nil && cps[j].CertSelection != nil {
					// if both have one, then combine AnyTag
					for _, tag := range cps[j].CertSelection.AnyTag {
						if !sliceContains(cps[i].CertSelection.AnyTag, tag) {
							cps[i].CertSelection.AnyTag = append(cps[i].CertSelection.AnyTag, tag)
						}
					}
				}

				cps = append(cps[:j], cps[j+1:]...)
				i--
				break
			}
		}
	}
	return cps, nil
}

// appendSubrouteToRouteList appends the routes in subroute
// to the routeList, optionally qualified by matchers.
func appendSubrouteToRouteList(routeList caddyhttp.RouteList,
	subroute *caddyhttp.Subroute,
	matcherSetsEnc []caddy.ModuleMap,
	p sbAddrAssociation,
	warnings *[]caddyconfig.Warning) caddyhttp.RouteList {

	// nothing to do if... there's nothing to do
	if len(matcherSetsEnc) == 0 && len(subroute.Routes) == 0 && subroute.Errors == nil {
		return routeList
	}

	if len(matcherSetsEnc) == 0 && len(p.serverBlocks) == 1 {
		// no need to wrap the handlers in a subroute if this is
		// the only server block and there is no matcher for it
		routeList = append(routeList, subroute.Routes...)
	} else {
		route := caddyhttp.Route{
			// the semantics of a site block in the Caddyfile dictate
			// that only the first matching one is evaluated, since
			// site blocks do not cascade nor inherit
			Terminal: true,
		}
		if len(matcherSetsEnc) > 0 {
			route.MatcherSetsRaw = matcherSetsEnc
		}
		if len(subroute.Routes) > 0 || subroute.Errors != nil {
			route.HandlersRaw = []json.RawMessage{
				caddyconfig.JSONModuleObject(subroute, "handler", "subroute", warnings),
			}
		}
		if len(route.MatcherSetsRaw) > 0 || len(route.HandlersRaw) > 0 {
			routeList = append(routeList, route)
		}
	}
	return routeList
}

// buildSubroute turns the config values, which are expected to be routes
// into a clean and orderly subroute that has all the routes within it.
func buildSubroute(routes []ConfigValue, groupCounter counter) (*caddyhttp.Subroute, error) {
	for _, val := range routes {
		if !directiveIsOrdered(val.directive) {
			return nil, fmt.Errorf("directive '%s' is not ordered, so it cannot be used here", val.directive)
		}
	}

	sortRoutes(routes)

	subroute := new(caddyhttp.Subroute)

	// some directives are mutually exclusive (only first matching
	// instance should be evaluated); this is done by putting their
	// routes in the same group
	mutuallyExclusiveDirs := map[string]*struct {
		count     int
		groupName string
	}{
		// as a special case, group rewrite directives so that they are mutually exclusive;
		// this means that only the first matching rewrite will be evaluated, and that's
		// probably a good thing, since there should never be a need to do more than one
		// rewrite (I think?), and cascading rewrites smell bad... imagine these rewrites:
		//     rewrite /docs/json/* /docs/json/index.html
		//     rewrite /docs/*      /docs/index.html
		// (We use this on the Caddy website, or at least we did once.) The first rewrite's
		// result is also matched by the second rewrite, making the first rewrite pointless.
		// See issue #2959.
		"rewrite": {},

		// handle blocks are also mutually exclusive by definition
		"handle": {},

		// root just sets a variable, so if it was not mutually exclusive, intersecting
		// root directives would overwrite previously-matched ones; they should not cascade
		"root": {},
	}

	// we need to deterministically loop over each of these directives
	// in order to keep the group numbers consistent
	keys := make([]string, 0, len(mutuallyExclusiveDirs))
	for k := range mutuallyExclusiveDirs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, meDir := range keys {
		info := mutuallyExclusiveDirs[meDir]

		// see how many instances of the directive there are
		for _, r := range routes {
			if r.directive == meDir {
				info.count++
				if info.count > 1 {
					break
				}
			}
		}
		// if there is more than one, put them in a group
		// (special case: "rewrite" directive must always be in
		// its own group--even if there is only one--because we
		// do not want a rewrite to be consolidated into other
		// adjacent routes that happen to have the same matcher,
		// see caddyserver/caddy#3108 - because the implied
		// intent of rewrite is to do an internal redirect,
		// we can't assume that the request will continue to
		// match the same matcher; anyway, giving a route a
		// unique group name should keep it from consolidating)
		if info.count > 1 || meDir == "rewrite" {
			info.groupName = groupCounter.nextGroup()
		}
	}

	// add all the routes piled in from directives
	for _, r := range routes {
		// put this route into a group if it is mutually exclusive
		if info, ok := mutuallyExclusiveDirs[r.directive]; ok {
			route := r.Value.(caddyhttp.Route)
			route.Group = info.groupName
			r.Value = route
		}

		switch route := r.Value.(type) {
		case caddyhttp.Subroute:
			// if a route-class config value is actually a Subroute handler
			// with nothing but a list of routes, then it is the intention
			// of the directive to keep these handlers together and in this
			// same order, but not necessarily in a subroute (if it wanted
			// to keep them in a subroute, the directive would have returned
			// a route with a Subroute as its handler); this is useful to
			// keep multiple handlers/routes together and in the same order
			// so that the sorting procedure we did above doesn't reorder them
			if route.Errors != nil {
				// if error handlers are also set, this is confusing; it's
				// probably supposed to be wrapped in a Route and encoded
				// as a regular handler route... programmer error.
				panic("found subroute with more than just routes; perhaps it should have been wrapped in a route?")
			}
			subroute.Routes = append(subroute.Routes, route.Routes...)
		case caddyhttp.Route:
			subroute.Routes = append(subroute.Routes, route)
		}
	}

	subroute.Routes = consolidateRoutes(subroute.Routes)

	return subroute, nil
}

// consolidateRoutes combines routes with the same properties
// (same matchers, same Terminal and Group settings) for a
// cleaner overall output.
func consolidateRoutes(routes caddyhttp.RouteList) caddyhttp.RouteList {
	for i := 0; i < len(routes)-1; i++ {
		if reflect.DeepEqual(routes[i].MatcherSetsRaw, routes[i+1].MatcherSetsRaw) &&
			routes[i].Terminal == routes[i+1].Terminal &&
			routes[i].Group == routes[i+1].Group {
			// keep the handlers in the same order, then splice out repetitive route
			routes[i].HandlersRaw = append(routes[i].HandlersRaw, routes[i+1].HandlersRaw...)
			routes = append(routes[:i+1], routes[i+2:]...)
			i--
		}
	}
	return routes
}

func matcherSetFromMatcherToken(
	tkn caddyfile.Token,
	matcherDefs map[string]caddy.ModuleMap,
	warnings *[]caddyconfig.Warning,
) (caddy.ModuleMap, bool, error) {
	// matcher tokens can be wildcards, simple path matchers,
	// or refer to a pre-defined matcher by some name
	if tkn.Text == "*" {
		// match all requests == no matchers, so nothing to do
		return nil, true, nil
	} else if strings.HasPrefix(tkn.Text, "/") {
		// convenient way to specify a single path match
		return caddy.ModuleMap{
			"path": caddyconfig.JSON(caddyhttp.MatchPath{tkn.Text}, warnings),
		}, true, nil
	} else if strings.HasPrefix(tkn.Text, matcherPrefix) {
		// pre-defined matcher
		m, ok := matcherDefs[tkn.Text]
		if !ok {
			return nil, false, fmt.Errorf("unrecognized matcher name: %+v", tkn.Text)
		}
		return m, true, nil
	}
	return nil, false, nil
}

func (st *ServerType) compileEncodedMatcherSets(sblock serverBlock) ([]caddy.ModuleMap, error) {
	type hostPathPair struct {
		hostm caddyhttp.MatchHost
		pathm caddyhttp.MatchPath
	}

	// keep routes with common host and path matchers together
	var matcherPairs []*hostPathPair

	var catchAllHosts bool
	for _, addr := range sblock.keys {
		// choose a matcher pair that should be shared by this
		// server block; if none exists yet, create one
		var chosenMatcherPair *hostPathPair
		for _, mp := range matcherPairs {
			if (len(mp.pathm) == 0 && addr.Path == "") ||
				(len(mp.pathm) == 1 && mp.pathm[0] == addr.Path) {
				chosenMatcherPair = mp
				break
			}
		}
		if chosenMatcherPair == nil {
			chosenMatcherPair = new(hostPathPair)
			if addr.Path != "" {
				chosenMatcherPair.pathm = []string{addr.Path}
			}
			matcherPairs = append(matcherPairs, chosenMatcherPair)
		}

		// if one of the keys has no host (i.e. is a catch-all for
		// any hostname), then we need to null out the host matcher
		// entirely so that it matches all hosts
		if addr.Host == "" && !catchAllHosts {
			chosenMatcherPair.hostm = nil
			catchAllHosts = true
		}
		if catchAllHosts {
			continue
		}

		// add this server block's keys to the matcher
		// pair if it doesn't already exist
		if addr.Host != "" {
			var found bool
			for _, h := range chosenMatcherPair.hostm {
				if h == addr.Host {
					found = true
					break
				}
			}
			if !found {
				chosenMatcherPair.hostm = append(chosenMatcherPair.hostm, addr.Host)
			}
		}
	}

	// iterate each pairing of host and path matchers and
	// put them into a map for JSON encoding
	var matcherSets []map[string]caddyhttp.RequestMatcher
	for _, mp := range matcherPairs {
		matcherSet := make(map[string]caddyhttp.RequestMatcher)
		if len(mp.hostm) > 0 {
			matcherSet["host"] = mp.hostm
		}
		if len(mp.pathm) > 0 {
			matcherSet["path"] = mp.pathm
		}
		if len(matcherSet) > 0 {
			matcherSets = append(matcherSets, matcherSet)
		}
	}

	// finally, encode each of the matcher sets
	matcherSetsEnc := make([]caddy.ModuleMap, 0, len(matcherSets))
	for _, ms := range matcherSets {
		msEncoded, err := encodeMatcherSet(ms)
		if err != nil {
			return nil, fmt.Errorf("server block %v: %v", sblock.block.Keys, err)
		}
		matcherSetsEnc = append(matcherSetsEnc, msEncoded)
	}

	return matcherSetsEnc, nil
}

func parseMatcherDefinitions(d *caddyfile.Dispenser, matchers map[string]caddy.ModuleMap) error {
	for d.Next() {
		definitionName := d.Val()

		if _, ok := matchers[definitionName]; ok {
			return fmt.Errorf("matcher is defined more than once: %s", definitionName)
		}
		matchers[definitionName] = make(caddy.ModuleMap)

		// in case there are multiple instances of the same matcher, concatenate
		// their tokens (we expect that UnmarshalCaddyfile should be able to
		// handle more than one segment); otherwise, we'd overwrite other
		// instances of the matcher in this set
		tokensByMatcherName := make(map[string][]caddyfile.Token)
		for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
			matcherName := d.Val()
			tokensByMatcherName[matcherName] = append(tokensByMatcherName[matcherName], d.NextSegment()...)
		}
		for matcherName, tokens := range tokensByMatcherName {
			mod, err := caddy.GetModule("http.matchers." + matcherName)
			if err != nil {
				return fmt.Errorf("getting matcher module '%s': %v", matcherName, err)
			}
			unm, ok := mod.New().(caddyfile.Unmarshaler)
			if !ok {
				return fmt.Errorf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
			}
			err = unm.UnmarshalCaddyfile(caddyfile.NewDispenser(tokens))
			if err != nil {
				return err
			}
			rm, ok := unm.(caddyhttp.RequestMatcher)
			if !ok {
				return fmt.Errorf("matcher module '%s' is not a request matcher", matcherName)
			}
			matchers[definitionName][matcherName] = caddyconfig.JSON(rm, nil)
		}
	}
	return nil
}

func encodeMatcherSet(matchers map[string]caddyhttp.RequestMatcher) (caddy.ModuleMap, error) {
	msEncoded := make(caddy.ModuleMap)
	for matcherName, val := range matchers {
		jsonBytes, err := json.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("marshaling matcher set %#v: %v", matchers, err)
		}
		msEncoded[matcherName] = jsonBytes
	}
	return msEncoded, nil
}

// tryInt tries to convert val to an integer. If it fails,
// it downgrades the error to a warning and returns 0.
func tryInt(val interface{}, warnings *[]caddyconfig.Warning) int {
	intVal, ok := val.(int)
	if val != nil && !ok && warnings != nil {
		*warnings = append(*warnings, caddyconfig.Warning{Message: "not an integer type"})
	}
	return intVal
}

func tryString(val interface{}, warnings *[]caddyconfig.Warning) string {
	stringVal, ok := val.(string)
	if val != nil && !ok && warnings != nil {
		*warnings = append(*warnings, caddyconfig.Warning{Message: "not a string type"})
	}
	return stringVal
}

func tryDuration(val interface{}, warnings *[]caddyconfig.Warning) caddy.Duration {
	durationVal, ok := val.(caddy.Duration)
	if val != nil && !ok && warnings != nil {
		*warnings = append(*warnings, caddyconfig.Warning{Message: "not a duration type"})
	}
	return durationVal
}

// sliceContains returns true if needle is in haystack.
func sliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// listenersUseAnyPortOtherThan returns true if there are any
// listeners in addresses that use a port which is not otherPort.
// Mostly borrowed from unexported method in caddyhttp package.
func listenersUseAnyPortOtherThan(addresses []string, otherPort string) bool {
	otherPortInt, err := strconv.Atoi(otherPort)
	if err != nil {
		return false
	}
	for _, lnAddr := range addresses {
		laddrs, err := caddy.ParseNetworkAddress(lnAddr)
		if err != nil {
			continue
		}
		if uint(otherPortInt) > laddrs.EndPort || uint(otherPortInt) < laddrs.StartPort {
			return true
		}
	}
	return false
}

// specificity returns len(s) minus any wildcards (*) and
// placeholders ({...}). Basically, it's a length count
// that penalizes the use of wildcards and placeholders.
// This is useful for comparing hostnames and paths.
// However, wildcards in paths are not a sure answer to
// the question of specificity. For example,
// '*.example.com' is clearly less specific than
// 'a.example.com', but is '/a' more or less specific
// than '/a*'?
func specificity(s string) int {
	l := len(s) - strings.Count(s, "*")
	for len(s) > 0 {
		start := strings.Index(s, "{")
		if start < 0 {
			return l
		}
		end := strings.Index(s[start:], "}") + start + 1
		if end <= start {
			return l
		}
		l -= end - start
		s = s[end:]
	}
	return l
}

type counter struct {
	n *int
}

func (c counter) nextGroup() string {
	name := fmt.Sprintf("group%d", *c.n)
	*c.n++
	return name
}

type namedCustomLog struct {
	name string
	log  *caddy.CustomLog
}

// sbAddrAssociation is a mapping from a list of
// addresses to a list of server blocks that are
// served on those addresses.
type sbAddrAssociation struct {
	addresses    []string
	serverBlocks []serverBlock
}

const matcherPrefix = "@"

// Interface guard
var _ caddyfile.ServerType = (*ServerType)(nil)
