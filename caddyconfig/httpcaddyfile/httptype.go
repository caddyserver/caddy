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
	"reflect"
	"sort"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/mholt/certmagic"
)

func init() {
	caddyconfig.RegisterAdapter("caddyfile", caddyfile.Adapter{ServerType: ServerType{}})
}

// ServerType can set up a config from an HTTP Caddyfile.
type ServerType struct {
}

// Setup makes a config from the tokens.
func (st ServerType) Setup(originalServerBlocks []caddyfile.ServerBlock,
	options map[string]interface{}) (*caddy.Config, []caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning
	gc := counter{new(int)}

	var serverBlocks []serverBlock
	for _, sblock := range originalServerBlocks {
		serverBlocks = append(serverBlocks, serverBlock{
			block: sblock,
			pile:  make(map[string][]ConfigValue),
		})
	}

	// global configuration
	if len(serverBlocks) > 0 && len(serverBlocks[0].block.Keys) == 0 {
		sb := serverBlocks[0]
		for _, segment := range sb.block.Segments {
			dir := segment.Directive()
			var val interface{}
			var err error
			disp := caddyfile.NewDispenser(segment)
			// TODO: make this switch into a map
			switch dir {
			case "http_port":
				val, err = parseOptHTTPPort(disp)
			case "https_port":
				val, err = parseOptHTTPSPort(disp)
			case "order":
				val, err = parseOptOrder(disp)
			case "experimental_http3":
				val, err = parseOptExperimentalHTTP3(disp)
			case "storage":
				val, err = parseOptStorage(disp)
			case "acme_ca", "acme_dns":
				val, err = parseOptACME(disp)
			case "email":
				val, err = parseOptEmail(disp)
			case "admin":
				val, err = parseOptAdmin(disp)
			default:
				return nil, warnings, fmt.Errorf("unrecognized parameter name: %s", dir)
			}
			if err != nil {
				return nil, warnings, fmt.Errorf("%s: %v", dir, err)
			}
			options[dir] = val
		}
		serverBlocks = serverBlocks[1:]
	}

	for _, sb := range serverBlocks {
		// replace shorthand placeholders (which are
		// convenient when writing a Caddyfile) with
		// their actual placeholder identifiers or
		// variable names
		replacer := strings.NewReplacer(
			"{dir}", "{http.request.uri.path.dir}",
			"{file}", "{http.request.uri.path.file}",
			"{host}", "{http.request.host}",
			"{hostport}", "{http.request.hostport}",
			"{method}", "{http.request.method}",
			"{path}", "{http.request.uri.path}",
			"{query}", "{http.request.uri.query}",
			"{remote_host}", "{http.request.remote.host}",
			"{remote_port}", "{http.request.remote.port}",
			"{remote}", "{http.request.remote}",
			"{scheme}", "{http.request.scheme}",
			"{uri}", "{http.request.uri}",
		)
		for _, segment := range sb.block.Segments {
			for i := 0; i < len(segment); i++ {
				segment[i].Text = replacer.Replace(segment[i].Text)
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

			results, err := dirFunc(Helper{
				Dispenser:    caddyfile.NewDispenser(segment),
				options:      options,
				warnings:     &warnings,
				matcherDefs:  matcherDefs,
				parentBlock:  sb.block,
				groupCounter: gc,
			})
			if err != nil {
				return nil, warnings, fmt.Errorf("parsing caddyfile tokens for '%s': %v", dir, err)
			}
			for _, result := range results {
				result.directive = dir
				sb.pile[result.Class] = append(sb.pile[result.Class], result)
			}
		}
	}

	// map
	sbmap, err := st.mapAddressToServerBlocks(serverBlocks, options)
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
		HTTPPort:  tryInt(options["http_port"], &warnings),
		HTTPSPort: tryInt(options["https_port"], &warnings),
		Servers:   servers,
	}

	// now for the TLS app! (TODO: refactor into own func)
	tlsApp := caddytls.TLS{CertificatesRaw: make(caddy.ModuleMap)}
	for _, p := range pairings {
		for i, sblock := range p.serverBlocks {
			// tls automation policies
			if mmVals, ok := sblock.pile["tls.automation_manager"]; ok {
				for _, mmVal := range mmVals {
					mm := mmVal.Value.(caddytls.ManagerMaker)
					sblockHosts, err := st.autoHTTPSHosts(sblock)
					if err != nil {
						return nil, warnings, err
					}
					if len(sblockHosts) > 0 {
						if tlsApp.Automation == nil {
							tlsApp.Automation = new(caddytls.AutomationConfig)
						}
						tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, caddytls.AutomationPolicy{
							Hosts:         sblockHosts,
							ManagementRaw: caddyconfig.JSONModuleObject(mm, "module", mm.(caddy.Module).CaddyModule().ID.Name(), &warnings),
						})
					} else {
						warnings = append(warnings, caddyconfig.Warning{
							Message: fmt.Sprintf("Server block %d %v has no names that qualify for automatic HTTPS, so no TLS automation policy will be added.", i, sblock.block.Keys),
						})
					}
				}
			}

			// tls certificate loaders
			if clVals, ok := sblock.pile["tls.certificate_loader"]; ok {
				for _, clVal := range clVals {
					loader := clVal.Value.(caddytls.CertificateLoader)
					loaderName := caddy.GetModuleName(loader)
					tlsApp.CertificatesRaw[loaderName] = caddyconfig.JSON(loader, &warnings)
				}
			}
		}
	}
	// if global ACME CA, DNS, or email were set, append a catch-all automation
	// policy that ensures they will be used if no tls directive was used
	acmeCA, hasACMECA := options["acme_ca"]
	acmeDNS, hasACMEDNS := options["acme_dns"]
	email, hasEmail := options["email"]
	if hasACMECA || hasACMEDNS || hasEmail {
		if tlsApp.Automation == nil {
			tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		if !hasACMECA {
			acmeCA = ""
		}
		if !hasEmail {
			email = ""
		}
		mgr := caddytls.ACMEManagerMaker{
			CA:    acmeCA.(string),
			Email: email.(string),
		}
		if hasACMEDNS {
			provName := acmeDNS.(string)
			dnsProvModule, err := caddy.GetModule("tls.dns." + provName)
			if err != nil {
				return nil, warnings, fmt.Errorf("getting DNS provider module named '%s': %v", provName, err)
			}
			mgr.Challenges = &caddytls.ChallengesConfig{
				DNSRaw: caddyconfig.JSONModuleObject(dnsProvModule.New(), "provider", provName, &warnings),
			}
		}
		tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, caddytls.AutomationPolicy{
			ManagementRaw: caddyconfig.JSONModuleObject(mgr, "module", "acme", &warnings),
		})
	}
	if tlsApp.Automation != nil {
		// consolidate automation policies that are the exact same
		tlsApp.Automation.Policies = consolidateAutomationPolicies(tlsApp.Automation.Policies)
	}

	// if experimental HTTP/3 is enabled, enable it on each server
	if enableH3, ok := options["experimental_http3"].(bool); ok && enableH3 {
		for _, srv := range httpApp.Servers {
			srv.ExperimentalHTTP3 = true
		}
	}

	// annnd the top-level config, then we're done!
	cfg := &caddy.Config{AppsRaw: make(caddy.ModuleMap)}
	if !reflect.DeepEqual(httpApp, caddyhttp.App{}) {
		cfg.AppsRaw["http"] = caddyconfig.JSON(httpApp, &warnings)
	}
	if !reflect.DeepEqual(tlsApp, caddytls.TLS{CertificatesRaw: make(caddy.ModuleMap)}) {
		cfg.AppsRaw["tls"] = caddyconfig.JSON(tlsApp, &warnings)
	}
	if storageCvtr, ok := options["storage"].(caddy.StorageConverter); ok {
		cfg.StorageRaw = caddyconfig.JSONModuleObject(storageCvtr,
			"module",
			storageCvtr.(caddy.Module).CaddyModule().ID.Name(),
			&warnings)
	}
	if adminConfig, ok := options["admin"].(string); ok && adminConfig != "" {
		cfg.Admin = &caddy.AdminConfig{Listen: adminConfig}
	}

	return cfg, warnings, nil
}

// hostsFromServerBlockKeys returns a list of all the
// hostnames found in the keys of the server block sb.
// The list may not be in a consistent order.
func (st *ServerType) hostsFromServerBlockKeys(sb caddyfile.ServerBlock) ([]string, error) {
	// first get each unique hostname
	hostMap := make(map[string]struct{})
	for _, sblockKey := range sb.Keys {
		addr, err := ParseAddress(sblockKey)
		if err != nil {
			return nil, fmt.Errorf("parsing server block key: %v", err)
		}
		addr = addr.Normalize()
		if addr.Host == "" {
			continue
		}
		hostMap[addr.Host] = struct{}{}
	}

	// convert map to slice
	sblockHosts := make([]string, 0, len(hostMap))
	for host := range hostMap {
		sblockHosts = append(sblockHosts, host)
	}

	return sblockHosts, nil
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

	for i, p := range pairings {
		srv := &caddyhttp.Server{
			Listen: p.addresses,
		}

		// sort server blocks by their keys; this is important because
		// only the first matching site should be evaluated, and we should
		// attempt to match most specific site first (host and path), in
		// case their matchers overlap; we do this somewhat naively by
		// descending sort by length of host then path
		sort.SliceStable(p.serverBlocks, func(i, j int) bool {
			// TODO: we could pre-process the specificities for efficiency,
			// but I don't expect many blocks will have SO many keys...
			var iLongestPath, jLongestPath string
			var iLongestHost, jLongestHost string
			for _, key := range p.serverBlocks[i].block.Keys {
				addr, _ := ParseAddress(key)
				if specificity(addr.Host) > specificity(iLongestHost) {
					iLongestHost = addr.Host
				}
				if specificity(addr.Path) > specificity(iLongestPath) {
					iLongestPath = addr.Path
				}
			}
			for _, key := range p.serverBlocks[j].block.Keys {
				addr, _ := ParseAddress(key)
				if specificity(addr.Host) > specificity(jLongestHost) {
					jLongestHost = addr.Host
				}
				if specificity(addr.Path) > specificity(jLongestPath) {
					jLongestPath = addr.Path
				}
			}
			if specificity(iLongestHost) == specificity(jLongestHost) {
				return len(iLongestPath) > len(jLongestPath)
			}
			return specificity(iLongestHost) > specificity(jLongestHost)
		})

		// create a subroute for each site in the server block
		for _, sblock := range p.serverBlocks {
			matcherSetsEnc, err := st.compileEncodedMatcherSets(sblock.block)
			if err != nil {
				return nil, fmt.Errorf("server block %v: compiling matcher sets: %v", sblock.block.Keys, err)
			}

			// tls: connection policies and toggle auto HTTPS
			autoHTTPSQualifiedHosts, err := st.autoHTTPSHosts(sblock)
			if err != nil {
				return nil, err
			}
			if _, ok := sblock.pile["tls.off"]; ok && len(autoHTTPSQualifiedHosts) > 0 {
				// tls off: disable TLS (and automatic HTTPS) for server block's names
				if srv.AutoHTTPS == nil {
					srv.AutoHTTPS = new(caddyhttp.AutoHTTPSConfig)
				}
				srv.AutoHTTPS.Skip = append(srv.AutoHTTPS.Skip, autoHTTPSQualifiedHosts...)
			} else if cpVals, ok := sblock.pile["tls.connection_policy"]; ok {
				// tls connection policies
				var hasCatchAll bool
				for _, cpVal := range cpVals {
					cp := cpVal.Value.(*caddytls.ConnectionPolicy)

					// make sure the policy covers all hostnames from the block
					hosts, err := st.hostsFromServerBlockKeys(sblock.block)
					if err != nil {
						return nil, err
					}

					// TODO: are matchers needed if every hostname of the resulting config is matched?
					if len(hosts) > 0 {
						cp.MatchersRaw = caddy.ModuleMap{
							"sni": caddyconfig.JSON(hosts, warnings), // make sure to match all hosts, not just auto-HTTPS-qualified ones
						}
					} else {
						hasCatchAll = true
					}

					srv.TLSConnPolicies = append(srv.TLSConnPolicies, cp)
				}

				// a catch-all is necessary to ensure TLS can be offered to
				// all hostnames of the server; even though only one policy
				// is needed to enable TLS for the server, that policy might
				// apply to only certain TLS handshakes; but when using the
				// Caddyfile, user would expect all handshakes to at least
				// have a matching connection policy, so here we append a
				// catch-all/default policy if there isn't one already (it's
				// important that it goes at the end) - see issue #3004:
				// https://github.com/caddyserver/caddy/issues/3004
				if !hasCatchAll {
					srv.TLSConnPolicies = append(srv.TLSConnPolicies, new(caddytls.ConnectionPolicy))
				}

				// TODO: consolidate equal conn policies
			}

			// exclude any hosts that were defined explicitly with
			// "http://" in the key from automated cert management (issue #2998)
			for _, key := range sblock.block.Keys {
				addr, err := ParseAddress(key)
				if err != nil {
					return nil, err
				}
				addr = addr.Normalize()
				if addr.Scheme == "http" {
					if srv.AutoHTTPS == nil {
						srv.AutoHTTPS = new(caddyhttp.AutoHTTPSConfig)
					}
					if !sliceContains(srv.AutoHTTPS.Skip, addr.Host) {
						srv.AutoHTTPS.Skip = append(srv.AutoHTTPS.Skip, addr.Host)
					}
				}
			}

			// set up each handler directive, making sure to honor directive order
			dirRoutes := sblock.pile["route"]
			siteSubroute, err := buildSubroute(dirRoutes, groupCounter)
			if err != nil {
				return nil, err
			}

			if len(matcherSetsEnc) == 0 && len(p.serverBlocks) == 1 {
				// no need to wrap the handlers in a subroute if this is
				// the only server block and there is no matcher for it
				srv.Routes = append(srv.Routes, siteSubroute.Routes...)
			} else {
				srv.Routes = append(srv.Routes, caddyhttp.Route{
					MatcherSetsRaw: matcherSetsEnc,
					HandlersRaw: []json.RawMessage{
						caddyconfig.JSONModuleObject(siteSubroute, "handler", "subroute", warnings),
					},
					Terminal: true, // only first matching site block should be evaluated
				})
			}
		}

		srv.Routes = consolidateRoutes(srv.Routes)

		servers[fmt.Sprintf("srv%d", i)] = srv
	}

	return servers, nil
}

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
	for meDir, info := range mutuallyExclusiveDirs {
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
		if info.count > 1 {
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

func (st ServerType) autoHTTPSHosts(sb serverBlock) ([]string, error) {
	// get the hosts for this server block...
	hosts, err := st.hostsFromServerBlockKeys(sb.block)
	if err != nil {
		return nil, err
	}
	// ...and of those, which ones qualify for auto HTTPS
	var autoHTTPSQualifiedHosts []string
	for _, h := range hosts {
		if certmagic.HostQualifies(h) {
			autoHTTPSQualifiedHosts = append(autoHTTPSQualifiedHosts, h)
		}
	}
	return autoHTTPSQualifiedHosts, nil
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

// consolidateAutomationPolicies combines automation policies that are the same,
// for a cleaner overall output.
func consolidateAutomationPolicies(aps []caddytls.AutomationPolicy) []caddytls.AutomationPolicy {
	for i := 0; i < len(aps); i++ {
		for j := 0; j < len(aps); j++ {
			if j == i {
				continue
			}

			// if they're exactly equal in every way, just keep one of them
			if reflect.DeepEqual(aps[i], aps[j]) {
				aps = append(aps[:j], aps[j+1:]...)
				i--
				break
			}

			// if the policy is the same, we can keep just one, but we have
			// to be careful which one we keep; if only one has any hostnames
			// defined, then we need to keep the one without any hostnames,
			// otherwise the one without any hosts (a catch-all) would be
			// eaten up by the one with hosts; and if both have hosts, we
			// need to combine their lists
			if reflect.DeepEqual(aps[i].ManagementRaw, aps[j].ManagementRaw) &&
				aps[i].ManageSync == aps[j].ManageSync {
				if len(aps[i].Hosts) == 0 && len(aps[j].Hosts) > 0 {
					aps = append(aps[:j], aps[j+1:]...)
				} else if len(aps[i].Hosts) > 0 && len(aps[j].Hosts) == 0 {
					aps = append(aps[:i], aps[i+1:]...)
				} else {
					aps[i].Hosts = append(aps[i].Hosts, aps[j].Hosts...)
					aps = append(aps[:j], aps[j+1:]...)
				}
				i--
				break
			}
		}
	}

	// ensure any catch-all policies go last
	sort.SliceStable(aps, func(i, j int) bool {
		return len(aps[i].Hosts) > len(aps[j].Hosts)
	})

	return aps
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

func (st *ServerType) compileEncodedMatcherSets(sblock caddyfile.ServerBlock) ([]caddy.ModuleMap, error) {
	type hostPathPair struct {
		hostm caddyhttp.MatchHost
		pathm caddyhttp.MatchPath
	}

	// keep routes with common host and path matchers together
	var matcherPairs []*hostPathPair

	for _, key := range sblock.Keys {
		addr, err := ParseAddress(key)
		if err != nil {
			return nil, fmt.Errorf("server block %v: parsing and standardizing address '%s': %v", sblock.Keys, key, err)
		}
		addr = addr.Normalize()

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
	var matcherSetsEnc []caddy.ModuleMap
	for _, ms := range matcherSets {
		msEncoded, err := encodeMatcherSet(ms)
		if err != nil {
			return nil, fmt.Errorf("server block %v: %v", sblock.Keys, err)
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

		for nesting := d.Nesting(); d.NextBlock(nesting); {
			matcherName := d.Val()
			mod, err := caddy.GetModule("http.matchers." + matcherName)
			if err != nil {
				return fmt.Errorf("getting matcher module '%s': %v", matcherName, err)
			}
			unm, ok := mod.New().(caddyfile.Unmarshaler)
			if !ok {
				return fmt.Errorf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
			}
			err = unm.UnmarshalCaddyfile(d.NewFromNextTokens())
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

// sliceContains returns true if needle is in haystack.
func sliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// specifity returns len(s) minus any wildcards (*) and
// placeholders ({...}). Basically, it's a length count
// that penalizes the use of wildcards and placeholders.
// This is useful for comparing hostnames and paths.
// However, wildcards in paths are not a sure answer to
// the question of specificity. For exmaple,
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

type matcherSetAndTokens struct {
	matcherSet caddy.ModuleMap
	tokens     []caddyfile.Token
}

// sbAddrAssocation is a mapping from a list of
// addresses to a list of server blocks that are
// served on those addresses.
type sbAddrAssociation struct {
	addresses    []string
	serverBlocks []serverBlock
}

const matcherPrefix = "@"

// Interface guard
var _ caddyfile.ServerType = (*ServerType)(nil)
