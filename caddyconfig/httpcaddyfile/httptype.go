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
			case "handler_order":
				val, err = parseOptHandlerOrder(disp)
			case "experimental_http3":
				val, err = parseOptExperimentalHTTP3(disp)
			case "storage":
				val, err = parseOptStorage(disp)
			case "acme_ca":
				val, err = parseOptACMECA(disp)
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
			"{uri}", "{http.request.uri}",
			"{path}", "{http.request.uri.path}",
			"{host}", "{http.request.host}",
			"{hostport}", "{http.request.hostport}",
			"{method}", "{http.request.method}",
			"{scheme}", "{http.request.scheme}",
			"{file}", "{http.request.uri.path.file}",
			"{dir}", "{http.request.uri.path.dir}",
			"{query}", "{http.request.uri.query_string}",
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
		d := sb.block.DispenseDirective("matcher")
		matcherDefs, err := parseMatcherDefinitions(d)
		if err != nil {
			return nil, warnings, err
		}

		for _, segment := range sb.block.Segments {
			dir := segment.Directive()
			if dir == "matcher" {
				// TODO: This is a special case because we pre-processed it; handle this better
				continue
			}
			if dirFunc, ok := registeredDirectives[dir]; ok {
				results, err := dirFunc(Helper{
					Dispenser:   caddyfile.NewDispenser(segment),
					options:     options,
					warnings:    &warnings,
					matcherDefs: matcherDefs,
					parentBlock: sb.block,
				})
				if err != nil {
					return nil, warnings, fmt.Errorf("parsing caddyfile tokens for '%s': %v", dir, err)
				}
				for _, result := range results {
					result.directive = dir
					sb.pile[result.Class] = append(sb.pile[result.Class], result)
				}
			} else {
				tkn := segment[0]
				return nil, warnings, fmt.Errorf("%s:%d: unrecognized directive: %s", tkn.File, tkn.Line, dir)
			}
		}
	}

	// map
	sbmap, err := st.mapAddressToServerBlocks(serverBlocks)
	if err != nil {
		return nil, warnings, err
	}

	// reduce
	pairings := st.consolidateAddrMappings(sbmap)

	// each pairing of listener addresses to list of server
	// blocks is basically a server definition
	servers, err := st.serversFromPairings(pairings, options, &warnings)
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
	// if global ACME CA or email were set, append a catch-all automation
	// policy that ensures they will be used if no tls directive was used
	acmeCA, hasACMECA := options["acme_ca"]
	email, hasEmail := options["email"]
	if hasACMECA || hasEmail {
		if tlsApp.Automation == nil {
			tlsApp.Automation = new(caddytls.AutomationConfig)
		}
		if !hasACMECA {
			acmeCA = ""
		}
		if !hasEmail {
			email = ""
		}
		tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, caddytls.AutomationPolicy{
			ManagementRaw: caddyconfig.JSONModuleObject(caddytls.ACMEManagerMaker{
				CA:    acmeCA.(string),
				Email: email.(string),
			}, "module", "acme", &warnings),
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
) (map[string]*caddyhttp.Server, error) {
	servers := make(map[string]*caddyhttp.Server)

	for i, p := range pairings {
		srv := &caddyhttp.Server{
			Listen: p.addresses,
		}

		for _, sblock := range p.serverBlocks {
			matcherSetsEnc, err := st.compileEncodedMatcherSets(sblock.block)
			if err != nil {
				return nil, fmt.Errorf("server block %v: compiling matcher sets: %v", sblock.block.Keys, err)
			}

			// if there are user-defined variables, then siteVarSubroute will
			// wrap the handlerSubroute; otherwise handlerSubroute will be the
			// site's primary subroute.
			siteVarSubroute, handlerSubroute := new(caddyhttp.Subroute), new(caddyhttp.Subroute)

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
				for _, cpVal := range cpVals {
					cp := cpVal.Value.(*caddytls.ConnectionPolicy)
					// only create if there is a non-empty policy
					if !reflect.DeepEqual(cp, new(caddytls.ConnectionPolicy)) {
						// make sure the policy covers all hostnames from the block
						hosts, err := st.hostsFromServerBlockKeys(sblock.block)
						if err != nil {
							return nil, err
						}

						// TODO: are matchers needed if every hostname of the config is matched?
						cp.MatchersRaw = caddy.ModuleMap{
							"sni": caddyconfig.JSON(hosts, warnings), // make sure to match all hosts, not just auto-HTTPS-qualified ones
						}
						srv.TLSConnPolicies = append(srv.TLSConnPolicies, cp)
					}
				}
				// TODO: consolidate equal conn policies
			}

			// vars: special routes that will have to wrap the normal handlers
			// so that these variables can be used across their matchers too
			for _, cfgVal := range sblock.pile["var"] {
				siteVarSubroute.Routes = append(siteVarSubroute.Routes, cfgVal.Value.(caddyhttp.Route))
			}

			// set up each handler directive - the order of the handlers
			// as they are added to the routes depends on user preference
			dirRoutes := sblock.pile["route"]
			handlerOrder, ok := options["handler_order"].([]string)
			if !ok {
				handlerOrder = defaultDirectiveOrder
			}
			if len(handlerOrder) == 1 && handlerOrder[0] == "appearance" {
				handlerOrder = nil
			}
			if handlerOrder != nil {
				dirPositions := make(map[string]int)
				for i, dir := range handlerOrder {
					dirPositions[dir] = i
				}
				sort.SliceStable(dirRoutes, func(i, j int) bool {
					iDir, jDir := dirRoutes[i].directive, dirRoutes[j].directive
					return dirPositions[iDir] < dirPositions[jDir]
				})
			}
			for _, r := range dirRoutes {
				handlerSubroute.Routes = append(handlerSubroute.Routes, r.Value.(caddyhttp.Route))
			}

			// the route that contains the site's handlers will
			// be assumed to be the sub-route for this site...
			siteSubroute := handlerSubroute

			// ... unless, of course, there are variables that might
			// be used by the site's matchers or handlers, in which
			// case we need to nest the handlers in a sub-sub-route,
			// and the variables go in the sub-route so the variables
			// get evaluated first
			if len(siteVarSubroute.Routes) > 0 {
				subSubRoute := caddyhttp.Subroute{Routes: siteSubroute.Routes}
				siteSubroute.Routes = append(
					siteVarSubroute.Routes,
					caddyhttp.Route{
						HandlersRaw: []json.RawMessage{
							caddyconfig.JSONModuleObject(subSubRoute, "handler", "subroute", warnings),
						},
					},
				)
			}

			siteSubroute.Routes = consolidateRoutes(siteSubroute.Routes)

			srv.Routes = append(srv.Routes, caddyhttp.Route{
				MatcherSetsRaw: matcherSetsEnc,
				HandlersRaw: []json.RawMessage{
					caddyconfig.JSONModuleObject(siteSubroute, "handler", "subroute", warnings),
				},
			})
		}

		srv.Routes = consolidateRoutes(srv.Routes)

		servers[fmt.Sprintf("srv%d", i)] = srv
	}

	return servers, nil
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
			if reflect.DeepEqual(aps[i].ManagementRaw, aps[j].ManagementRaw) {
				aps[i].Hosts = append(aps[i].Hosts, aps[j].Hosts...)
				aps = append(aps[:j], aps[j+1:]...)
				i--
				break
			}
		}
	}
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
	} else if strings.HasPrefix(tkn.Text, "/") || strings.HasPrefix(tkn.Text, "=/") {
		// convenient way to specify a single path match
		return caddy.ModuleMap{
			"path": caddyconfig.JSON(caddyhttp.MatchPath{tkn.Text}, warnings),
		}, true, nil
	} else if strings.HasPrefix(tkn.Text, "match:") {
		// pre-defined matcher
		matcherName := strings.TrimPrefix(tkn.Text, "match:")
		m, ok := matcherDefs[matcherName]
		if !ok {
			return nil, false, fmt.Errorf("unrecognized matcher name: %+v", matcherName)
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

func parseMatcherDefinitions(d *caddyfile.Dispenser) (map[string]caddy.ModuleMap, error) {
	matchers := make(map[string]caddy.ModuleMap)
	for d.Next() {
		definitionName := d.Val()
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			matcherName := d.Val()
			mod, err := caddy.GetModule("http.matchers." + matcherName)
			if err != nil {
				return nil, fmt.Errorf("getting matcher module '%s': %v", matcherName, err)
			}
			unm, ok := mod.New().(caddyfile.Unmarshaler)
			if !ok {
				return nil, fmt.Errorf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
			}
			err = unm.UnmarshalCaddyfile(d.NewFromNextTokens())
			if err != nil {
				return nil, err
			}
			rm, ok := unm.(caddyhttp.RequestMatcher)
			if !ok {
				return nil, fmt.Errorf("matcher module '%s' is not a request matcher", matcherName)
			}
			if _, ok := matchers[definitionName]; !ok {
				matchers[definitionName] = make(caddy.ModuleMap)
			}
			matchers[definitionName][matcherName] = caddyconfig.JSON(rm, nil)
		}
	}
	return matchers, nil
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

// Interface guard
var _ caddyfile.ServerType = (*ServerType)(nil)
