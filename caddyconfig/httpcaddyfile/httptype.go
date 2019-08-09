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
	"strconv"
	"strings"

	"github.com/mholt/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddyconfig.RegisterAdapter("caddyfile", caddyfile.Adapter{ServerType: ServerType{}})
}

// ServerType can set up a config from an HTTP Caddyfile.
type ServerType struct {
}

// ValidDirectives returns the list of known directives.
func (ServerType) ValidDirectives() []string {
	dirs := []string{"matcher", "root", "tls", "redir"} // TODO: put special-case (hard-coded, or non-handler) directives here
	for _, mod := range caddy.GetModules("http.handlers") {
		if _, ok := mod.New().(HandlerDirective); ok {
			dirs = append(dirs, mod.ID())
		}
	}
	return dirs
}

// Setup makes a config from the tokens.
func (st ServerType) Setup(originalServerBlocks []caddyfile.ServerBlock,
	options map[string]string) (*caddy.Config, []caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning

	// map
	sbmap, err := st.mapAddressToServerBlocks(originalServerBlocks)
	if err != nil {
		return nil, warnings, err
	}

	// reduce
	pairings := st.consolidateAddrMappings(sbmap)

	// each pairing of listener addresses to list of server
	// blocks is basically a server definition
	servers, err := st.serversFromPairings(pairings, &warnings)
	if err != nil {
		return nil, warnings, err
	}

	// now that each server is configured, make the HTTP app
	httpApp := caddyhttp.App{
		HTTPPort:  tryInt(options["http-port"], &warnings),
		HTTPSPort: tryInt(options["https-port"], &warnings),
		Servers:   servers,
	}

	// now for the TLS app! (TODO: refactor into own func)
	tlsApp := caddytls.TLS{Certificates: make(map[string]json.RawMessage)}
	for _, p := range pairings {
		for _, sblock := range p.serverBlocks {
			if tkns, ok := sblock.Tokens["tls"]; ok {
				// extract all unique hostnames from the server block
				// keys, then convert to a slice for use in the TLS app
				hostMap := make(map[string]struct{})
				for _, sblockKey := range sblock.Keys {
					addr, err := standardizeAddress(sblockKey)
					if err != nil {
						return nil, warnings, fmt.Errorf("parsing server block key: %v", err)
					}
					hostMap[addr.Host] = struct{}{}
				}
				sblockHosts := make([]string, 0, len(hostMap))
				for host := range hostMap {
					sblockHosts = append(sblockHosts, host)
				}

				// parse tokens to get ACME manager config
				acmeMgr, err := st.parseTLSAutomationManager(caddyfile.NewDispenser("Caddyfile", tkns))
				if err != nil {
					return nil, warnings, err
				}

				tlsApp.Automation.Policies = append(tlsApp.Automation.Policies, caddytls.AutomationPolicy{
					Hosts:         sblockHosts,
					ManagementRaw: caddyconfig.JSONModuleObject(acmeMgr, "module", "acme", &warnings),
				})

				// parse tokens to get certificates to be loaded manually
				certLoaders, err := st.parseTLSCerts(caddyfile.NewDispenser("Caddyfile", tkns))
				if err != nil {
					return nil, nil, err
				}
				for loaderName, loader := range certLoaders {
					tlsApp.Certificates[loaderName] = caddyconfig.JSON(loader, &warnings)
				}

			}
		}
	}

	// annnd the top-level config, then we're done!
	cfg := &caddy.Config{AppsRaw: make(map[string]json.RawMessage)}
	if !reflect.DeepEqual(httpApp, caddyhttp.App{}) {
		cfg.AppsRaw["http"] = caddyconfig.JSON(httpApp, &warnings)
	}
	if !reflect.DeepEqual(tlsApp, caddytls.TLS{}) {
		cfg.AppsRaw["tls"] = caddyconfig.JSON(tlsApp, &warnings)
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
		addr, err := standardizeAddress(sblockKey)
		if err != nil {
			return nil, fmt.Errorf("parsing server block key: %v", err)
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
func (st *ServerType) serversFromPairings(pairings []sbAddrAssociation, warnings *[]caddyconfig.Warning) (map[string]*caddyhttp.Server, error) {
	servers := make(map[string]*caddyhttp.Server)

	for i, p := range pairings {
		srv := &caddyhttp.Server{
			Listen: p.addresses,
		}

		for _, sblock := range p.serverBlocks {
			matcherSetsEnc, err := st.compileEncodedMatcherSets(sblock)
			if err != nil {
				return nil, fmt.Errorf("server block %v: compiling matcher sets: %v", sblock.Keys, err)
			}

			// extract matcher definitions
			d := caddyfile.NewDispenser("Caddyfile", sblock.Tokens["matcher"])
			matcherDefs, err := st.parseMatcherDefinitions(d)
			if err != nil {
				return nil, err
			}

			siteVarSubroute, handlerSubroute := new(caddyhttp.Subroute), new(caddyhttp.Subroute)

			// built-in directives

			// root: path to root of site
			if tkns, ok := sblock.Tokens["root"]; ok {
				routes, err := st.parseRoot(tkns, matcherDefs, warnings)
				if err != nil {
					return nil, err
				}
				siteVarSubroute.Routes = append(siteVarSubroute.Routes, routes...)
			}

			// tls: off and conn policies
			if tkns, ok := sblock.Tokens["tls"]; ok {
				// get the hosts for this server block...
				hosts, err := st.hostsFromServerBlockKeys(sblock)
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

				if len(tkns) == 2 && tkns[1].Text == "off" {
					// tls off: disable TLS (and automatic HTTPS) for server block's names
					if srv.AutoHTTPS == nil {
						srv.AutoHTTPS = new(caddyhttp.AutoHTTPSConfig)
					}
					srv.AutoHTTPS.Skip = append(srv.AutoHTTPS.Skip, autoHTTPSQualifiedHosts...)
				} else {
					// tls connection policies
					cp, err := st.parseTLSConnPolicy(caddyfile.NewDispenser("Caddyfile", tkns))
					if err != nil {
						return nil, err
					}
					// TODO: are matchers needed if every hostname of the config is matched?
					cp.Matchers = map[string]json.RawMessage{
						"sni": caddyconfig.JSON(hosts, warnings), // make sure to match all hosts, not just auto-HTTPS-qualified ones
					}
					srv.TLSConnPolicies = append(srv.TLSConnPolicies, cp)
				}
			}

			// set up each handler directive
			for _, dirBucket := range directiveBuckets() {
				for dir := range dirBucket {
					// keep in mind that multiple occurrences of the directive may appear here
					tkns, ok := sblock.Tokens[dir]
					if !ok {
						continue
					}

					// extract matcher sets from matcher tokens, if any
					matcherSetsMap, err := st.tokensToMatcherSets(tkns, matcherDefs, warnings)

					mod, err := caddy.GetModule("http.handlers." + dir)
					if err != nil {
						return nil, fmt.Errorf("getting handler module '%s': %v", mod.Name, err)
					}

					// the tokens have been divided by matcher set for us,
					// so iterate each one and set them up
					for _, mst := range matcherSetsMap {
						unm, ok := mod.New().(caddyfile.Unmarshaler)
						if !ok {
							return nil, fmt.Errorf("handler module '%s' is not a Caddyfile unmarshaler", mod.Name)
						}
						err = unm.UnmarshalCaddyfile(caddyfile.NewDispenser(d.File(), mst.tokens))
						if err != nil {
							return nil, err
						}
						handler, ok := unm.(caddyhttp.MiddlewareHandler)
						if !ok {
							return nil, fmt.Errorf("handler module '%s' does not implement caddyhttp.MiddlewareHandler interface", mod.Name)
						}

						route := caddyhttp.Route{
							Handle: []json.RawMessage{
								caddyconfig.JSONModuleObject(handler, "handler", dir, warnings),
							},
						}
						if mst.matcherSet != nil {
							route.MatcherSets = []map[string]json.RawMessage{mst.matcherSet}
						}
						handlerSubroute.Routes = append(handlerSubroute.Routes, route)
					}

				}
			}

			// redir: static responses that redirect
			if tkns, ok := sblock.Tokens["redir"]; ok {
				routes, err := st.parseRedir(tkns, matcherDefs, warnings)
				if err != nil {
					return nil, err
				}
				handlerSubroute.Routes = append(handlerSubroute.Routes, routes...)
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
						Handle: []json.RawMessage{
							caddyconfig.JSONModuleObject(subSubRoute, "handler", "subroute", warnings),
						},
					},
				)
			}

			siteSubroute.Routes = consolidateRoutes(siteSubroute.Routes)

			srv.Routes = append(srv.Routes, caddyhttp.Route{
				MatcherSets: matcherSetsEnc,
				Handle: []json.RawMessage{
					caddyconfig.JSONModuleObject(siteSubroute, "handler", "subroute", warnings),
				},
			})
		}

		srv.Routes = consolidateRoutes(srv.Routes)

		servers[fmt.Sprintf("srv%d", i)] = srv
	}

	return servers, nil
}

// consolidateRoutes combines routes with the same properties
// (same matchers, same Terminal and Group settings) for a
// cleaner overall output.
func consolidateRoutes(routes caddyhttp.RouteList) caddyhttp.RouteList {
	for i := 0; i < len(routes)-1; i++ {
		if reflect.DeepEqual(routes[i].MatcherSets, routes[i+1].MatcherSets) &&
			routes[i].Terminal == routes[i+1].Terminal &&
			routes[i].Group == routes[i+1].Group {
			// keep the handlers in the same order, then splice out repetitive route
			routes[i].Handle = append(routes[i].Handle, routes[i+1].Handle...)
			routes = append(routes[:i+1], routes[i+2:]...)
			i--
		}
	}
	return routes
}

func (st *ServerType) tokensToMatcherSets(
	tkns []caddyfile.Token,
	matcherDefs map[string]map[string]json.RawMessage,
	warnings *[]caddyconfig.Warning,
) (map[string]matcherSetAndTokens, error) {
	m := make(map[string]matcherSetAndTokens)

	for len(tkns) > 0 {
		d := caddyfile.NewDispenser("Caddyfile", tkns)
		d.Next() // consume directive token

		// look for matcher; it should be the next argument
		var matcherToken caddyfile.Token
		var matcherSet map[string]json.RawMessage
		if d.NextArg() {
			var ok bool
			var err error
			matcherSet, ok, err = st.matcherSetFromMatcherToken(d.Token(), matcherDefs, warnings)
			if err != nil {
				return nil, err
			}
			if ok {
				// found a matcher; save it, then splice it out
				// since we don't want to parse it again
				matcherToken = d.Token()
				tkns = d.Delete()
			}
			d.RemainingArgs() // advance to end of line
		}
		for d.NextBlock() {
			// skip entire block including any nested blocks; all
			// we care about is accessing next directive occurrence
			for d.Nested() {
				d.NextBlock()
			}
		}
		end := d.Cursor() + 1
		m[matcherToken.Text] = matcherSetAndTokens{
			matcherSet: matcherSet,
			tokens:     append(m[matcherToken.Text].tokens, tkns[:end]...),
		}
		tkns = tkns[end:]
	}
	return m, nil
}

func (st *ServerType) matcherSetFromMatcherToken(
	tkn caddyfile.Token,
	matcherDefs map[string]map[string]json.RawMessage,
	warnings *[]caddyconfig.Warning,
) (map[string]json.RawMessage, bool, error) {
	// matcher tokens can be wildcards, simple path matchers,
	// or refer to a pre-defined matcher by some name
	if tkn.Text == "*" {
		// match all requests == no matchers, so nothing to do
		return nil, true, nil
	} else if strings.HasPrefix(tkn.Text, "/") {
		// convenient way to specify a single path match
		return map[string]json.RawMessage{
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

func (st *ServerType) compileEncodedMatcherSets(sblock caddyfile.ServerBlock) ([]map[string]json.RawMessage, error) {
	type hostPathPair struct {
		hostm caddyhttp.MatchHost
		pathm caddyhttp.MatchPath
	}

	// keep routes with common host and path matchers together
	var matcherPairs []*hostPathPair

	for _, key := range sblock.Keys {
		addr, err := standardizeAddress(key)
		if err != nil {
			return nil, fmt.Errorf("server block %v: parsing and standardizing address '%s': %v", sblock.Keys, key, err)
		}

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
	var matcherSetsEnc []map[string]json.RawMessage
	for _, ms := range matcherSets {
		msEncoded, err := encodeMatcherSet(ms)
		if err != nil {
			return nil, fmt.Errorf("server block %v: %v", sblock.Keys, err)
		}
		matcherSetsEnc = append(matcherSetsEnc, msEncoded)
	}

	return matcherSetsEnc, nil
}

func encodeMatcherSet(matchers map[string]caddyhttp.RequestMatcher) (map[string]json.RawMessage, error) {
	msEncoded := make(map[string]json.RawMessage)
	for matcherName, val := range matchers {
		jsonBytes, err := json.Marshal(val)
		if err != nil {
			return nil, fmt.Errorf("marshaling matcher set %#v: %v", matchers, err)
		}
		msEncoded[matcherName] = jsonBytes
	}
	return msEncoded, nil
}

// HandlerDirective implements a directive for an HTTP handler,
// in that it can unmarshal its own configuration from Caddyfile
// tokens and also specify which directive bucket it belongs in.
type HandlerDirective interface {
	caddyfile.Unmarshaler
	Bucket() int
}

// tryInt tries to convert str to an integer. If it fails, it downgrades
// the error to a warning and returns 0.
func tryInt(str string, warnings *[]caddyconfig.Warning) int {
	if str == "" {
		return 0
	}
	val, err := strconv.Atoi(str)
	if err != nil && warnings != nil {
		*warnings = append(*warnings, caddyconfig.Warning{Message: err.Error()})
	}
	return val
}

type matcherSetAndTokens struct {
	matcherSet map[string]json.RawMessage
	tokens     []caddyfile.Token
}

// sbAddrAssocation is a mapping from a list of
// addresses to a list of server blocks that are
// served on those addresses.
type sbAddrAssociation struct {
	addresses    []string
	serverBlocks []caddyfile.ServerBlock
}

// Interface guard
var _ caddyfile.ServerType = (*ServerType)(nil)
