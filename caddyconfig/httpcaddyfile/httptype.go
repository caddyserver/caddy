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
	"cmp"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/configbuilder"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile/blocktypes"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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
type ServerType struct{}

// Setup processes the server blocks from a Caddyfile and builds a complete Caddy configuration.
// It supports explicit [type] syntax with type registry for extensibility, with backwards
// compatibility defaults: first block with no keys is treated as [global], others as [http.server].
func (st ServerType) Setup(
	inputServerBlocks []caddyfile.ServerBlock,
	options map[string]any,
) (*caddy.Config, []caddyconfig.Warning, error) {
	var warnings []caddyconfig.Warning

	// Track block types in order of appearance
	type blockGroup struct {
		blockType string
		blocks    []caddyfile.ServerBlock
	}
	var orderedBlocks []blockGroup
	seenTypes := make(map[string]int) // maps block type to index in orderedBlocks

	for i, sblock := range inputServerBlocks {
		// Extract explicit block type if present
		blockType, err := extractBlockType(&sblock)
		if err != nil {
			return nil, warnings, err
		}

		// Apply caddyfile compatibility defaults
		if blockType == "" {
			// First block with no keys is treated as global config
			if i == 0 && len(sblock.Keys) == 0 {
				blockType = "global"
			} else {
				// Default to http.server for backwards compatibility with Caddyfile
				blockType = "http.server"
			}
		}

		// Add to the appropriate group, preserving order
		if idx, seen := seenTypes[blockType]; seen {
			// Append to existing group
			orderedBlocks[idx].blocks = append(orderedBlocks[idx].blocks, sblock)
		} else {
			// Create new group
			seenTypes[blockType] = len(orderedBlocks)
			orderedBlocks = append(orderedBlocks, blockGroup{
				blockType: blockType,
				blocks:    []caddyfile.ServerBlock{sblock},
			})
		}
	}

	// Create the config builder
	builder := configbuilder.New()

	// Process block types in the order they appear, but ensure parent blocks
	// are processed before their children
	processed := make(map[string]bool)

	var processBlock func(blockType string) error
	processBlock = func(blockType string) error {
		if processed[blockType] {
			return nil
		}

		// Get block type info to check for parent
		info, ok := blocktypes.GetBlockTypeInfo(blockType)
		if !ok {
			available := blocktypes.RegisteredBlockTypes()
			return fmt.Errorf("block type '%s' is not registered; available types: %v", blockType, available)
		}

		// Process parent first if it exists
		if info.Parent != "" {
			if err := processBlock(info.Parent); err != nil {
				return err
			}
		}

		// Find and process this block type's blocks
		for _, group := range orderedBlocks {
			if group.blockType == blockType {
				blockWarnings, err := info.SetupFunc(builder, group.blocks, options)
				warnings = append(warnings, blockWarnings...)
				processed[blockType] = true
				if err != nil {
					return fmt.Errorf("processing [%s] blocks: %w", blockType, err)
				}
				break
			}
		}

		return nil
	}

	// Process each block type
	for _, group := range orderedBlocks {
		if err := processBlock(group.blockType); err != nil {
			return nil, warnings, err
		}
	}

	// Apply global options from the options map to the builder
	// This mirrors what httpcaddyfile does at the end of Setup()
	if err := applyGlobalOptions(builder, options, &warnings); err != nil {
		return nil, warnings, err
	}

	// Get the config - this finalizes structured apps
	cfg := builder.Config()

	// Process logs after all apps are finalized so we can collect server-specific logs
	if err := processLogs(cfg, options, &warnings); err != nil {
		return nil, warnings, err
	}

	return cfg, warnings, nil
}

// ServerBlockPairings represents the association between listen addresses
// and server blocks. This is needed for building TLS and PKI apps.
type ServerBlockPairings []sbAddrAssociation

// BuildServersAndPairings processes server blocks and creates servers from pairings.
// This is the core reusable primitive for building servers that is used by both
// httpcaddyfile and xcaddyfile. It processes directives, creates pairings,
// and builds servers without constructing the full HTTP app or processing
// global options. It returns the servers map, pairings, hoisted metrics,
// warnings, and any error.
//
// The caller is responsible for extracting/loading server blocks and for
// constructing the HTTP app from the returned servers.
func BuildServersAndPairings(originalServerBlocks []ServerBlock, options map[string]any, warnings []caddyconfig.Warning) (map[string]*caddyhttp.Server, ServerBlockPairings, *caddyhttp.Metrics, []caddyconfig.Warning, error) {
	st := ServerType{}
	gc := counter{new(int)}
	state := make(map[string]any)

	// this will replace both static and user-defined placeholder shorthands
	// with actual identifiers used by Caddy
	replacer := NewShorthandReplacer()

	originalServerBlocks, err := st.extractNamedRoutes(originalServerBlocks, options, &warnings, replacer)
	if err != nil {
		return nil, nil, nil, warnings, err
	}

	for _, sb := range originalServerBlocks {
		for i := range sb.Block.Segments {
			replacer.ApplyToSegment(&sb.Block.Segments[i])
		}

		if len(sb.Block.Keys) == 0 {
			return nil, nil, nil, warnings, fmt.Errorf("server block without any key is global configuration, and if used, it must be first")
		}

		// extract matcher definitions
		matcherDefs := make(map[string]caddy.ModuleMap)
		for _, segment := range sb.Block.Segments {
			if dir := segment.Directive(); strings.HasPrefix(dir, matcherPrefix) {
				d := sb.Block.DispenseDirective(dir)
				err := parseMatcherDefinitions(d, matcherDefs)
				if err != nil {
					return nil, nil, nil, warnings, err
				}
			}
		}

		// evaluate each directive ("segment") in this block
		for _, segment := range sb.Block.Segments {
			dir := segment.Directive()

			if strings.HasPrefix(dir, matcherPrefix) {
				// matcher definitions were pre-processed
				continue
			}

			dirFunc, ok := registeredDirectives[dir]
			if !ok {
				tkn := segment[0]
				message := "%s:%d: unrecognized directive: %s"
				if !sb.Block.HasBraces {
					message += "\nDid you mean to define a second site? If so, you must use curly braces around each site to separate their configurations."
				}
				return nil, nil, nil, warnings, fmt.Errorf(message, tkn.File, tkn.Line, dir)
			}

			h := Helper{
				Dispenser:    caddyfile.NewDispenser(segment),
				options:      options,
				warnings:     &warnings,
				matcherDefs:  matcherDefs,
				parentBlock:  sb.Block,
				groupCounter: gc,
				State:        state,
			}

			results, err := dirFunc(h)
			if err != nil {
				return nil, nil, nil, warnings, fmt.Errorf("parsing caddyfile tokens for '%s': %v", dir, err)
			}

			dir = normalizeDirectiveName(dir)

			for _, result := range results {
				result.directive = dir
				sb.Pile[result.Class] = append(sb.Pile[result.Class], result)
			}

			// specially handle named routes that were pulled out from
			// the invoke directive, which could be nested anywhere within
			// some subroutes in this directive; we add them to the pile
			// for this server block
			if state[namedRouteKey] != nil {
				for name := range state[namedRouteKey].(map[string]struct{}) {
					result := ConfigValue{Class: namedRouteKey, Value: name}
					sb.Pile[result.Class] = append(sb.Pile[result.Class], result)
				}
				state[namedRouteKey] = nil
			}
		}
	}

	// map
	sbmap, err := st.mapAddressToProtocolToServerBlocks(originalServerBlocks, options)
	if err != nil {
		return nil, nil, nil, warnings, err
	}

	// reduce
	pairings := st.consolidateAddrMappings(sbmap)

	// each pairing of listener addresses to list of server
	// blocks is basically a server definition
	servers, err := st.serversFromPairings(pairings, options, &warnings, gc)
	if err != nil {
		return nil, nil, nil, warnings, err
	}

	// hoist the metrics config from per-server to global
	metrics, _ := options["metrics"].(*caddyhttp.Metrics)
	for _, s := range servers {
		if s.Metrics != nil {
			metrics = cmp.Or(metrics, &caddyhttp.Metrics{})
			metrics = &caddyhttp.Metrics{
				PerHost: metrics.PerHost || s.Metrics.PerHost,
			}
			s.Metrics = nil // we don't need it anymore
		}
	}

	return servers, pairings, metrics, warnings, nil
}

// EvaluateGlobalOptions processes global option directives from the given segments
// and stores the parsed values in the options map. This is the core reusable logic
// for parsing global options that can be used by both httpcaddyfile and xcaddyfile.
func EvaluateGlobalOptions(segments []caddyfile.Segment, options map[string]any) error {
	for _, segment := range segments {
		opt := segment.Directive()
		var val any
		var err error
		disp := caddyfile.NewDispenser(segment)

		optFunc, ok := registeredGlobalOptions[opt]
		if !ok {
			tkn := segment[0]
			return fmt.Errorf("%s:%d: unrecognized global option: %s", tkn.File, tkn.Line, opt)
		}

		val, err = optFunc(disp, options[opt])
		if err != nil {
			return fmt.Errorf("parsing caddyfile tokens for '%s': %v", opt, err)
		}

		// As a special case, fold multiple "servers" options together
		// in an array instead of overwriting a possible existing value
		if opt == "servers" {
			existingOpts, ok := options[opt].([]ServerOptions)
			if !ok {
				existingOpts = []ServerOptions{}
			}
			serverOpts, ok := val.(ServerOptions)
			if !ok {
				return fmt.Errorf("unexpected type from 'servers' global options: %T", val)
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
				return fmt.Errorf("unexpected type from 'log' global options: %T", val)
			}
			options[opt] = append(existingOpts, logOpts...)
			continue
		}
		// Also fold multiple "default_bind" options together into an
		// array so that server blocks can have multiple binds by default.
		if opt == "default_bind" {
			existingOpts, ok := options[opt].([]ConfigValue)
			if !ok {
				existingOpts = []ConfigValue{}
			}
			defaultBindOpts, ok := val.([]ConfigValue)
			if !ok {
				return fmt.Errorf("unexpected type from 'default_bind' global options: %T", val)
			}
			options[opt] = append(existingOpts, defaultBindOpts...)
			continue
		}

		options[opt] = val
	}

	// If we got "servers" options, we'll sort them by their listener address
	if serverOpts, ok := options["servers"].([]ServerOptions); ok {
		sort.Slice(serverOpts, func(i, j int) bool {
			return len(serverOpts[i].ListenerAddress) > len(serverOpts[j].ListenerAddress)
		})

		// Reject the config if there are duplicate listener address
		seen := make(map[string]bool)
		for _, entry := range serverOpts {
			if _, alreadySeen := seen[entry.ListenerAddress]; alreadySeen {
				return fmt.Errorf("cannot have 'servers' global options with duplicate listener addresses: %s", entry.ListenerAddress)
			}
			seen[entry.ListenerAddress] = true
		}
	}

	return nil
}

// extractNamedRoutes pulls out any named route server blocks
// so they don't get parsed as sites, and stores them in options
// for later.
func (ServerType) extractNamedRoutes(
	serverBlocks []ServerBlock,
	options map[string]any,
	warnings *[]caddyconfig.Warning,
	replacer ShorthandReplacer,
) ([]ServerBlock, error) {
	namedRoutes := map[string]*caddyhttp.Route{}

	gc := counter{new(int)}
	state := make(map[string]any)

	// copy the server blocks so we can
	// splice out the named route ones
	filtered := append([]ServerBlock{}, serverBlocks...)
	index := -1

	for _, sb := range serverBlocks {
		index++
		if !sb.Block.IsNamedRoute {
			continue
		}

		// splice out this block, because we know it's not a real server
		filtered = append(filtered[:index], filtered[index+1:]...)
		index--

		if len(sb.Block.Segments) == 0 {
			continue
		}

		wholeSegment := caddyfile.Segment{}
		for i := range sb.Block.Segments {
			// replace user-defined placeholder shorthands in extracted named routes
			replacer.ApplyToSegment(&sb.Block.Segments[i])

			// zip up all the segments since ParseSegmentAsSubroute
			// was designed to take a directive+
			wholeSegment = append(wholeSegment, sb.Block.Segments[i]...)
		}

		h := Helper{
			Dispenser:    caddyfile.NewDispenser(wholeSegment),
			options:      options,
			warnings:     warnings,
			matcherDefs:  nil,
			parentBlock:  sb.Block,
			groupCounter: gc,
			State:        state,
		}

		handler, err := ParseSegmentAsSubroute(h)
		if err != nil {
			return nil, err
		}
		subroute := handler.(*caddyhttp.Subroute)
		route := caddyhttp.Route{}

		if len(subroute.Routes) == 1 && len(subroute.Routes[0].MatcherSetsRaw) == 0 {
			// if there's only one route with no matcher, then we can simplify
			route.HandlersRaw = append(route.HandlersRaw, subroute.Routes[0].HandlersRaw[0])
		} else {
			// otherwise we need the whole subroute
			route.HandlersRaw = []json.RawMessage{caddyconfig.JSONModuleObject(handler, "handler", subroute.CaddyModule().ID.Name(), h.warnings)}
		}

		namedRoutes[sb.Block.GetKeysText()[0]] = &route
	}
	options["named_routes"] = namedRoutes

	return filtered, nil
}

// serversFromPairings creates the servers for each pairing of addresses
// to server blocks. Each pairing is essentially a server definition.
func (st *ServerType) serversFromPairings(
	pairings []sbAddrAssociation,
	options map[string]any,
	warnings *[]caddyconfig.Warning,
	groupCounter counter,
) (map[string]*caddyhttp.Server, error) {
	servers := make(map[string]*caddyhttp.Server)
	defaultSNI := tryString(options["default_sni"], warnings)
	fallbackSNI := tryString(options["fallback_sni"], warnings)

	httpPort := strconv.Itoa(caddyhttp.DefaultHTTPPort)
	if hp, ok := options["http_port"].(int); ok {
		httpPort = strconv.Itoa(hp)
	}
	httpsPort := strconv.Itoa(caddyhttp.DefaultHTTPSPort)
	if hsp, ok := options["https_port"].(int); ok {
		httpsPort = strconv.Itoa(hsp)
	}
	autoHTTPS := []string{}
	if ah, ok := options["auto_https"].([]string); ok {
		autoHTTPS = ah
	}

	for i, p := range pairings {
		// detect ambiguous site definitions: server blocks which
		// have the same host bound to the same interface (listener
		// address), otherwise their routes will improperly be added
		// to the same server (see issue #4635)
		for j, sblock1 := range p.serverBlocks {
			for _, key := range sblock1.Block.GetKeysText() {
				for k, sblock2 := range p.serverBlocks {
					if k == j {
						continue
					}
					if slices.Contains(sblock2.Block.GetKeysText(), key) {
						return nil, fmt.Errorf("ambiguous site definition: %s", key)
					}
				}
			}
		}

		var (
			addresses []string
			protocols [][]string
		)

		for _, addressWithProtocols := range p.addressesWithProtocols {
			addresses = append(addresses, addressWithProtocols.address)
			protocols = append(protocols, addressWithProtocols.protocols)
		}

		srv := &caddyhttp.Server{
			Listen:          addresses,
			ListenProtocols: protocols,
		}

		// remove srv.ListenProtocols[j] if it only contains the default protocols
		for j, lnProtocols := range srv.ListenProtocols {
			srv.ListenProtocols[j] = nil
			for _, lnProtocol := range lnProtocols {
				if lnProtocol != "" {
					srv.ListenProtocols[j] = lnProtocols
					break
				}
			}
		}

		// remove srv.ListenProtocols if it only contains the default protocols for all listen addresses
		listenProtocols := srv.ListenProtocols
		srv.ListenProtocols = nil
		for _, lnProtocols := range listenProtocols {
			if lnProtocols != nil {
				srv.ListenProtocols = listenProtocols
				break
			}
		}

		// handle the auto_https global option
		for _, val := range autoHTTPS {
			switch val {
			case "off":
				if srv.AutoHTTPS == nil {
					srv.AutoHTTPS = new(caddyhttp.AutoHTTPSConfig)
				}
				srv.AutoHTTPS.Disabled = true

			case "disable_redirects":
				if srv.AutoHTTPS == nil {
					srv.AutoHTTPS = new(caddyhttp.AutoHTTPSConfig)
				}
				srv.AutoHTTPS.DisableRedir = true

			case "disable_certs":
				if srv.AutoHTTPS == nil {
					srv.AutoHTTPS = new(caddyhttp.AutoHTTPSConfig)
				}
				srv.AutoHTTPS.DisableCerts = true

			case "ignore_loaded_certs":
				if srv.AutoHTTPS == nil {
					srv.AutoHTTPS = new(caddyhttp.AutoHTTPSConfig)
				}
				srv.AutoHTTPS.IgnoreLoadedCerts = true
			}
		}

		// Using paths in site addresses is deprecated
		// See ParseAddress() where parsing should later reject paths
		// See https://github.com/caddyserver/caddy/pull/4728 for a full explanation
		for _, sblock := range p.serverBlocks {
			for _, addr := range sblock.ParsedKeys {
				if addr.Path != "" {
					caddy.Log().Named("caddyfile").Warn("Using a path in a site address is deprecated; please use the 'handle' directive instead", zap.String("address", addr.String()))
				}
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
			for _, addr := range p.serverBlocks[i].ParsedKeys {
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
			for _, addr := range p.serverBlocks[j].ParsedKeys {
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
		autoHTTPSWillAddConnPolicy := srv.AutoHTTPS == nil || !srv.AutoHTTPS.Disabled

		// if needed, the ServerLogConfig is initialized beforehand so
		// that all server blocks can populate it with data, even when not
		// coming with a log directive
		for _, sblock := range p.serverBlocks {
			if len(sblock.Pile["custom_log"]) != 0 {
				srv.Logs = new(caddyhttp.ServerLogConfig)
				break
			}
		}

		// add named routes to the server if 'invoke' was used inside of it
		configuredNamedRoutes := options["named_routes"].(map[string]*caddyhttp.Route)
		for _, sblock := range p.serverBlocks {
			if len(sblock.Pile[namedRouteKey]) == 0 {
				continue
			}
			for _, value := range sblock.Pile[namedRouteKey] {
				if srv.NamedRoutes == nil {
					srv.NamedRoutes = map[string]*caddyhttp.Route{}
				}
				name := value.Value.(string)
				if configuredNamedRoutes[name] == nil {
					return nil, fmt.Errorf("cannot invoke named route '%s', which was not defined", name)
				}
				srv.NamedRoutes[name] = configuredNamedRoutes[name]
			}
		}

		// create a subroute for each site in the server block
		for _, sblock := range p.serverBlocks {
			matcherSetsEnc, err := st.compileEncodedMatcherSets(sblock)
			if err != nil {
				return nil, fmt.Errorf("server block %v: compiling matcher sets: %v", sblock.Block.Keys, err)
			}

			hosts := sblock.hostsFromKeys(false)

			// emit warnings if user put unspecified IP addresses; they probably want the bind directive
			for _, h := range hosts {
				if h == "0.0.0.0" || h == "::" {
					caddy.Log().Named("caddyfile").Warn("Site block has an unspecified IP address which only matches requests having that Host header; you probably want the 'bind' directive to configure the socket", zap.String("address", h))
				}
			}

			// collect hosts that are forced to be automated
			forceAutomatedNames := make(map[string]struct{})
			if _, ok := sblock.Pile["tls.force_automate"]; ok {
				for _, host := range hosts {
					forceAutomatedNames[host] = struct{}{}
				}
			}

			// tls: connection policies
			if cpVals, ok := sblock.Pile["tls.connection_policy"]; ok {
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
						if h == fallbackSNI {
							hosts = append(hosts, "")
							cp.FallbackSNI = fallbackSNI
							break
						}
					}

					if len(hosts) > 0 {
						slices.Sort(hosts) // for deterministic JSON output
						cp.MatchersRaw = caddy.ModuleMap{
							"sni": caddyconfig.JSON(hosts, warnings), // make sure to match all hosts, not just auto-HTTPS-qualified ones
						}
					} else {
						cp.DefaultSNI = defaultSNI
						cp.FallbackSNI = fallbackSNI
					}

					// only append this policy if it actually changes something,
					// or if the configuration explicitly automates certs for
					// these names (this is necessary to hoist a connection policy
					// above one that may manually load a wildcard cert that would
					// otherwise clobber the automated one; the code that appends
					// policies that manually load certs comes later, so they're
					// lower in the list)
					if !cp.SettingsEmpty() || mapContains(forceAutomatedNames, hosts) {
						srv.TLSConnPolicies = append(srv.TLSConnPolicies, cp)
						hasCatchAllTLSConnPolicy = len(hosts) == 0
					}
				}
			}

			for _, addr := range sblock.ParsedKeys {
				// if server only uses HTTP port, auto-HTTPS will not apply
				if listenersUseAnyPortOtherThan(srv.Listen, httpPort) {
					// exclude any hosts that were defined explicitly with "http://"
					// in the key from automated cert management (issue #2998)
					if addr.Scheme == "http" && addr.Host != "" {
						if srv.AutoHTTPS == nil {
							srv.AutoHTTPS = new(caddyhttp.AutoHTTPSConfig)
						}
						if !slices.Contains(srv.AutoHTTPS.Skip, addr.Host) {
							srv.AutoHTTPS.Skip = append(srv.AutoHTTPS.Skip, addr.Host)
						}
					}
				}

				// If TLS is specified as directive, it will also result in 1 or more connection policy being created
				// Thus, catch-all address with non-standard port, e.g. :8443, can have TLS enabled without
				// specifying prefix "https://"
				// Second part of the condition is to allow creating TLS conn policy even though `auto_https` has been disabled
				// ensuring compatibility with behavior described in below link
				// https://caddy.community/t/making-sense-of-auto-https-and-why-disabling-it-still-serves-https-instead-of-http/9761
				createdTLSConnPolicies, ok := sblock.Pile["tls.connection_policy"]
				hasTLSEnabled := (ok && len(createdTLSConnPolicies) > 0) ||
					(addr.Host != "" && srv.AutoHTTPS != nil && !slices.Contains(srv.AutoHTTPS.Skip, addr.Host))

				// we'll need to remember if the address qualifies for auto-HTTPS, so we
				// can add a TLS conn policy if necessary
				if addr.Scheme == "https" ||
					(addr.Scheme != "http" && addr.Port != httpPort && hasTLSEnabled) {
					addressQualifiesForTLS = true
				}

				// predict whether auto-HTTPS will add the conn policy for us; if so, we
				// may not need to add one for this server
				autoHTTPSWillAddConnPolicy = autoHTTPSWillAddConnPolicy &&
					(addr.Port == httpsPort || (addr.Port != httpPort && addr.Host != ""))
			}

			// Look for any config values that provide listener wrappers on the server block
			for _, listenerConfig := range sblock.Pile["listener_wrapper"] {
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
			dirRoutes := sblock.Pile["route"]
			siteSubroute, err := buildSubroute(dirRoutes, groupCounter, true)
			if err != nil {
				return nil, err
			}

			// add the site block's route(s) to the server
			srv.Routes = appendSubrouteToRouteList(srv.Routes, siteSubroute, matcherSetsEnc, p, warnings)

			// if error routes are defined, add those too
			if errorSubrouteVals, ok := sblock.Pile["error_route"]; ok {
				if srv.Errors == nil {
					srv.Errors = new(caddyhttp.HTTPErrorConfig)
				}
				sort.SliceStable(errorSubrouteVals, func(i, j int) bool {
					sri, srj := errorSubrouteVals[i].Value.(*caddyhttp.Subroute), errorSubrouteVals[j].Value.(*caddyhttp.Subroute)
					if len(sri.Routes[0].MatcherSetsRaw) == 0 && len(srj.Routes[0].MatcherSetsRaw) != 0 {
						return false
					}
					return true
				})
				errorsSubroute := &caddyhttp.Subroute{}
				for _, val := range errorSubrouteVals {
					sr := val.Value.(*caddyhttp.Subroute)
					errorsSubroute.Routes = append(errorsSubroute.Routes, sr.Routes...)
				}
				srv.Errors.Routes = appendSubrouteToRouteList(srv.Errors.Routes, errorsSubroute, matcherSetsEnc, p, warnings)
			}

			// add log associations
			// see https://github.com/caddyserver/caddy/issues/3310
			sblockLogHosts := sblock.hostsFromKeys(true)
			for _, cval := range sblock.Pile["custom_log"] {
				ncl := cval.Value.(namedCustomLog)

				// if `no_hostname` is set, then this logger will not
				// be associated with any of the site block's hostnames,
				// and only be usable via the `log_name` directive
				// or the `access_logger_names` variable
				if ncl.noHostname {
					continue
				}

				if sblock.hasHostCatchAllKey() && len(ncl.hostnames) == 0 {
					// all requests for hosts not able to be listed should use
					// this log because it's a catch-all-hosts server block
					srv.Logs.DefaultLoggerName = ncl.name
				} else if len(ncl.hostnames) > 0 {
					// if the logger overrides the hostnames, map that to the logger name
					for _, h := range ncl.hostnames {
						if srv.Logs.LoggerNames == nil {
							srv.Logs.LoggerNames = make(map[string]caddyhttp.StringArray)
						}
						srv.Logs.LoggerNames[h] = append(srv.Logs.LoggerNames[h], ncl.name)
					}
				} else {
					// otherwise, map each host to the logger name
					for _, h := range sblockLogHosts {
						// strip the port from the host, if any
						host, _, err := net.SplitHostPort(h)
						if err != nil {
							host = h
						}
						if srv.Logs.LoggerNames == nil {
							srv.Logs.LoggerNames = make(map[string]caddyhttp.StringArray)
						}
						srv.Logs.LoggerNames[host] = append(srv.Logs.LoggerNames[host], ncl.name)
					}
				}
			}
			if srv.Logs != nil && len(sblock.Pile["custom_log"]) == 0 {
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

		// sort for deterministic JSON output
		if srv.Logs != nil {
			slices.Sort(srv.Logs.SkipHosts)
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
			(len(srv.TLSConnPolicies) > 0 || !autoHTTPSWillAddConnPolicy || defaultSNI != "" || fallbackSNI != "") {
			srv.TLSConnPolicies = append(srv.TLSConnPolicies, &caddytls.ConnectionPolicy{
				DefaultSNI:  defaultSNI,
				FallbackSNI: fallbackSNI,
			})
		}

		// tidy things up a bit
		srv.TLSConnPolicies, err = consolidateConnPolicies(srv.TLSConnPolicies)
		if err != nil {
			return nil, fmt.Errorf("consolidating TLS connection policies for server %d: %v", i, err)
		}
		srv.Routes = consolidateRoutes(srv.Routes)

		servers[fmt.Sprintf("srv%d", i)] = srv
	}

	if err := applyServerOptions(servers, options, warnings); err != nil {
		return nil, fmt.Errorf("applying global server options: %v", err)
	}

	return servers, nil
}

func detectConflictingSchemes(srv *caddyhttp.Server, serverBlocks []ServerBlock, options map[string]any) error {
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
		for _, addr := range sblock.ParsedKeys {
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
				cps = slices.Delete(cps, j, j+1)
				i--
				break
			}

			// as a special case, if there are adjacent TLS conn policies that are identical except
			// by their matchers, and the matchers are specifically just ServerName ("sni") matchers
			// (by far the most common), we can combine them into a single policy
			if i == j-1 && len(cps[i].MatchersRaw) == 1 && len(cps[j].MatchersRaw) == 1 {
				if iSNIMatcherJSON, ok := cps[i].MatchersRaw["sni"]; ok {
					if jSNIMatcherJSON, ok := cps[j].MatchersRaw["sni"]; ok {
						// position of policies and the matcher criteria check out; if settings are
						// the same, then we can combine the policies; we have to unmarshal and
						// remarshal the matchers though
						if cps[i].SettingsEqual(*cps[j]) {
							var iSNIMatcher caddytls.MatchServerName
							if err := json.Unmarshal(iSNIMatcherJSON, &iSNIMatcher); err == nil {
								var jSNIMatcher caddytls.MatchServerName
								if err := json.Unmarshal(jSNIMatcherJSON, &jSNIMatcher); err == nil {
									iSNIMatcher = append(iSNIMatcher, jSNIMatcher...)
									cps[i].MatchersRaw["sni"], err = json.Marshal(iSNIMatcher)
									if err != nil {
										return nil, fmt.Errorf("recombining SNI matchers: %v", err)
									}
									cps = slices.Delete(cps, j, j+1)
									i--
									break
								}
							}
						}
					}
				}
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
				if cps[i].FallbackSNI != "" &&
					cps[j].FallbackSNI != "" &&
					cps[i].FallbackSNI != cps[j].FallbackSNI {
					return nil, fmt.Errorf("two policies with same match criteria have conflicting fallback SNI: %s vs. %s",
						cps[i].FallbackSNI, cps[j].FallbackSNI)
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
				if cps[i].FallbackSNI == "" && cps[j].FallbackSNI != "" {
					cps[i].FallbackSNI = cps[j].FallbackSNI
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
						if !slices.Contains(cps[i].CertSelection.AnyTag, tag) {
							cps[i].CertSelection.AnyTag = append(cps[i].CertSelection.AnyTag, tag)
						}
					}
				}

				cps = slices.Delete(cps, j, j+1)
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
	warnings *[]caddyconfig.Warning,
) caddyhttp.RouteList {
	// nothing to do if... there's nothing to do
	if len(matcherSetsEnc) == 0 && len(subroute.Routes) == 0 && subroute.Errors == nil {
		return routeList
	}

	// No need to wrap the handlers in a subroute if this is the only server block
	// and there is no matcher for it (doing so would produce unnecessarily nested
	// JSON), *unless* there is a host matcher within this site block; if so, then
	// we still need to wrap in a subroute because otherwise the host matcher from
	// the inside of the site block would be a top-level host matcher, which is
	// subject to auto-HTTPS (cert management), and using a host matcher within
	// a site block is a valid, common pattern for excluding domains from cert
	// management, leading to unexpected behavior; see issue #5124.
	wrapInSubroute := true
	if len(matcherSetsEnc) == 0 && len(p.serverBlocks) == 1 {
		var hasHostMatcher bool
	outer:
		for _, route := range subroute.Routes {
			for _, ms := range route.MatcherSetsRaw {
				for matcherName := range ms {
					if matcherName == "host" {
						hasHostMatcher = true
						break outer
					}
				}
			}
		}
		wrapInSubroute = hasHostMatcher
	}

	if wrapInSubroute {
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
	} else {
		routeList = append(routeList, subroute.Routes...)
	}

	return routeList
}

// buildSubroute turns the config values, which are expected to be routes
// into a clean and orderly subroute that has all the routes within it.
func buildSubroute(routes []ConfigValue, groupCounter counter, needsSorting bool) (*caddyhttp.Subroute, error) {
	if needsSorting {
		for _, val := range routes {
			if !slices.Contains(directiveOrder, val.directive) {
				return nil, fmt.Errorf("directive '%s' is not an ordered HTTP handler, so it cannot be used here - try placing within a route block or using the order global option", val.directive)
			}
		}

		sortRoutes(routes)
	}

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

// normalizeDirectiveName ensures directives that should be sorted
// at the same level are named the same before sorting happens.
func normalizeDirectiveName(directive string) string {
	// As a special case, we want "handle_path" to be sorted
	// at the same level as "handle", so we force them to use
	// the same directive name after their parsing is complete.
	// See https://github.com/caddyserver/caddy/issues/3675#issuecomment-678042377
	if directive == "handle_path" {
		directive = "handle"
	}
	return directive
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
	}

	// convenient way to specify a single path match
	if strings.HasPrefix(tkn.Text, "/") {
		return caddy.ModuleMap{
			"path": caddyconfig.JSON(caddyhttp.MatchPath{tkn.Text}, warnings),
		}, true, nil
	}

	// pre-defined matcher
	if strings.HasPrefix(tkn.Text, matcherPrefix) {
		m, ok := matcherDefs[tkn.Text]
		if !ok {
			return nil, false, fmt.Errorf("unrecognized matcher name: %+v", tkn.Text)
		}
		return m, true, nil
	}

	return nil, false, nil
}

func (st *ServerType) compileEncodedMatcherSets(sblock ServerBlock) ([]caddy.ModuleMap, error) {
	type hostPathPair struct {
		hostm caddyhttp.MatchHost
		pathm caddyhttp.MatchPath
	}

	// keep routes with common host and path matchers together
	var matcherPairs []*hostPathPair

	var catchAllHosts bool
	for _, addr := range sblock.ParsedKeys {
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
		if addr.Host != "" && !slices.Contains(chosenMatcherPair.hostm, addr.Host) {
			chosenMatcherPair.hostm = append(chosenMatcherPair.hostm, addr.Host)
		}
	}

	// iterate each pairing of host and path matchers and
	// put them into a map for JSON encoding
	var matcherSets []map[string]caddyhttp.RequestMatcherWithError
	for _, mp := range matcherPairs {
		matcherSet := make(map[string]caddyhttp.RequestMatcherWithError)
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
			return nil, fmt.Errorf("server block %v: %v", sblock.Block.Keys, err)
		}
		matcherSetsEnc = append(matcherSetsEnc, msEncoded)
	}

	return matcherSetsEnc, nil
}

func parseMatcherDefinitions(d *caddyfile.Dispenser, matchers map[string]caddy.ModuleMap) error {
	d.Next() // advance to the first token

	// this is the "name" for "named matchers"
	definitionName := d.Val()

	if _, ok := matchers[definitionName]; ok {
		return fmt.Errorf("matcher is defined more than once: %s", definitionName)
	}
	matchers[definitionName] = make(caddy.ModuleMap)

	// given a matcher name and the tokens following it, parse
	// the tokens as a matcher module and record it
	makeMatcher := func(matcherName string, tokens []caddyfile.Token) error {
		// create a new dispenser from the tokens
		dispenser := caddyfile.NewDispenser(tokens)

		// set the matcher name (without @) in the dispenser context so
		// that matcher modules can access it to use it as their name
		// (e.g. regexp matchers which use the name for capture groups)
		dispenser.SetContext(caddyfile.MatcherNameCtxKey, definitionName[1:])

		mod, err := caddy.GetModule("http.matchers." + matcherName)
		if err != nil {
			return fmt.Errorf("getting matcher module '%s': %v", matcherName, err)
		}
		unm, ok := mod.New().(caddyfile.Unmarshaler)
		if !ok {
			return fmt.Errorf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
		}
		err = unm.UnmarshalCaddyfile(dispenser)
		if err != nil {
			return err
		}

		if rm, ok := unm.(caddyhttp.RequestMatcherWithError); ok {
			matchers[definitionName][matcherName] = caddyconfig.JSON(rm, nil)
			return nil
		}
		// nolint:staticcheck
		if rm, ok := unm.(caddyhttp.RequestMatcher); ok {
			matchers[definitionName][matcherName] = caddyconfig.JSON(rm, nil)
			return nil
		}
		return fmt.Errorf("matcher module '%s' is not a request matcher", matcherName)
	}

	// if the next token is quoted, we can assume it's not a matcher name
	// and that it's probably an 'expression' matcher
	if d.NextArg() {
		if d.Token().Quoted() {
			// since it was missing the matcher name, we insert a token
			// in front of the expression token itself; we use Clone() to
			// make the new token to keep the same the import location as
			// the next token, if this is within a snippet or imported file.
			// see https://github.com/caddyserver/caddy/issues/6287
			expressionToken := d.Token().Clone()
			expressionToken.Text = "expression"
			err := makeMatcher("expression", []caddyfile.Token{expressionToken, d.Token()})
			if err != nil {
				return err
			}
			return nil
		}

		// if it wasn't quoted, then we need to rewind after calling
		// d.NextArg() so the below properly grabs the matcher name
		d.Prev()
	}

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
		err := makeMatcher(matcherName, tokens)
		if err != nil {
			return err
		}
	}
	return nil
}

func encodeMatcherSet(matchers map[string]caddyhttp.RequestMatcherWithError) (caddy.ModuleMap, error) {
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

// WasReplacedPlaceholderShorthand checks if a token string was
// likely a replaced shorthand of the known Caddyfile placeholder
// replacement outputs. Useful to prevent some user-defined map
// output destinations from overlapping with one of the
// predefined shorthands.
func WasReplacedPlaceholderShorthand(token string) string {
	prev := ""
	for i, item := range placeholderShorthands() {
		// only look at every 2nd item, which is the replacement
		if i%2 == 0 {
			prev = item
			continue
		}
		if strings.Trim(token, "{}") == strings.Trim(item, "{}") {
			// we return the original shorthand so it
			// can be used for an error message
			return prev
		}
	}
	return ""
}

// DirectiveIsRegistered returns true if the directive name is registered.
// This is exported for use by xcaddyfile.
func DirectiveIsRegistered(name string) bool {
	_, ok := registeredDirectives[name]
	return ok
}

// TryInt tries to convert val to an integer. If it fails,
// it downgrades the error to a warning and returns 0.
func TryInt(val any, warnings *[]caddyconfig.Warning) int {
	intVal, ok := val.(int)
	if val != nil && !ok && warnings != nil {
		*warnings = append(*warnings, caddyconfig.Warning{Message: "not an integer type"})
	}
	return intVal
}

func tryString(val any, warnings *[]caddyconfig.Warning) string {
	stringVal, ok := val.(string)
	if val != nil && !ok && warnings != nil {
		*warnings = append(*warnings, caddyconfig.Warning{Message: "not a string type"})
	}
	return stringVal
}

// TryDuration converts val to a caddy.Duration, adding a warning if conversion fails.
// This is exported for use by xcaddyfile.
func TryDuration(val any, warnings *[]caddyconfig.Warning) caddy.Duration {
	durationVal, ok := val.(caddy.Duration)
	if val != nil && !ok && warnings != nil {
		*warnings = append(*warnings, caddyconfig.Warning{Message: "not a duration type"})
	}
	return durationVal
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

func mapContains[K comparable, V any](m map[K]V, keys []K) bool {
	if len(m) == 0 || len(keys) == 0 {
		return false
	}
	for _, key := range keys {
		if _, ok := m[key]; ok {
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
	name       string
	hostnames  []string
	log        *caddy.CustomLog
	noHostname bool
}

// GetNamedCustomLogName extracts the name field from a namedCustomLog value.
// This is exported to allow xcaddyfile to work with namedCustomLog without exposing the type.
func GetNamedCustomLogName(v any) string {
	if ncl, ok := v.(namedCustomLog); ok {
		return ncl.name
	}
	return ""
}

// GetNamedCustomLogLog extracts the log field from a namedCustomLog value.
// This is exported to allow xcaddyfile to work with namedCustomLog without exposing the type.
func GetNamedCustomLogLog(v any) *caddy.CustomLog {
	if ncl, ok := v.(namedCustomLog); ok {
		return ncl.log
	}
	return nil
}

// CollectServerLogs extracts all server-specific custom log configurations from pairings.
// This is exported to allow xcaddyfile and other adapters to access server-specific logs
// that are defined within server blocks (via the log directive).
func CollectServerLogs(pairings ServerBlockPairings) []ConfigValue {
	var logs []ConfigValue
	for _, p := range pairings {
		for _, sb := range p.serverBlocks {
			logs = append(logs, sb.Pile["custom_log"]...)
		}
	}
	return logs
}

// addressWithProtocols associates a listen address with
// the protocols to serve it with
type addressWithProtocols struct {
	address   string
	protocols []string
}

// sbAddrAssociation is a mapping from a list of
// addresses with protocols, and a list of server
// blocks that are served on those addresses.
type sbAddrAssociation struct {
	addressesWithProtocols []addressWithProtocols
	serverBlocks           []ServerBlock
}

const (
	matcherPrefix = "@"
	namedRouteKey = "named_route"
)

// extractBlockType extracts the block type from a server block if it has
// explicit [type] syntax. Returns empty string if no explicit type is found.
func extractBlockType(sblock *caddyfile.ServerBlock) (blockType string, err error) {
	if len(sblock.Keys) == 0 {
		return "", nil
	}

	firstKey := sblock.Keys[0].Text

	// Check if this uses explicit [type] syntax
	if strings.HasPrefix(firstKey, "[") && strings.HasSuffix(firstKey, "]") {
		// Extract the block type name
		blockType = strings.TrimSuffix(strings.TrimPrefix(firstKey, "["), "]")
		if blockType == "" {
			return "", fmt.Errorf("%s:%d: empty block type declaration []",
				sblock.Keys[0].File, sblock.Keys[0].Line)
		}

		// Remove the [type] token from the keys
		sblock.Keys = sblock.Keys[1:]
		return blockType, nil
	}

	// No explicit type
	return "", nil
}

// applyGlobalOptions applies values from the options map to the builder.
// This includes admin config, storage, logging, and other global settings.
func applyGlobalOptions(builder *configbuilder.Builder, options map[string]any, warnings *[]caddyconfig.Warning) error {
	// Add any httpcaddyfile.App types from options
	for _, opt := range options {
		if app, ok := opt.(App); ok {
			builder.AddRawApp(app.Name, app.Value)
		}
	}

	// Apply filesystem option
	if filesystems, ok := options["filesystem"].(caddy.Module); ok {
		builder.AddRawApp("caddy.filesystems", caddyconfig.JSON(filesystems, warnings))
	}

	// Apply storage option
	if storageCvtr, ok := options["storage"].(caddy.StorageConverter); ok {
		builder.SetStorage(storageCvtr)
	}

	// Apply admin option
	if adminConfig, ok := options["admin"].(*caddy.AdminConfig); ok && adminConfig != nil {
		builder.SetAdmin(adminConfig)
	}

	// Apply persist_config option
	if pc, ok := options["persist_config"].(string); ok && pc == "off" {
		admin := builder.GetAdmin()
		if admin.Config == nil {
			admin.Config = new(caddy.ConfigSettings)
		}
		falseBool := false
		admin.Config.Persist = &falseBool
	}

	return nil
}

// processLogs collects all custom logs (global and server-specific) and applies them to the config.
// This must run after the config is finalized so we can access the HTTP app.
func processLogs(cfg *caddy.Config, options map[string]any, warnings *[]caddyconfig.Warning) error {
	var customLogs []struct {
		name string
		log  *caddy.CustomLog
	}
	var hasDefaultLog bool

	addCustomLog := func(name string, log *caddy.CustomLog) {
		if name == "" {
			return
		}
		if name == caddy.DefaultLoggerName {
			hasDefaultLog = true
		}
		// Apply debug level if debug is on and no level is set
		if _, ok := options["debug"]; ok && log != nil && log.Level == "" {
			log.Level = zap.DebugLevel.CapitalString()
		}
		customLogs = append(customLogs, struct {
			name string
			log  *caddy.CustomLog
		}{name: name, log: log})
	}

	// Collect global log options from options["log"]
	if options["log"] != nil {
		for _, logValue := range options["log"].([]ConfigValue) {
			nclValue := logValue.Value
			name := GetNamedCustomLogName(nclValue)
			log := GetNamedCustomLogLog(nclValue)
			addCustomLog(name, log)
		}
	}

	// Collect server-specific log options from options["__xcaddyfile_server_logs__"]
	if options["__xcaddyfile_server_logs__"] != nil {
		for _, logValue := range options["__xcaddyfile_server_logs__"].([]ConfigValue) {
			nclValue := logValue.Value
			name := GetNamedCustomLogName(nclValue)
			log := GetNamedCustomLogLog(nclValue)
			addCustomLog(name, log)
		}
	}

	// If no default log was configured but debug is on, add one
	if !hasDefaultLog {
		if _, ok := options["debug"]; ok {
			customLogs = append(customLogs, struct {
				name string
				log  *caddy.CustomLog
			}{
				name: caddy.DefaultLoggerName,
				log: &caddy.CustomLog{
					BaseLog: caddy.BaseLog{Level: zap.DebugLevel.CapitalString()},
				},
			})
		}
	}

	// Apply custom logs to the config
	if len(customLogs) > 0 {
		if cfg.Logging == nil {
			cfg.Logging = &caddy.Logging{
				Logs: make(map[string]*caddy.CustomLog),
			}
		}
		if cfg.Logging.Logs == nil {
			cfg.Logging.Logs = make(map[string]*caddy.CustomLog)
		}

		// Add the default log first if defined
		for _, ncl := range customLogs {
			if ncl.name == caddy.DefaultLoggerName && ncl.log != nil {
				cfg.Logging.Logs[caddy.DefaultLoggerName] = ncl.log
				break
			}
		}

		// Add the rest of the custom logs
		for _, ncl := range customLogs {
			if ncl.log == nil || ncl.name == caddy.DefaultLoggerName {
				continue
			}
			if ncl.name != "" {
				cfg.Logging.Logs[ncl.name] = ncl.log
			}
			// Most users prefer not writing access logs to the default log
			// when they are directed to a file or have special customization
			if ncl.name != caddy.DefaultLoggerName && len(ncl.log.Include) > 0 {
				defaultLog, ok := cfg.Logging.Logs[caddy.DefaultLoggerName]
				if !ok {
					defaultLog = new(caddy.CustomLog)
					cfg.Logging.Logs[caddy.DefaultLoggerName] = defaultLog
				}
				defaultLog.Exclude = append(defaultLog.Exclude, ncl.log.Include...)

				// Avoid duplicates by sorting + compacting
				sort.Strings(defaultLog.Exclude)
				defaultLog.Exclude = slices.Compact(defaultLog.Exclude)
			}
		}
		// we may have not actually added anything, so remove if empty
		if len(cfg.Logging.Logs) == 0 {
			cfg.Logging = nil
		}
	}

	return nil
}

// Interface guard
var _ caddyfile.ServerType = (*ServerType)(nil)
