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
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// defaultDirectiveOrder specifies the default order
// to apply directives in HTTP routes. This must only
// consist of directives that are included in Caddy's
// standard distribution.
//
// e.g. The 'root' directive goes near the start in
// case rewrites or redirects depend on existence of
// files, i.e. the file matcher, which must know the
// root first.
//
// e.g. The 'header' directive goes before 'redir' so
// that headers can be manipulated before doing redirects.
//
// e.g. The 'respond' directive is near the end because it
// writes a response and terminates the middleware chain.
var defaultDirectiveOrder = []string{
	"tracing",

	// set variables that may be used by other directives
	"map",
	"vars",
	"fs",
	"root",
	"log_append",
	"skip_log", // TODO: deprecated, renamed to log_skip
	"log_skip",
	"log_name",

	"header",
	"copy_response_headers", // only in reverse_proxy's handle_response
	"request_body",

	"redir",

	// incoming request manipulation
	"method",
	"rewrite",
	"uri",
	"try_files",

	// middleware handlers; some wrap responses
	"basicauth", // TODO: deprecated, renamed to basic_auth
	"basic_auth",
	"forward_auth",
	"request_header",
	"encode",
	"push",
	"intercept",
	"templates",

	// special routing & dispatching directives
	"invoke",
	"handle",
	"handle_path",
	"route",

	// handlers that typically respond to requests
	"abort",
	"error",
	"copy_response", // only in reverse_proxy's handle_response
	"respond",
	"metrics",
	"reverse_proxy",
	"php_fastcgi",
	"file_server",
	"acme_server",
}

// directiveOrder specifies the order to apply directives
// in HTTP routes, after being modified by either the
// plugins or by the user via the "order" global option.
var directiveOrder = defaultDirectiveOrder

// RegisterDirective registers a unique directive dir with an
// associated unmarshaling (setup) function. When directive dir
// is encountered in a Caddyfile, setupFunc will be called to
// unmarshal its tokens.
func RegisterDirective(dir string, setupFunc UnmarshalFunc) {
	if _, ok := registeredDirectives[dir]; ok {
		panic("directive " + dir + " already registered")
	}
	registeredDirectives[dir] = setupFunc
}

// RegisterHandlerDirective is like RegisterDirective, but for
// directives which specifically output only an HTTP handler.
// Directives registered with this function will always have
// an optional matcher token as the first argument.
func RegisterHandlerDirective(dir string, setupFunc UnmarshalHandlerFunc) {
	RegisterDirective(dir, func(h Helper) ([]ConfigValue, error) {
		if !h.Next() {
			return nil, h.ArgErr()
		}

		matcherSet, err := h.ExtractMatcherSet()
		if err != nil {
			return nil, err
		}

		val, err := setupFunc(h)
		if err != nil {
			return nil, err
		}

		return h.NewRoute(matcherSet, val), nil
	})
}

// RegisterDirectiveOrder registers the default order for a
// directive from a plugin.
//
// This is useful when a plugin has a well-understood place
// it should run in the middleware pipeline, and it allows
// users to avoid having to define the order themselves.
//
// The directive dir may be placed in the position relative
// to ('before' or 'after') a directive included in Caddy's
// standard distribution. It cannot be relative to another
// plugin's directive.
//
// EXPERIMENTAL: This API may change or be removed.
func RegisterDirectiveOrder(dir string, position Positional, standardDir string) {
	// check if directive was already ordered
	if slices.Contains(directiveOrder, dir) {
		panic("directive '" + dir + "' already ordered")
	}

	if position != Before && position != After {
		panic("the 2nd argument must be either 'before' or 'after', got '" + position + "'")
	}

	// check if directive exists in standard distribution, since
	// we can't allow plugins to depend on one another; we can't
	// guarantee the order that plugins are loaded in.
	foundStandardDir := slices.Contains(defaultDirectiveOrder, standardDir)
	if !foundStandardDir {
		panic("the 3rd argument '" + standardDir + "' must be a directive that exists in the standard distribution of Caddy")
	}

	// insert directive into proper position
	newOrder := directiveOrder
	for i, d := range newOrder {
		if d != standardDir {
			continue
		}
		if position == Before {
			newOrder = append(newOrder[:i], append([]string{dir}, newOrder[i:]...)...)
		} else if position == After {
			newOrder = append(newOrder[:i+1], append([]string{dir}, newOrder[i+1:]...)...)
		}
		break
	}
	directiveOrder = newOrder
}

// RegisterGlobalOption registers a unique global option opt with
// an associated unmarshaling (setup) function. When the global
// option opt is encountered in a Caddyfile, setupFunc will be
// called to unmarshal its tokens.
func RegisterGlobalOption(opt string, setupFunc UnmarshalGlobalFunc) {
	if _, ok := registeredGlobalOptions[opt]; ok {
		panic("global option " + opt + " already registered")
	}
	registeredGlobalOptions[opt] = setupFunc
}

// Helper is a type which helps setup a value from
// Caddyfile tokens.
type Helper struct {
	*caddyfile.Dispenser
	// State stores intermediate variables during caddyfile adaptation.
	State        map[string]any
	options      map[string]any
	warnings     *[]caddyconfig.Warning
	matcherDefs  map[string]caddy.ModuleMap
	parentBlock  caddyfile.ServerBlock
	groupCounter counter
}

// Option gets the option keyed by name.
func (h Helper) Option(name string) any {
	return h.options[name]
}

// Caddyfiles returns the list of config files from
// which tokens in the current server block were loaded.
func (h Helper) Caddyfiles() []string {
	// first obtain set of names of files involved
	// in this server block, without duplicates
	files := make(map[string]struct{})
	for _, segment := range h.parentBlock.Segments {
		for _, token := range segment {
			files[token.File] = struct{}{}
		}
	}
	// then convert the set into a slice
	filesSlice := make([]string, 0, len(files))
	for file := range files {
		filesSlice = append(filesSlice, file)
	}
	sort.Strings(filesSlice)
	return filesSlice
}

// JSON converts val into JSON. Any errors are added to warnings.
func (h Helper) JSON(val any) json.RawMessage {
	return caddyconfig.JSON(val, h.warnings)
}

// MatcherToken assumes the next argument token is (possibly) a matcher,
// and if so, returns the matcher set along with a true value. If the next
// token is not a matcher, nil and false is returned. Note that a true
// value may be returned with a nil matcher set if it is a catch-all.
func (h Helper) MatcherToken() (caddy.ModuleMap, bool, error) {
	if !h.NextArg() {
		return nil, false, nil
	}
	return matcherSetFromMatcherToken(h.Dispenser.Token(), h.matcherDefs, h.warnings)
}

// ExtractMatcherSet is like MatcherToken, except this is a higher-level
// method that returns the matcher set described by the matcher token,
// or nil if there is none, and deletes the matcher token from the
// dispenser and resets it as if this look-ahead never happened. Useful
// when wrapping a route (one or more handlers) in a user-defined matcher.
func (h Helper) ExtractMatcherSet() (caddy.ModuleMap, error) {
	matcherSet, hasMatcher, err := h.MatcherToken()
	if err != nil {
		return nil, err
	}
	if hasMatcher {
		// strip matcher token; we don't need to
		// use the return value here because a
		// new dispenser should have been made
		// solely for this directive's tokens,
		// with no other uses of same slice
		h.Dispenser.Delete()
	}
	h.Dispenser.Reset() // pretend this lookahead never happened
	return matcherSet, nil
}

// NewRoute returns config values relevant to creating a new HTTP route.
func (h Helper) NewRoute(matcherSet caddy.ModuleMap,
	handler caddyhttp.MiddlewareHandler,
) []ConfigValue {
	mod, err := caddy.GetModule(caddy.GetModuleID(handler))
	if err != nil {
		*h.warnings = append(*h.warnings, caddyconfig.Warning{
			File:    h.File(),
			Line:    h.Line(),
			Message: err.Error(),
		})
		return nil
	}
	var matcherSetsRaw []caddy.ModuleMap
	if matcherSet != nil {
		matcherSetsRaw = append(matcherSetsRaw, matcherSet)
	}
	return []ConfigValue{
		{
			Class: "route",
			Value: caddyhttp.Route{
				MatcherSetsRaw: matcherSetsRaw,
				HandlersRaw:    []json.RawMessage{caddyconfig.JSONModuleObject(handler, "handler", mod.ID.Name(), h.warnings)},
			},
		},
	}
}

// GroupRoutes adds the routes (caddyhttp.Route type) in vals to the
// same group, if there is more than one route in vals.
func (h Helper) GroupRoutes(vals []ConfigValue) {
	// ensure there's at least two routes; group of one is pointless
	var count int
	for _, v := range vals {
		if _, ok := v.Value.(caddyhttp.Route); ok {
			count++
			if count > 1 {
				break
			}
		}
	}
	if count < 2 {
		return
	}

	// now that we know the group will have some effect, do it
	groupName := h.groupCounter.nextGroup()
	for i := range vals {
		if route, ok := vals[i].Value.(caddyhttp.Route); ok {
			route.Group = groupName
			vals[i].Value = route
		}
	}
}

// WithDispenser returns a new instance based on d. All others Helper
// fields are copied, so typically maps are shared with this new instance.
func (h Helper) WithDispenser(d *caddyfile.Dispenser) Helper {
	h.Dispenser = d
	return h
}

// ParseSegmentAsSubroute parses the segment such that its subdirectives
// are themselves treated as directives, from which a subroute is built
// and returned.
func ParseSegmentAsSubroute(h Helper) (caddyhttp.MiddlewareHandler, error) {
	allResults, err := parseSegmentAsConfig(h)
	if err != nil {
		return nil, err
	}

	return buildSubroute(allResults, h.groupCounter, true)
}

// parseSegmentAsConfig parses the segment such that its subdirectives
// are themselves treated as directives, including named matcher definitions,
// and the raw Config structs are returned.
func parseSegmentAsConfig(h Helper) ([]ConfigValue, error) {
	var allResults []ConfigValue

	for h.Next() {
		// don't allow non-matcher args on the first line
		if h.NextArg() {
			return nil, h.ArgErr()
		}

		// slice the linear list of tokens into top-level segments
		var segments []caddyfile.Segment
		for nesting := h.Nesting(); h.NextBlock(nesting); {
			segments = append(segments, h.NextSegment())
		}

		// copy existing matcher definitions so we can augment
		// new ones that are defined only in this scope
		matcherDefs := make(map[string]caddy.ModuleMap, len(h.matcherDefs))
		for key, val := range h.matcherDefs {
			matcherDefs[key] = val
		}

		// find and extract any embedded matcher definitions in this scope
		for i := 0; i < len(segments); i++ {
			seg := segments[i]
			if strings.HasPrefix(seg.Directive(), matcherPrefix) {
				// parse, then add the matcher to matcherDefs
				err := parseMatcherDefinitions(caddyfile.NewDispenser(seg), matcherDefs)
				if err != nil {
					return nil, err
				}
				// remove the matcher segment (consumed), then step back the loop
				segments = append(segments[:i], segments[i+1:]...)
				i--
			}
		}

		// with matchers ready to go, evaluate each directive's segment
		for _, seg := range segments {
			dir := seg.Directive()
			dirFunc, ok := registeredDirectives[dir]
			if !ok {
				return nil, h.Errf("unrecognized directive: %s - are you sure your Caddyfile structure (nesting and braces) is correct?", dir)
			}

			subHelper := h
			subHelper.Dispenser = caddyfile.NewDispenser(seg)
			subHelper.matcherDefs = matcherDefs

			results, err := dirFunc(subHelper)
			if err != nil {
				return nil, h.Errf("parsing caddyfile tokens for '%s': %v", dir, err)
			}

			dir = normalizeDirectiveName(dir)

			for _, result := range results {
				result.directive = dir
				allResults = append(allResults, result)
			}
		}
	}

	return allResults, nil
}

// ConfigValue represents a value to be added to the final
// configuration, or a value to be consulted when building
// the final configuration.
type ConfigValue struct {
	// The kind of value this is. As the config is
	// being built, the adapter will look in the
	// "pile" for values belonging to a certain
	// class when it is setting up a certain part
	// of the config. The associated value will be
	// type-asserted and placed accordingly.
	Class string

	// The value to be used when building the config.
	// Generally its type is associated with the
	// name of the Class.
	Value any

	directive string
}

func sortRoutes(routes []ConfigValue) {
	dirPositions := make(map[string]int)
	for i, dir := range directiveOrder {
		dirPositions[dir] = i
	}

	sort.SliceStable(routes, func(i, j int) bool {
		// if the directives are different, just use the established directive order
		iDir, jDir := routes[i].directive, routes[j].directive
		if iDir != jDir {
			return dirPositions[iDir] < dirPositions[jDir]
		}

		// directives are the same; sub-sort by path matcher length if there's
		// only one matcher set and one path (this is a very common case and
		// usually -- but not always -- helpful/expected, oh well; user can
		// always take manual control of order using handler or route blocks)
		iRoute, ok := routes[i].Value.(caddyhttp.Route)
		if !ok {
			return false
		}
		jRoute, ok := routes[j].Value.(caddyhttp.Route)
		if !ok {
			return false
		}

		// decode the path matchers if there is just one matcher set
		var iPM, jPM caddyhttp.MatchPath
		if len(iRoute.MatcherSetsRaw) == 1 {
			_ = json.Unmarshal(iRoute.MatcherSetsRaw[0]["path"], &iPM)
		}
		if len(jRoute.MatcherSetsRaw) == 1 {
			_ = json.Unmarshal(jRoute.MatcherSetsRaw[0]["path"], &jPM)
		}

		// if there is only one path in the path matcher, sort by longer path
		// (more specific) first; missing path matchers or multi-matchers are
		// treated as zero-length paths
		var iPathLen, jPathLen int
		if len(iPM) == 1 {
			iPathLen = len(iPM[0])
		}
		if len(jPM) == 1 {
			jPathLen = len(jPM[0])
		}

		sortByPath := func() bool {
			// we can only confidently compare path lengths if both
			// directives have a single path to match (issue #5037)
			if iPathLen > 0 && jPathLen > 0 {
				// if both paths are the same except for a trailing wildcard,
				// sort by the shorter path first (which is more specific)
				if strings.TrimSuffix(iPM[0], "*") == strings.TrimSuffix(jPM[0], "*") {
					return iPathLen < jPathLen
				}

				// sort most-specific (longest) path first
				return iPathLen > jPathLen
			}

			// if both directives don't have a single path to compare,
			// sort whichever one has a matcher first; if both have
			// a matcher, sort equally (stable sort preserves order)
			return len(iRoute.MatcherSetsRaw) > 0 && len(jRoute.MatcherSetsRaw) == 0
		}()

		// some directives involve setting values which can overwrite
		// each other, so it makes most sense to reverse the order so
		// that the least-specific matcher is first, allowing the last
		// matching one to win
		if iDir == "vars" {
			return !sortByPath
		}

		// everything else is most-specific matcher first
		return sortByPath
	})
}

// serverBlock pairs a Caddyfile server block with
// a "pile" of config values, keyed by class name,
// as well as its parsed keys for convenience.
type serverBlock struct {
	block      caddyfile.ServerBlock
	pile       map[string][]ConfigValue // config values obtained from directives
	parsedKeys []Address
}

// hostsFromKeys returns a list of all the non-empty hostnames found in
// the keys of the server block sb. If logger mode is false, a key with
// an empty hostname portion will return an empty slice, since that
// server block is interpreted to effectively match all hosts. An empty
// string is never added to the slice.
//
// If loggerMode is true, then the non-standard ports of keys will be
// joined to the hostnames. This is to effectively match the Host
// header of requests that come in for that key.
//
// The resulting slice is not sorted but will never have duplicates.
func (sb serverBlock) hostsFromKeys(loggerMode bool) []string {
	// ensure each entry in our list is unique
	hostMap := make(map[string]struct{})
	for _, addr := range sb.parsedKeys {
		if addr.Host == "" {
			if !loggerMode {
				// server block contains a key like ":443", i.e. the host portion
				// is empty / catch-all, which means to match all hosts
				return []string{}
			}
			// never append an empty string
			continue
		}
		if loggerMode &&
			addr.Port != "" &&
			addr.Port != strconv.Itoa(caddyhttp.DefaultHTTPPort) &&
			addr.Port != strconv.Itoa(caddyhttp.DefaultHTTPSPort) {
			hostMap[net.JoinHostPort(addr.Host, addr.Port)] = struct{}{}
		} else {
			hostMap[addr.Host] = struct{}{}
		}
	}

	// convert map to slice
	sblockHosts := make([]string, 0, len(hostMap))
	for host := range hostMap {
		sblockHosts = append(sblockHosts, host)
	}

	return sblockHosts
}

func (sb serverBlock) hostsFromKeysNotHTTP(httpPort string) []string {
	// ensure each entry in our list is unique
	hostMap := make(map[string]struct{})
	for _, addr := range sb.parsedKeys {
		if addr.Host == "" {
			continue
		}
		if addr.Scheme != "http" && addr.Port != httpPort {
			hostMap[addr.Host] = struct{}{}
		}
	}

	// convert map to slice
	sblockHosts := make([]string, 0, len(hostMap))
	for host := range hostMap {
		sblockHosts = append(sblockHosts, host)
	}

	return sblockHosts
}

// hasHostCatchAllKey returns true if sb has a key that
// omits a host portion, i.e. it "catches all" hosts.
func (sb serverBlock) hasHostCatchAllKey() bool {
	return slices.ContainsFunc(sb.parsedKeys, func(addr Address) bool {
		return addr.Host == ""
	})
}

// isAllHTTP returns true if all sb keys explicitly specify
// the http:// scheme
func (sb serverBlock) isAllHTTP() bool {
	return !slices.ContainsFunc(sb.parsedKeys, func(addr Address) bool {
		return addr.Scheme != "http"
	})
}

// Positional are the supported modes for ordering directives.
type Positional string

const (
	Before Positional = "before"
	After  Positional = "after"
	First  Positional = "first"
	Last   Positional = "last"
)

type (
	// UnmarshalFunc is a function which can unmarshal Caddyfile
	// tokens into zero or more config values using a Helper type.
	// These are passed in a call to RegisterDirective.
	UnmarshalFunc func(h Helper) ([]ConfigValue, error)

	// UnmarshalHandlerFunc is like UnmarshalFunc, except the
	// output of the unmarshaling is an HTTP handler. This
	// function does not need to deal with HTTP request matching
	// which is abstracted away. Since writing HTTP handlers
	// with Caddyfile support is very common, this is a more
	// convenient way to add a handler to the chain since a lot
	// of the details common to HTTP handlers are taken care of
	// for you. These are passed to a call to
	// RegisterHandlerDirective.
	UnmarshalHandlerFunc func(h Helper) (caddyhttp.MiddlewareHandler, error)

	// UnmarshalGlobalFunc is a function which can unmarshal Caddyfile
	// tokens from a global option. It is passed the tokens to parse and
	// existing value from the previous instance of this global option
	// (if any). It returns the value to associate with this global option.
	UnmarshalGlobalFunc func(d *caddyfile.Dispenser, existingVal any) (any, error)
)

var registeredDirectives = make(map[string]UnmarshalFunc)

var registeredGlobalOptions = make(map[string]UnmarshalGlobalFunc)
