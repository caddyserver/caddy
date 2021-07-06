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

package caddyhttp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

type (
	// MatchHost matches requests by the Host value (case-insensitive).
	//
	// When used in a top-level HTTP route,
	// [qualifying domain names](/docs/automatic-https#hostname-requirements)
	// may trigger [automatic HTTPS](/docs/automatic-https), which automatically
	// provisions and renews certificates for you. Before doing this, you
	// should ensure that DNS records for these domains are properly configured,
	// especially A/AAAA pointed at your server.
	//
	// Automatic HTTPS can be
	// [customized or disabled](/docs/modules/http#servers/automatic_https).
	//
	// Wildcards (`*`) may be used to represent exactly one label of the
	// hostname, in accordance with RFC 1034 (because host matchers are also
	// used for automatic HTTPS which influences TLS certificates). Thus,
	// a host of `*` matches hosts like `localhost` or `internal` but not
	// `example.com`. To catch all hosts, omit the host matcher entirely.
	//
	// The wildcard can be useful for matching all subdomains, for example:
	// `*.example.com` matches `foo.example.com` but not `foo.bar.example.com`.
	//
	// Duplicate entries will return an error.
	MatchHost []string

	// MatchPath matches requests by the URI's path (case-insensitive). Path
	// matches are exact, but wildcards may be used:
	//
	// - At the end, for a prefix match (`/prefix/*`)
	// - At the beginning, for a suffix match (`*.suffix`)
	// - On both sides, for a substring match (`*/contains/*`)
	// - In the middle, for a globular match (`/accounts/*/info`)
	//
	// This matcher is fast, so it does not support regular expressions or
	// capture groups. For slower but more powerful matching, use the
	// path_regexp matcher.
	MatchPath []string

	// MatchPathRE matches requests by a regular expression on the URI's path.
	//
	// Upon a match, it adds placeholders to the request: `{http.regexp.name.capture_group}`
	// where `name` is the regular expression's name, and `capture_group` is either
	// the named or positional capture group from the expression itself. If no name
	// is given, then the placeholder omits the name: `{http.regexp.capture_group}`
	// (potentially leading to collisions).
	MatchPathRE struct{ MatchRegexp }

	// MatchMethod matches requests by the method.
	MatchMethod []string

	// MatchQuery matches requests by URI's query string.
	MatchQuery url.Values

	// MatchHeader matches requests by header fields. It performs fast,
	// exact string comparisons of the field values. Fast prefix, suffix,
	// and substring matches can also be done by suffixing, prefixing, or
	// surrounding the value with the wildcard `*` character, respectively.
	// If a list is null, the header must not exist. If the list is empty,
	// the field must simply exist, regardless of its value.
	MatchHeader http.Header

	// MatchHeaderRE matches requests by a regular expression on header fields.
	//
	// Upon a match, it adds placeholders to the request: `{http.regexp.name.capture_group}`
	// where `name` is the regular expression's name, and `capture_group` is either
	// the named or positional capture group from the expression itself. If no name
	// is given, then the placeholder omits the name: `{http.regexp.capture_group}`
	// (potentially leading to collisions).
	MatchHeaderRE map[string]*MatchRegexp

	// MatchProtocol matches requests by protocol.
	MatchProtocol string

	// MatchRemoteIP matches requests by client IP (or CIDR range).
	MatchRemoteIP struct {
		// The IPs or CIDR ranges to match.
		Ranges []string `json:"ranges,omitempty"`

		// If true, prefer the first IP in the request's X-Forwarded-For
		// header, if present, rather than the immediate peer's IP, as
		// the reference IP against which to match. Note that it is easy
		// to spoof request headers. Default: false
		Forwarded bool `json:"forwarded,omitempty"`

		cidrs  []*net.IPNet
		logger *zap.Logger
	}

	// MatchNot matches requests by negating the results of its matcher
	// sets. A single "not" matcher takes one or more matcher sets. Each
	// matcher set is OR'ed; in other words, if any matcher set returns
	// true, the final result of the "not" matcher is false. Individual
	// matchers within a set work the same (i.e. different matchers in
	// the same set are AND'ed).
	//
	// Note that the generated docs which describe the structure of
	// this module are wrong because of how this type unmarshals JSON
	// in a custom way. The correct structure is:
	//
	// ```json
	// [
	// 	{},
	// 	{}
	// ]
	// ```
	//
	// where each of the array elements is a matcher set, i.e. an
	// object keyed by matcher name.
	MatchNot struct {
		MatcherSetsRaw []caddy.ModuleMap `json:"-" caddy:"namespace=http.matchers"`
		MatcherSets    []MatcherSet      `json:"-"`
	}
)

func init() {
	caddy.RegisterModule(MatchHost{})
	caddy.RegisterModule(MatchPath{})
	caddy.RegisterModule(MatchPathRE{})
	caddy.RegisterModule(MatchMethod{})
	caddy.RegisterModule(MatchQuery{})
	caddy.RegisterModule(MatchHeader{})
	caddy.RegisterModule(MatchHeaderRE{})
	caddy.RegisterModule(new(MatchProtocol))
	caddy.RegisterModule(MatchRemoteIP{})
	caddy.RegisterModule(MatchNot{})
}

// CaddyModule returns the Caddy module information.
func (MatchHost) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.host",
		New: func() caddy.Module { return new(MatchHost) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchHost) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		*m = append(*m, d.RemainingArgs()...)
		if d.NextBlock(0) {
			return d.Err("malformed host matcher: blocks are not supported")
		}
	}
	return nil
}

// Provision sets up and validates m, including making it more efficient for large lists.
func (m MatchHost) Provision(_ caddy.Context) error {
	// check for duplicates; they are nonsensical and reduce efficiency
	// (we could just remove them, but the user should know their config is erroneous)
	seen := make(map[string]int)
	for i, h := range m {
		h = strings.ToLower(h)
		if firstI, ok := seen[h]; ok {
			return fmt.Errorf("host at index %d is repeated at index %d: %s", firstI, i, h)
		}
		seen[h] = i
	}

	if m.large() {
		// sort the slice lexicographically, grouping "fuzzy" entries (wildcards and placeholders)
		// at the front of the list; this allows us to use binary search for exact matches, which
		// we have seen from experience is the most common kind of value in large lists; and any
		// other kinds of values (wildcards and placeholders) are grouped in front so the linear
		// search should find a match fairly quickly
		sort.Slice(m, func(i, j int) bool {
			iInexact, jInexact := m.fuzzy(m[i]), m.fuzzy(m[j])
			if iInexact && !jInexact {
				return true
			}
			if !iInexact && jInexact {
				return false
			}
			return m[i] < m[j]
		})
	}

	return nil
}

// Match returns true if r matches m.
func (m MatchHost) Match(r *http.Request) bool {
	reqHost, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		// OK; probably didn't have a port
		reqHost = r.Host

		// make sure we strip the brackets from IPv6 addresses
		reqHost = strings.TrimPrefix(reqHost, "[")
		reqHost = strings.TrimSuffix(reqHost, "]")
	}

	if m.large() {
		// fast path: locate exact match using binary search (about 100-1000x faster for large lists)
		pos := sort.Search(len(m), func(i int) bool {
			if m.fuzzy(m[i]) {
				return false
			}
			return m[i] >= reqHost
		})
		if pos < len(m) && m[pos] == reqHost {
			return true
		}
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

outer:
	for _, host := range m {
		// fast path: if matcher is large, we already know we don't have an exact
		// match, so we're only looking for fuzzy match now, which should be at the
		// front of the list; if we have reached a value that is not fuzzy, there
		// will be no match and we can short-circuit for efficiency
		if m.large() && !m.fuzzy(host) {
			break
		}

		host = repl.ReplaceAll(host, "")
		if strings.Contains(host, "*") {
			patternParts := strings.Split(host, ".")
			incomingParts := strings.Split(reqHost, ".")
			if len(patternParts) != len(incomingParts) {
				continue
			}
			for i := range patternParts {
				if patternParts[i] == "*" {
					continue
				}
				if !strings.EqualFold(patternParts[i], incomingParts[i]) {
					continue outer
				}
			}
			return true
		} else if strings.EqualFold(reqHost, host) {
			return true
		}
	}

	return false
}

// fuzzy returns true if the given hostname h is not a specific
// hostname, e.g. has placeholders or wildcards.
func (MatchHost) fuzzy(h string) bool { return strings.ContainsAny(h, "{*") }

// large returns true if m is considered to be large. Optimizing
// the matcher for smaller lists has diminishing returns.
// See related benchmark function in test file to conduct experiments.
func (m MatchHost) large() bool { return len(m) > 100 }

// CaddyModule returns the Caddy module information.
func (MatchPath) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.path",
		New: func() caddy.Module { return new(MatchPath) },
	}
}

// Provision lower-cases the paths in m to ensure case-insensitive matching.
func (m MatchPath) Provision(_ caddy.Context) error {
	for i := range m {
		m[i] = strings.ToLower(m[i])
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchPath) Match(r *http.Request) bool {
	lowerPath := strings.ToLower(r.URL.Path)

	// see #2917; Windows ignores trailing dots and spaces
	// when accessing files (sigh), potentially causing a
	// security risk (cry) if PHP files end up being served
	// as static files, exposing the source code, instead of
	// being matched by *.php to be treated as PHP scripts
	lowerPath = strings.TrimRight(lowerPath, ". ")

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	for _, matchPath := range m {
		matchPath = repl.ReplaceAll(matchPath, "")

		// special case: whole path is wildcard; this is unnecessary
		// as it matches all requests, which is the same as no matcher
		if matchPath == "*" {
			return true
		}

		// special case: first and last characters are wildcard,
		// treat it as a fast substring match
		if len(matchPath) > 1 &&
			strings.HasPrefix(matchPath, "*") &&
			strings.HasSuffix(matchPath, "*") {
			if strings.Contains(lowerPath, matchPath[1:len(matchPath)-1]) {
				return true
			}
			continue
		}

		// special case: first character is a wildcard,
		// treat it as a fast suffix match
		if strings.HasPrefix(matchPath, "*") {
			if strings.HasSuffix(lowerPath, matchPath[1:]) {
				return true
			}
			continue
		}

		// special case: last character is a wildcard,
		// treat it as a fast prefix match
		if strings.HasSuffix(matchPath, "*") {
			if strings.HasPrefix(lowerPath, matchPath[:len(matchPath)-1]) {
				return true
			}
			continue
		}

		// for everything else, try globular matching, which also
		// is exact matching if there are no glob/wildcard chars;
		// can ignore error here because we can't handle it anyway
		matches, _ := filepath.Match(matchPath, lowerPath)
		if matches {
			return true
		}
	}
	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchPath) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		*m = append(*m, d.RemainingArgs()...)
		if d.NextBlock(0) {
			return d.Err("malformed path matcher: blocks are not supported")
		}
	}
	return nil
}

// CaddyModule returns the Caddy module information.
func (MatchPathRE) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.path_regexp",
		New: func() caddy.Module { return new(MatchPathRE) },
	}
}

// Match returns true if r matches m.
func (m MatchPathRE) Match(r *http.Request) bool {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	return m.MatchRegexp.Match(r.URL.Path, repl)
}

// CaddyModule returns the Caddy module information.
func (MatchMethod) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.method",
		New: func() caddy.Module { return new(MatchMethod) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchMethod) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		*m = append(*m, d.RemainingArgs()...)
		if d.NextBlock(0) {
			return d.Err("malformed method matcher: blocks are not supported")
		}
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchMethod) Match(r *http.Request) bool {
	for _, method := range m {
		if r.Method == method {
			return true
		}
	}
	return false
}

// CaddyModule returns the Caddy module information.
func (MatchQuery) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.query",
		New: func() caddy.Module { return new(MatchQuery) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchQuery) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if *m == nil {
		*m = make(map[string][]string)
	}
	for d.Next() {
		for _, query := range d.RemainingArgs() {
			if query == "" {
				continue
			}
			parts := strings.SplitN(query, "=", 2)
			if len(parts) != 2 {
				return d.Errf("malformed query matcher token: %s; must be in param=val format", d.Val())
			}
			url.Values(*m).Add(parts[0], parts[1])
		}
		if d.NextBlock(0) {
			return d.Err("malformed query matcher: blocks are not supported")
		}
	}
	return nil
}

// Match returns true if r matches m. An empty m matches an empty query string.
func (m MatchQuery) Match(r *http.Request) bool {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for param, vals := range m {
		param = repl.ReplaceAll(param, "")
		paramVal, found := r.URL.Query()[param]
		if found {
			for _, v := range vals {
				v = repl.ReplaceAll(v, "")
				if paramVal[0] == v || v == "*" {
					return true
				}
			}
		}
	}
	return len(m) == 0 && len(r.URL.Query()) == 0
}

// CaddyModule returns the Caddy module information.
func (MatchHeader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.header",
		New: func() caddy.Module { return new(MatchHeader) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchHeader) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if *m == nil {
		*m = make(map[string][]string)
	}
	for d.Next() {
		var field, val string
		if !d.Args(&field) {
			return d.Errf("malformed header matcher: expected field")
		}

		if strings.HasPrefix(field, "!") {
			if len(field) == 1 {
				return d.Errf("malformed header matcher: must have field name following ! character")
			}

			field = field[1:]
			headers := *m
			headers[field] = nil
			m = &headers
			if d.NextArg() {
				return d.Errf("malformed header matcher: null matching headers cannot have a field value")
			}
		} else {
			if !d.NextArg() {
				return d.Errf("malformed header matcher: expected both field and value")
			}

			// If multiple header matchers with the same header field are defined,
			// we want to add the existing to the list of headers (will be OR'ed)
			val = d.Val()
			http.Header(*m).Add(field, val)
		}

		if d.NextBlock(0) {
			return d.Err("malformed header matcher: blocks are not supported")
		}
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchHeader) Match(r *http.Request) bool {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	return matchHeaders(r.Header, http.Header(m), r.Host, repl)
}

// getHeaderFieldVals returns the field values for the given fieldName from input.
// The host parameter should be obtained from the http.Request.Host field since
// net/http removes it from the header map.
func getHeaderFieldVals(input http.Header, fieldName, host string) []string {
	fieldName = textproto.CanonicalMIMEHeaderKey(fieldName)
	if fieldName == "Host" && host != "" {
		return []string{host}
	}
	return input[fieldName]
}

// matchHeaders returns true if input matches the criteria in against without regex.
// The host parameter should be obtained from the http.Request.Host field since
// net/http removes it from the header map.
func matchHeaders(input, against http.Header, host string, repl *caddy.Replacer) bool {
	for field, allowedFieldVals := range against {
		actualFieldVals := getHeaderFieldVals(input, field, host)
		if allowedFieldVals != nil && len(allowedFieldVals) == 0 && actualFieldVals != nil {
			// a non-nil but empty list of allowed values means
			// match if the header field exists at all
			continue
		}
		if allowedFieldVals == nil && actualFieldVals == nil {
			// a nil list means match if the header does not exist at all
			continue
		}
		var match bool
	fieldVals:
		for _, actualFieldVal := range actualFieldVals {
			for _, allowedFieldVal := range allowedFieldVals {
				if repl != nil {
					allowedFieldVal = repl.ReplaceAll(allowedFieldVal, "")
				}
				switch {
				case allowedFieldVal == "*":
					match = true
				case strings.HasPrefix(allowedFieldVal, "*") && strings.HasSuffix(allowedFieldVal, "*"):
					match = strings.Contains(actualFieldVal, allowedFieldVal[1:len(allowedFieldVal)-1])
				case strings.HasPrefix(allowedFieldVal, "*"):
					match = strings.HasSuffix(actualFieldVal, allowedFieldVal[1:])
				case strings.HasSuffix(allowedFieldVal, "*"):
					match = strings.HasPrefix(actualFieldVal, allowedFieldVal[:len(allowedFieldVal)-1])
				default:
					match = actualFieldVal == allowedFieldVal
				}
				if match {
					break fieldVals
				}
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// CaddyModule returns the Caddy module information.
func (MatchHeaderRE) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.header_regexp",
		New: func() caddy.Module { return new(MatchHeaderRE) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchHeaderRE) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if *m == nil {
		*m = make(map[string]*MatchRegexp)
	}
	for d.Next() {
		var first, second, third string
		if !d.Args(&first, &second) {
			return d.ArgErr()
		}

		var name, field, val string
		if d.Args(&third) {
			name = first
			field = second
			val = third
		} else {
			field = first
			val = second
		}

		(*m)[field] = &MatchRegexp{Pattern: val, Name: name}

		if d.NextBlock(0) {
			return d.Err("malformed header_regexp matcher: blocks are not supported")
		}
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchHeaderRE) Match(r *http.Request) bool {
	for field, rm := range m {
		actualFieldVals := getHeaderFieldVals(r.Header, field, r.Host)
		match := false
	fieldVal:
		for _, actualFieldVal := range actualFieldVals {
			repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
			if rm.Match(actualFieldVal, repl) {
				match = true
				break fieldVal
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// Provision compiles m's regular expressions.
func (m MatchHeaderRE) Provision(ctx caddy.Context) error {
	for _, rm := range m {
		err := rm.Provision(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// Validate validates m's regular expressions.
func (m MatchHeaderRE) Validate() error {
	for _, rm := range m {
		err := rm.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// CaddyModule returns the Caddy module information.
func (MatchProtocol) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.protocol",
		New: func() caddy.Module { return new(MatchProtocol) },
	}
}

// Match returns true if r matches m.
func (m MatchProtocol) Match(r *http.Request) bool {
	switch string(m) {
	case "grpc":
		return strings.HasPrefix(r.Header.Get("content-type"), "application/grpc")
	case "https":
		return r.TLS != nil
	case "http":
		return r.TLS == nil
	}
	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchProtocol) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		var proto string
		if !d.Args(&proto) {
			return d.Err("expected exactly one protocol")
		}
		*m = MatchProtocol(proto)
	}
	return nil
}

// CaddyModule returns the Caddy module information.
func (MatchNot) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.not",
		New: func() caddy.Module { return new(MatchNot) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchNot) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// first, unmarshal each matcher in the set from its tokens
	type matcherPair struct {
		raw     caddy.ModuleMap
		decoded MatcherSet
	}
	for d.Next() {
		var mp matcherPair
		matcherMap := make(map[string]RequestMatcher)

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
				return d.Errf("getting matcher module '%s': %v", matcherName, err)
			}
			unm, ok := mod.New().(caddyfile.Unmarshaler)
			if !ok {
				return d.Errf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
			}
			err = unm.UnmarshalCaddyfile(caddyfile.NewDispenser(tokens))
			if err != nil {
				return err
			}
			rm, ok := unm.(RequestMatcher)
			if !ok {
				return fmt.Errorf("matcher module '%s' is not a request matcher", matcherName)
			}
			matcherMap[matcherName] = rm
			mp.decoded = append(mp.decoded, rm)
		}

		// we should now have a functional 'not' matcher, but we also
		// need to be able to marshal as JSON, otherwise config
		// adaptation will be missing the matchers!
		mp.raw = make(caddy.ModuleMap)
		for name, matcher := range matcherMap {
			jsonBytes, err := json.Marshal(matcher)
			if err != nil {
				return fmt.Errorf("marshaling %T matcher: %v", matcher, err)
			}
			mp.raw[name] = jsonBytes
		}
		m.MatcherSetsRaw = append(m.MatcherSetsRaw, mp.raw)
	}
	return nil
}

// UnmarshalJSON satisfies json.Unmarshaler. It puts the JSON
// bytes directly into m's MatcherSetsRaw field.
func (m *MatchNot) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &m.MatcherSetsRaw)
}

// MarshalJSON satisfies json.Marshaler by marshaling
// m's raw matcher sets.
func (m MatchNot) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.MatcherSetsRaw)
}

// Provision loads the matcher modules to be negated.
func (m *MatchNot) Provision(ctx caddy.Context) error {
	matcherSets, err := ctx.LoadModule(m, "MatcherSetsRaw")
	if err != nil {
		return fmt.Errorf("loading matcher sets: %v", err)
	}
	for _, modMap := range matcherSets.([]map[string]interface{}) {
		var ms MatcherSet
		for _, modIface := range modMap {
			ms = append(ms, modIface.(RequestMatcher))
		}
		m.MatcherSets = append(m.MatcherSets, ms)
	}
	return nil
}

// Match returns true if r matches m. Since this matcher negates
// the embedded matchers, false is returned if any of its matcher
// sets return true.
func (m MatchNot) Match(r *http.Request) bool {
	for _, ms := range m.MatcherSets {
		if ms.Match(r) {
			return false
		}
	}
	return true
}

// CaddyModule returns the Caddy module information.
func (MatchRemoteIP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.remote_ip",
		New: func() caddy.Module { return new(MatchRemoteIP) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchRemoteIP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextArg() {
			if d.Val() == "forwarded" {
				if len(m.Ranges) > 0 {
					return d.Err("if used, 'forwarded' must be first argument")
				}
				m.Forwarded = true
				continue
			}
			m.Ranges = append(m.Ranges, d.Val())
		}
		if d.NextBlock(0) {
			return d.Err("malformed remote_ip matcher: blocks are not supported")
		}
	}
	return nil
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *MatchRemoteIP) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	for _, str := range m.Ranges {
		if strings.Contains(str, "/") {
			_, ipNet, err := net.ParseCIDR(str)
			if err != nil {
				return fmt.Errorf("parsing CIDR expression: %v", err)
			}
			m.cidrs = append(m.cidrs, ipNet)
		} else {
			ip := net.ParseIP(str)
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", str)
			}
			mask := len(ip) * 8
			m.cidrs = append(m.cidrs, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(mask, mask),
			})
		}
	}
	return nil
}

func (m MatchRemoteIP) getClientIP(r *http.Request) (net.IP, error) {
	remote := r.RemoteAddr
	if m.Forwarded {
		if fwdFor := r.Header.Get("X-Forwarded-For"); fwdFor != "" {
			remote = strings.TrimSpace(strings.Split(fwdFor, ",")[0])
		}
	}
	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid client IP address: %s", ipStr)
	}
	return ip, nil
}

// Match returns true if r matches m.
func (m MatchRemoteIP) Match(r *http.Request) bool {
	clientIP, err := m.getClientIP(r)
	if err != nil {
		m.logger.Error("getting client IP", zap.Error(err))
		return false
	}
	for _, ipRange := range m.cidrs {
		if ipRange.Contains(clientIP) {
			return true
		}
	}
	return false
}

// MatchRegexp is an embedable type for matching
// using regular expressions. It adds placeholders
// to the request's replacer.
type MatchRegexp struct {
	// A unique name for this regular expression. Optional,
	// but useful to prevent overwriting captures from other
	// regexp matchers.
	Name string `json:"name,omitempty"`

	// The regular expression to evaluate, in RE2 syntax,
	// which is the same general syntax used by Go, Perl,
	// and Python. For details, see
	// [Go's regexp package](https://golang.org/pkg/regexp/).
	// Captures are accessible via placeholders. Unnamed
	// capture groups are exposed as their numeric, 1-based
	// index, while named capture groups are available by
	// the capture group name.
	Pattern string `json:"pattern"`

	compiled *regexp.Regexp
	phPrefix string
}

// Provision compiles the regular expression.
func (mre *MatchRegexp) Provision(caddy.Context) error {
	re, err := regexp.Compile(mre.Pattern)
	if err != nil {
		return fmt.Errorf("compiling matcher regexp %s: %v", mre.Pattern, err)
	}
	mre.compiled = re
	mre.phPrefix = regexpPlaceholderPrefix
	if mre.Name != "" {
		mre.phPrefix += "." + mre.Name
	}
	return nil
}

// Validate ensures mre is set up correctly.
func (mre *MatchRegexp) Validate() error {
	if mre.Name != "" && !wordRE.MatchString(mre.Name) {
		return fmt.Errorf("invalid regexp name (must contain only word characters): %s", mre.Name)
	}
	return nil
}

// Match returns true if input matches the compiled regular
// expression in mre. It sets values on the replacer repl
// associated with capture groups, using the given scope
// (namespace).
func (mre *MatchRegexp) Match(input string, repl *caddy.Replacer) bool {
	matches := mre.compiled.FindStringSubmatch(input)
	if matches == nil {
		return false
	}

	// save all capture groups, first by index
	for i, match := range matches {
		key := mre.phPrefix + "." + strconv.Itoa(i)
		repl.Set(key, match)
	}

	// then by name
	for i, name := range mre.compiled.SubexpNames() {
		if i != 0 && name != "" {
			key := mre.phPrefix + "." + name
			repl.Set(key, matches[i])
		}
	}

	return true
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (mre *MatchRegexp) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 1:
			mre.Pattern = args[0]
		case 2:
			mre.Name = args[0]
			mre.Pattern = args[1]
		default:
			return d.ArgErr()
		}
		if d.NextBlock(0) {
			return d.Err("malformed path_regexp matcher: blocks are not supported")
		}
	}
	return nil
}

var wordRE = regexp.MustCompile(`\w+`)

const regexpPlaceholderPrefix = "http.regexp"

// Interface guards
var (
	_ RequestMatcher    = (*MatchHost)(nil)
	_ caddy.Provisioner = (*MatchHost)(nil)
	_ RequestMatcher    = (*MatchPath)(nil)
	_ RequestMatcher    = (*MatchPathRE)(nil)
	_ caddy.Provisioner = (*MatchPathRE)(nil)
	_ RequestMatcher    = (*MatchMethod)(nil)
	_ RequestMatcher    = (*MatchQuery)(nil)
	_ RequestMatcher    = (*MatchHeader)(nil)
	_ RequestMatcher    = (*MatchHeaderRE)(nil)
	_ caddy.Provisioner = (*MatchHeaderRE)(nil)
	_ RequestMatcher    = (*MatchProtocol)(nil)
	_ RequestMatcher    = (*MatchRemoteIP)(nil)
	_ caddy.Provisioner = (*MatchRemoteIP)(nil)
	_ RequestMatcher    = (*MatchNot)(nil)
	_ caddy.Provisioner = (*MatchNot)(nil)
	_ caddy.Provisioner = (*MatchRegexp)(nil)

	_ caddyfile.Unmarshaler = (*MatchHost)(nil)
	_ caddyfile.Unmarshaler = (*MatchPath)(nil)
	_ caddyfile.Unmarshaler = (*MatchPathRE)(nil)
	_ caddyfile.Unmarshaler = (*MatchMethod)(nil)
	_ caddyfile.Unmarshaler = (*MatchQuery)(nil)
	_ caddyfile.Unmarshaler = (*MatchHeader)(nil)
	_ caddyfile.Unmarshaler = (*MatchHeaderRE)(nil)
	_ caddyfile.Unmarshaler = (*MatchProtocol)(nil)
	_ caddyfile.Unmarshaler = (*MatchRemoteIP)(nil)
	_ caddyfile.Unmarshaler = (*VarsMatcher)(nil)
	_ caddyfile.Unmarshaler = (*MatchVarsRE)(nil)

	_ json.Marshaler   = (*MatchNot)(nil)
	_ json.Unmarshaler = (*MatchNot)(nil)
)
