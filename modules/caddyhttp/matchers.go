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
	"log"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
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
		Ranges []string `json:"ranges,omitempty"`

		cidrs []*net.IPNet
	}

	// MatchNot matches requests by negating the results of its matcher
	// sets. A single "not" matcher takes one or more matcher sets. Each
	// matcher set is OR'ed; in other words, if any matcher set returns
	// true, the final result of the "not" matcher is false. Individual
	// matchers within a set work the same (i.e. different matchers in
	// the same set are AND'ed).
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

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

outer:
	for _, host := range m {
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
		var query string
		if !d.Args(&query) {
			return d.ArgErr()
		}
		parts := strings.SplitN(query, "=", 2)
		if len(parts) != 2 {
			return d.Errf("malformed query matcher token: %s; must be in param=val format", d.Val())
		}
		url.Values(*m).Set(parts[0], parts[1])
		if d.NextBlock(0) {
			return d.Err("malformed query matcher: blocks are not supported")
		}
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchQuery) Match(r *http.Request) bool {
	for param, vals := range m {
		paramVal, found := r.URL.Query()[param]
		if found {
			for _, v := range vals {
				if paramVal[0] == v || v == "*" {
					return true
				}
			}
		}
	}
	return false
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
		if !d.Args(&field, &val) {
			return d.Errf("malformed header matcher: expected both field and value")
		}
		http.Header(*m).Set(field, val)
		if d.NextBlock(0) {
			return d.Err("malformed header matcher: blocks are not supported")
		}
	}
	return nil
}

// Like req.Header.Get(), but that works with Host header.
// go's http module swallows "Host" header.
func getHeader(r *http.Request, field string) []string {
	field = textproto.CanonicalMIMEHeaderKey(field)

	if field == "Host" {
		return []string{r.Host}
	}

	return r.Header[field]
}

// Match returns true if r matches m.
func (m MatchHeader) Match(r *http.Request) bool {
	for field, allowedFieldVals := range m {
		actualFieldVals := getHeader(r, field)

		if allowedFieldVals != nil && len(allowedFieldVals) == 0 && actualFieldVals != nil {
			// a non-nil but empty list of allowed values means
			// match if the header field exists at all
			continue
		}
		var match bool
	fieldVals:
		for _, actualFieldVal := range actualFieldVals {
			for _, allowedFieldVal := range allowedFieldVals {
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
		actualFieldVals := getHeader(r, field)

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
		return r.Header.Get("content-type") == "application/grpc"
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
		for d.NextBlock(0) {
			matcherName := d.Val()
			mod, err := caddy.GetModule("http.matchers." + matcherName)
			if err != nil {
				return d.Errf("getting matcher module '%s': %v", matcherName, err)
			}
			unm, ok := mod.New().(caddyfile.Unmarshaler)
			if !ok {
				return d.Errf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
			}
			err = unm.UnmarshalCaddyfile(d.NewFromNextSegment())
			if err != nil {
				return err
			}
			rm := unm.(RequestMatcher)
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
		m.Ranges = append(m.Ranges, d.RemainingArgs()...)
		if d.NextBlock(0) {
			return d.Err("malformed remote_ip matcher: blocks are not supported")
		}
	}
	return nil
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *MatchRemoteIP) Provision(ctx caddy.Context) error {
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
	var remote string
	if fwdFor := r.Header.Get("X-Forwarded-For"); fwdFor != "" {
		remote = strings.TrimSpace(strings.Split(fwdFor, ",")[0])
	}
	if remote == "" {
		remote = r.RemoteAddr
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
		log.Printf("[ERROR] remote_ip matcher: %v", err)
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
		key := fmt.Sprintf("%s.%d", mre.phPrefix, i)
		repl.Set(key, match)
	}

	// then by name
	for i, name := range mre.compiled.SubexpNames() {
		if i != 0 && name != "" {
			key := fmt.Sprintf("%s.%s", mre.phPrefix, name)
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

// ResponseMatcher is a type which can determine if an
// HTTP response matches some criteria.
type ResponseMatcher struct {
	// If set, one of these status codes would be required.
	// A one-digit status can be used to represent all codes
	// in that class (e.g. 3 for all 3xx codes).
	StatusCode []int `json:"status_code,omitempty"`

	// If set, each header specified must be one of the specified values.
	Headers http.Header `json:"headers,omitempty"`
}

// Match returns true if the given statusCode and hdr match rm.
func (rm ResponseMatcher) Match(statusCode int, hdr http.Header) bool {
	if !rm.matchStatusCode(statusCode) {
		return false
	}
	return rm.matchHeaders(hdr)
}

func (rm ResponseMatcher) matchStatusCode(statusCode int) bool {
	if rm.StatusCode == nil {
		return true
	}
	for _, code := range rm.StatusCode {
		if StatusCodeMatches(statusCode, code) {
			return true
		}
	}
	return false
}

func (rm ResponseMatcher) matchHeaders(hdr http.Header) bool {
	for field, allowedFieldVals := range rm.Headers {
		actualFieldVals, fieldExists := hdr[textproto.CanonicalMIMEHeaderKey(field)]
		if allowedFieldVals != nil && len(allowedFieldVals) == 0 && fieldExists {
			// a non-nil but empty list of allowed values means
			// match if the header field exists at all
			continue
		}
		var match bool
	fieldVals:
		for _, actualFieldVal := range actualFieldVals {
			for _, allowedFieldVal := range allowedFieldVals {
				if actualFieldVal == allowedFieldVal {
					match = true
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

var wordRE = regexp.MustCompile(`\w+`)

const regexpPlaceholderPrefix = "http.regexp"

// Interface guards
var (
	_ RequestMatcher    = (*MatchHost)(nil)
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

	_ json.Marshaler   = (*MatchNot)(nil)
	_ json.Unmarshaler = (*MatchNot)(nil)
)
