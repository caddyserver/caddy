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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"golang.org/x/net/idna"

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
	//
	// Duplicate entries will return an error.
	MatchHost []string

	// MatchPath case-insensitively matches requests by the URI's path. Path
	// matching is exact, not prefix-based, giving you more control and clarity
	// over matching. Wildcards (`*`) may be used:
	//
	// - At the end only, for a prefix match (`/prefix/*`)
	// - At the beginning only, for a suffix match (`*.suffix`)
	// - On both sides only, for a substring match (`*/contains/*`)
	// - In the middle, for a globular match (`/accounts/*/info`)
	//
	// Slashes are significant; i.e. `/foo*` matches `/foo`, `/foo/`, `/foo/bar`,
	// and `/foobar`; but `/foo/*` does not match `/foo` or `/foobar`. Valid
	// paths start with a slash `/`.
	//
	// Because there are, in general, multiple possible escaped forms of any
	// path, path matchers operate in unescaped space; that is, path matchers
	// should be written in their unescaped form to prevent ambiguities and
	// possible security issues, as all request paths will be normalized to
	// their unescaped forms before matcher evaluation.
	//
	// However, escape sequences in a match pattern are supported; they are
	// compared with the request's raw/escaped path for those bytes only.
	// In other words, a matcher of `/foo%2Fbar` will match a request path
	// of precisely `/foo%2Fbar`, but not `/foo/bar`. It follows that matching
	// the literal percent sign (%) in normalized space can be done using the
	// escaped form, `%25`.
	//
	// Even though wildcards (`*`) operate in the normalized space, the special
	// escaped wildcard (`%*`), which is not a valid escape sequence, may be
	// used in place of a span that should NOT be decoded; that is, `/bands/%*`
	// will match `/bands/AC%2fDC` whereas `/bands/*` will not.
	//
	// Even though path matching is done in normalized space, the special
	// wildcard `%*` may be used in place of a span that should NOT be decoded;
	// that is, `/bands/%*/` will match `/bands/AC%2fDC/` whereas `/bands/*/`
	// will not.
	//
	// This matcher is fast, so it does not support regular expressions or
	// capture groups. For slower but more powerful matching, use the
	// path_regexp matcher. (Note that due to the special treatment of
	// escape sequences in matcher patterns, they may perform slightly slower
	// in high-traffic environments.)
	MatchPath []string

	// MatchPathRE matches requests by a regular expression on the URI's path.
	// Path matching is performed in the unescaped (decoded) form of the path.
	//
	// Upon a match, it adds placeholders to the request: `{http.regexp.name.capture_group}`
	// where `name` is the regular expression's name, and `capture_group` is either
	// the named or positional capture group from the expression itself. If no name
	// is given, then the placeholder omits the name: `{http.regexp.capture_group}`
	// (potentially leading to collisions).
	MatchPathRE struct{ MatchRegexp }

	// MatchMethod matches requests by the method.
	MatchMethod []string

	// MatchQuery matches requests by the URI's query string. It takes a JSON object
	// keyed by the query keys, with an array of string values to match for that key.
	// Query key matches are exact, but wildcards may be used for value matches. Both
	// keys and values may be placeholders.
	//
	// An example of the structure to match `?key=value&topic=api&query=something` is:
	//
	// ```json
	// {
	// 	"key": ["value"],
	//	"topic": ["api"],
	//	"query": ["*"]
	// }
	// ```
	//
	// Invalid query strings, including those with bad escapings or illegal characters
	// like semicolons, will fail to parse and thus fail to match.
	//
	// **NOTE:** Notice that query string values are arrays, not singular values. This is
	// because repeated keys are valid in query strings, and each one may have a
	// different value. This matcher will match for a key if any one of its configured
	// values is assigned in the query string. Backend applications relying on query
	// strings MUST take into consideration that query string values are arrays and can
	// have multiple values.
	MatchQuery url.Values

	// MatchHeader matches requests by header fields. The key is the field
	// name and the array is the list of field values. It performs fast,
	// exact string comparisons of the field values. Fast prefix, suffix,
	// and substring matches can also be done by suffixing, prefixing, or
	// surrounding the value with the wildcard `*` character, respectively.
	// If a list is null, the header must not exist. If the list is empty,
	// the field must simply exist, regardless of its value.
	//
	// **NOTE:** Notice that header values are arrays, not singular values. This is
	// because repeated fields are valid in headers, and each one may have a
	// different value. This matcher will match for a field if any one of its configured
	// values matches in the header. Backend applications relying on headers MUST take
	// into consideration that header field values are arrays and can have multiple
	// values.
	MatchHeader http.Header

	// MatchHeaderRE matches requests by a regular expression on header fields.
	//
	// Upon a match, it adds placeholders to the request: `{http.regexp.name.capture_group}`
	// where `name` is the regular expression's name, and `capture_group` is either
	// the named or positional capture group from the expression itself. If no name
	// is given, then the placeholder omits the name: `{http.regexp.capture_group}`
	// (potentially leading to collisions).
	MatchHeaderRE map[string]*MatchRegexp

	// MatchProtocol matches requests by protocol. Recognized values are
	// "http", "https", and "grpc" for broad protocol matches, or specific
	// HTTP versions can be specified like so: "http/1", "http/1.1",
	// "http/2", "http/3", or minimum versions: "http/2+", etc.
	MatchProtocol string

	// MatchTLS matches HTTP requests based on the underlying
	// TLS connection state. If this matcher is specified but
	// the request did not come over TLS, it will never match.
	// If this matcher is specified but is empty and the request
	// did come in over TLS, it will always match.
	MatchTLS struct {
		// Matches if the TLS handshake has completed. QUIC 0-RTT early
		// data may arrive before the handshake completes. Generally, it
		// is unsafe to replay these requests if they are not idempotent;
		// additionally, the remote IP of early data packets can more
		// easily be spoofed. It is conventional to respond with HTTP 425
		// Too Early if the request cannot risk being processed in this
		// state.
		HandshakeComplete *bool `json:"handshake_complete,omitempty"`
	}

	// MatchNot matches requests by negating the results of its matcher
	// sets. A single "not" matcher takes one or more matcher sets. Each
	// matcher set is OR'ed; in other words, if any matcher set returns
	// true, the final result of the "not" matcher is false. Individual
	// matchers within a set work the same (i.e. different matchers in
	// the same set are AND'ed).
	//
	// NOTE: The generated docs which describe the structure of this
	// module are wrong because of how this type unmarshals JSON in a
	// custom way. The correct structure is:
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
	caddy.RegisterModule(MatchTLS{})
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
	// iterate to merge multiple matchers into one
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
	seen := make(map[string]int, len(m))
	for i, host := range m {
		asciiHost, err := idna.ToASCII(host)
		if err != nil {
			return fmt.Errorf("converting hostname '%s' to ASCII: %v", host, err)
		}
		if asciiHost != host {
			m[i] = asciiHost
		}
		normalizedHost := strings.ToLower(asciiHost)
		if firstI, ok := seen[normalizedHost]; ok {
			return fmt.Errorf("host at index %d is repeated at index %d: %s", firstI, i, host)
		}
		seen[normalizedHost] = i
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
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchHost) MatchWithError(r *http.Request) (bool, error) {
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
			return true, nil
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
			return true, nil
		} else if strings.EqualFold(reqHost, host) {
			return true, nil
		}
	}

	return false, nil
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression host('localhost')
func (MatchHost) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	return CELMatcherImpl(
		"host",
		"host_match_request_list",
		[]*cel.Type{cel.ListType(cel.StringType)},
		func(data ref.Val) (RequestMatcherWithError, error) {
			refStringList := reflect.TypeOf([]string{})
			strList, err := data.ConvertToNative(refStringList)
			if err != nil {
				return nil, err
			}
			matcher := MatchHost(strList.([]string))
			err = matcher.Provision(ctx)
			return matcher, err
		},
	)
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
		if m[i] == "*" && i > 0 {
			// will always match, so just put it first
			m[0] = m[i]
			break
		}
		m[i] = strings.ToLower(m[i])
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchPath) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchPath) MatchWithError(r *http.Request) (bool, error) {
	// Even though RFC 9110 says that path matching is case-sensitive
	// (https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.3),
	// we do case-insensitive matching to mitigate security issues
	// related to differences between operating systems, applications,
	// etc; if case-sensitive matching is needed, the regex matcher
	// can be used instead.
	reqPath := strings.ToLower(r.URL.Path)

	// See #2917; Windows ignores trailing dots and spaces
	// when accessing files (sigh), potentially causing a
	// security risk (cry) if PHP files end up being served
	// as static files, exposing the source code, instead of
	// being matched by *.php to be treated as PHP scripts.
	if runtime.GOOS == "windows" { // issue #5613
		reqPath = strings.TrimRight(reqPath, ". ")
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	for _, matchPattern := range m {
		matchPattern = repl.ReplaceAll(matchPattern, "")

		// special case: whole path is wildcard; this is unnecessary
		// as it matches all requests, which is the same as no matcher
		if matchPattern == "*" {
			return true, nil
		}

		// Clean the path, merge doubled slashes, etc.
		// This ensures maliciously crafted requests can't bypass
		// the path matcher. See #4407. Good security posture
		// requires that we should do all we can to reduce any
		// funny-looking paths into "normalized" forms such that
		// weird variants can't sneak by.
		//
		// How we clean the path depends on the kind of pattern:
		// we either merge slashes or we don't. If the pattern
		// has double slashes, we preserve them in the path.
		//
		// TODO: Despite the fact that the *vast* majority of path
		// matchers have only 1 pattern, a possible optimization is
		// to remember the cleaned form of the path for future
		// iterations; it's just that the way we clean depends on
		// the kind of pattern.

		mergeSlashes := !strings.Contains(matchPattern, "//")

		// if '%' appears in the match pattern, we interpret that to mean
		// the intent is to compare that part of the path in raw/escaped
		// space; i.e. "%40"=="%40", not "@", and "%2F"=="%2F", not "/"
		if strings.Contains(matchPattern, "%") {
			reqPathForPattern := CleanPath(r.URL.EscapedPath(), mergeSlashes)
			if m.matchPatternWithEscapeSequence(reqPathForPattern, matchPattern) {
				return true, nil
			}

			// doing prefix/suffix/substring matches doesn't make sense
			continue
		}

		reqPathForPattern := CleanPath(reqPath, mergeSlashes)

		// for substring, prefix, and suffix matching, only perform those
		// special, fast matches if they are the only wildcards in the pattern;
		// otherwise we assume a globular match if any * appears in the middle

		// special case: first and last characters are wildcard,
		// treat it as a fast substring match
		if strings.Count(matchPattern, "*") == 2 &&
			strings.HasPrefix(matchPattern, "*") &&
			strings.HasSuffix(matchPattern, "*") {
			if strings.Contains(reqPathForPattern, matchPattern[1:len(matchPattern)-1]) {
				return true, nil
			}
			continue
		}

		// only perform prefix/suffix match if it is the only wildcard...
		// I think that is more correct most of the time
		if strings.Count(matchPattern, "*") == 1 {
			// special case: first character is a wildcard,
			// treat it as a fast suffix match
			if strings.HasPrefix(matchPattern, "*") {
				if strings.HasSuffix(reqPathForPattern, matchPattern[1:]) {
					return true, nil
				}
				continue
			}

			// special case: last character is a wildcard,
			// treat it as a fast prefix match
			if strings.HasSuffix(matchPattern, "*") {
				if strings.HasPrefix(reqPathForPattern, matchPattern[:len(matchPattern)-1]) {
					return true, nil
				}
				continue
			}
		}

		// at last, use globular matching, which also is exact matching
		// if there are no glob/wildcard chars; we ignore the error here
		// because we can't handle it anyway
		matches, _ := path.Match(matchPattern, reqPathForPattern)
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func (MatchPath) matchPatternWithEscapeSequence(escapedPath, matchPath string) bool {
	// We would just compare the pattern against r.URL.Path,
	// but the pattern contains %, indicating that we should
	// compare at least some part of the path in raw/escaped
	// space, not normalized space; so we build the string we
	// will compare against by adding the normalized parts
	// of the path, then switching to the escaped parts where
	// the pattern hints to us wherever % is present.
	var sb strings.Builder

	// iterate the pattern and escaped path in lock-step;
	// increment iPattern every time we consume a char from the pattern,
	// increment iPath every time we consume a char from the path;
	// iPattern and iPath are our cursors/iterator positions for each string
	var iPattern, iPath int
	for {
		if iPattern >= len(matchPath) || iPath >= len(escapedPath) {
			break
		}

		// get the next character from the request path

		pathCh := string(escapedPath[iPath])
		var escapedPathCh string

		// normalize (decode) escape sequences
		if pathCh == "%" && len(escapedPath) >= iPath+3 {
			// hold onto this in case we find out the intent is to match in escaped space here;
			// we lowercase it even though technically the spec says: "For consistency, URI
			// producers and normalizers should use uppercase hexadecimal digits for all percent-
			// encodings" (RFC 3986 section 2.1) - we lowercased the matcher pattern earlier in
			// provisioning so we do the same here to gain case-insensitivity in equivalence;
			// besides, this string is never shown visibly
			escapedPathCh = strings.ToLower(escapedPath[iPath : iPath+3])

			var err error
			pathCh, err = url.PathUnescape(escapedPathCh)
			if err != nil {
				// should be impossible unless EscapedPath() is giving us an invalid sequence!
				return false
			}
			iPath += 2 // escape sequence is 2 bytes longer than normal char
		}

		// now get the next character from the pattern

		normalize := true
		switch matchPath[iPattern] {
		case '%':
			// escape sequence

			// if not a wildcard ("%*"), compare literally; consume next two bytes of pattern
			if len(matchPath) >= iPattern+3 && matchPath[iPattern+1] != '*' {
				sb.WriteString(escapedPathCh)
				iPath++
				iPattern += 2
				break
			}

			// escaped wildcard sequence; consume next byte only ('*')
			iPattern++
			normalize = false

			fallthrough
		case '*':
			// wildcard, so consume until next matching character
			remaining := escapedPath[iPath:]
			until := len(escapedPath) - iPath // go until end of string...
			if iPattern < len(matchPath)-1 {  // ...unless the * is not at the end
				nextCh := matchPath[iPattern+1]
				until = strings.IndexByte(remaining, nextCh)
				if until == -1 {
					// terminating char of wildcard span not found, so definitely no match
					return false
				}
			}
			if until == 0 {
				// empty span; nothing to add on this iteration
				break
			}
			next := remaining[:until]
			if normalize {
				var err error
				next, err = url.PathUnescape(next)
				if err != nil {
					return false // should be impossible anyway
				}
			}
			sb.WriteString(next)
			iPath += until
		default:
			sb.WriteString(pathCh)
			iPath++
		}

		iPattern++
	}

	// we can now treat rawpath globs (%*) as regular globs (*)
	matchPath = strings.ReplaceAll(matchPath, "%*", "*")

	// ignore error here because we can't handle it anyway=
	matches, _ := path.Match(matchPath, sb.String())
	return matches
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression path('*substring*', '*suffix')
func (MatchPath) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	return CELMatcherImpl(
		// name of the macro, this is the function name that users see when writing expressions.
		"path",
		// name of the function that the macro will be rewritten to call.
		"path_match_request_list",
		// internal data type of the MatchPath value.
		[]*cel.Type{cel.ListType(cel.StringType)},
		// function to convert a constant list of strings to a MatchPath instance.
		func(data ref.Val) (RequestMatcherWithError, error) {
			refStringList := reflect.TypeOf([]string{})
			strList, err := data.ConvertToNative(refStringList)
			if err != nil {
				return nil, err
			}
			matcher := MatchPath(strList.([]string))
			err = matcher.Provision(ctx)
			return matcher, err
		},
	)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchPath) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// iterate to merge multiple matchers into one
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
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchPathRE) MatchWithError(r *http.Request) (bool, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// Clean the path, merges doubled slashes, etc.
	// This ensures maliciously crafted requests can't bypass
	// the path matcher. See #4407
	cleanedPath := cleanPath(r.URL.Path)

	return m.MatchRegexp.Match(cleanedPath, repl), nil
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression path_regexp('^/bar')
func (MatchPathRE) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	unnamedPattern, err := CELMatcherImpl(
		"path_regexp",
		"path_regexp_request_string",
		[]*cel.Type{cel.StringType},
		func(data ref.Val) (RequestMatcherWithError, error) {
			pattern := data.(types.String)
			matcher := MatchPathRE{MatchRegexp{
				Name:    ctx.Value(MatcherNameCtxKey).(string),
				Pattern: string(pattern),
			}}
			err := matcher.Provision(ctx)
			return matcher, err
		},
	)
	if err != nil {
		return nil, err
	}
	namedPattern, err := CELMatcherImpl(
		"path_regexp",
		"path_regexp_request_string_string",
		[]*cel.Type{cel.StringType, cel.StringType},
		func(data ref.Val) (RequestMatcherWithError, error) {
			refStringList := reflect.TypeOf([]string{})
			params, err := data.ConvertToNative(refStringList)
			if err != nil {
				return nil, err
			}
			strParams := params.([]string)
			name := strParams[0]
			if name == "" {
				name = ctx.Value(MatcherNameCtxKey).(string)
			}
			matcher := MatchPathRE{MatchRegexp{
				Name:    name,
				Pattern: strParams[1],
			}}
			err = matcher.Provision(ctx)
			return matcher, err
		},
	)
	if err != nil {
		return nil, err
	}
	envOpts := append(unnamedPattern.CompileOptions(), namedPattern.CompileOptions()...)
	prgOpts := append(unnamedPattern.ProgramOptions(), namedPattern.ProgramOptions()...)
	return NewMatcherCELLibrary(envOpts, prgOpts), nil
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
	// iterate to merge multiple matchers into one
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
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchMethod) MatchWithError(r *http.Request) (bool, error) {
	return slices.Contains(m, r.Method), nil
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression method('PUT', 'POST')
func (MatchMethod) CELLibrary(_ caddy.Context) (cel.Library, error) {
	return CELMatcherImpl(
		"method",
		"method_request_list",
		[]*cel.Type{cel.ListType(cel.StringType)},
		func(data ref.Val) (RequestMatcherWithError, error) {
			refStringList := reflect.TypeOf([]string{})
			strList, err := data.ConvertToNative(refStringList)
			if err != nil {
				return nil, err
			}
			return MatchMethod(strList.([]string)), nil
		},
	)
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
	// iterate to merge multiple matchers into one
	for d.Next() {
		for _, query := range d.RemainingArgs() {
			if query == "" {
				continue
			}
			before, after, found := strings.Cut(query, "=")
			if !found {
				return d.Errf("malformed query matcher token: %s; must be in param=val format", d.Val())
			}
			url.Values(*m).Add(before, after)
		}
		if d.NextBlock(0) {
			return d.Err("malformed query matcher: blocks are not supported")
		}
	}
	return nil
}

// Match returns true if r matches m. An empty m matches an empty query string.
func (m MatchQuery) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
// An empty m matches an empty query string.
func (m MatchQuery) MatchWithError(r *http.Request) (bool, error) {
	// If no query keys are configured, this only
	// matches an empty query string.
	if len(m) == 0 {
		return len(r.URL.Query()) == 0, nil
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// parse query string just once, for efficiency
	parsed, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		// Illegal query string. Likely bad escape sequence or unescaped literals.
		// Note that semicolons in query string have a controversial history. Summaries:
		// - https://github.com/golang/go/issues/50034
		// - https://github.com/golang/go/issues/25192
		// Despite the URL WHATWG spec mandating the use of & separators for query strings,
		// every URL parser implementation is different, and Filippo Valsorda rightly wrote:
		// "Relying on parser alignment for security is doomed." Overall conclusion is that
		// splitting on & and rejecting ; in key=value pairs is safer than accepting raw ;.
		// We regard the Go team's decision as sound and thus reject malformed query strings.
		return false, nil
	}

	// Count the amount of matched keys, to ensure we AND
	// between all configured query keys; all keys must
	// match at least one value.
	matchedKeys := 0
	for param, vals := range m {
		param = repl.ReplaceAll(param, "")
		paramVal, found := parsed[param]
		if !found {
			return false, nil
		}
		for _, v := range vals {
			v = repl.ReplaceAll(v, "")
			if slices.Contains(paramVal, v) || v == "*" {
				matchedKeys++
				break
			}
		}
	}
	return matchedKeys == len(m), nil
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression query({'sort': 'asc'}) || query({'foo': ['*bar*', 'baz']})
func (MatchQuery) CELLibrary(_ caddy.Context) (cel.Library, error) {
	return CELMatcherImpl(
		"query",
		"query_matcher_request_map",
		[]*cel.Type{CELTypeJSON},
		func(data ref.Val) (RequestMatcherWithError, error) {
			mapStrListStr, err := CELValueToMapStrList(data)
			if err != nil {
				return nil, err
			}
			return MatchQuery(url.Values(mapStrListStr)), nil
		},
	)
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
	// iterate to merge multiple matchers into one
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
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchHeader) MatchWithError(r *http.Request) (bool, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	return matchHeaders(r.Header, http.Header(m), r.Host, r.TransferEncoding, repl), nil
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression header({'content-type': 'image/png'})
//	expression header({'foo': ['bar', 'baz']}) // match bar or baz
func (MatchHeader) CELLibrary(_ caddy.Context) (cel.Library, error) {
	return CELMatcherImpl(
		"header",
		"header_matcher_request_map",
		[]*cel.Type{CELTypeJSON},
		func(data ref.Val) (RequestMatcherWithError, error) {
			mapStrListStr, err := CELValueToMapStrList(data)
			if err != nil {
				return nil, err
			}
			return MatchHeader(http.Header(mapStrListStr)), nil
		},
	)
}

// getHeaderFieldVals returns the field values for the given fieldName from input.
// The host parameter should be obtained from the http.Request.Host field, and the
// transferEncoding from http.Request.TransferEncoding, since net/http removes them
// from the header map.
func getHeaderFieldVals(input http.Header, fieldName, host string, transferEncoding []string) []string {
	fieldName = textproto.CanonicalMIMEHeaderKey(fieldName)
	if fieldName == "Host" && host != "" {
		return []string{host}
	}
	if fieldName == "Transfer-Encoding" && input[fieldName] == nil {
		return transferEncoding
	}
	return input[fieldName]
}

// matchHeaders returns true if input matches the criteria in against without regex.
// The host parameter should be obtained from the http.Request.Host field since
// net/http removes it from the header map.
func matchHeaders(input, against http.Header, host string, transferEncoding []string, repl *caddy.Replacer) bool {
	for field, allowedFieldVals := range against {
		actualFieldVals := getHeaderFieldVals(input, field, host, transferEncoding)
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
	// iterate to merge multiple matchers into one
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

		// Default to the named matcher's name, if no regexp name is provided
		if name == "" {
			name = d.GetContextString(caddyfile.MatcherNameCtxKey)
		}

		// If there's already a pattern for this field
		// then we would end up overwriting the old one
		if (*m)[field] != nil {
			return d.Errf("header_regexp matcher can only be used once per named matcher, per header field: %s", field)
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
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchHeaderRE) MatchWithError(r *http.Request) (bool, error) {
	for field, rm := range m {
		actualFieldVals := getHeaderFieldVals(r.Header, field, r.Host, r.TransferEncoding)
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
			return false, nil
		}
	}
	return true, nil
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

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression header_regexp('foo', 'Field', 'fo+')
func (MatchHeaderRE) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	unnamedPattern, err := CELMatcherImpl(
		"header_regexp",
		"header_regexp_request_string_string",
		[]*cel.Type{cel.StringType, cel.StringType},
		func(data ref.Val) (RequestMatcherWithError, error) {
			refStringList := reflect.TypeOf([]string{})
			params, err := data.ConvertToNative(refStringList)
			if err != nil {
				return nil, err
			}
			strParams := params.([]string)
			matcher := MatchHeaderRE{}
			matcher[strParams[0]] = &MatchRegexp{
				Pattern: strParams[1],
				Name:    ctx.Value(MatcherNameCtxKey).(string),
			}
			err = matcher.Provision(ctx)
			return matcher, err
		},
	)
	if err != nil {
		return nil, err
	}
	namedPattern, err := CELMatcherImpl(
		"header_regexp",
		"header_regexp_request_string_string_string",
		[]*cel.Type{cel.StringType, cel.StringType, cel.StringType},
		func(data ref.Val) (RequestMatcherWithError, error) {
			refStringList := reflect.TypeOf([]string{})
			params, err := data.ConvertToNative(refStringList)
			if err != nil {
				return nil, err
			}
			strParams := params.([]string)
			name := strParams[0]
			if name == "" {
				name = ctx.Value(MatcherNameCtxKey).(string)
			}
			matcher := MatchHeaderRE{}
			matcher[strParams[1]] = &MatchRegexp{
				Pattern: strParams[2],
				Name:    name,
			}
			err = matcher.Provision(ctx)
			return matcher, err
		},
	)
	if err != nil {
		return nil, err
	}
	envOpts := append(unnamedPattern.CompileOptions(), namedPattern.CompileOptions()...)
	prgOpts := append(unnamedPattern.ProgramOptions(), namedPattern.ProgramOptions()...)
	return NewMatcherCELLibrary(envOpts, prgOpts), nil
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
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchProtocol) MatchWithError(r *http.Request) (bool, error) {
	switch string(m) {
	case "grpc":
		return strings.HasPrefix(r.Header.Get("content-type"), "application/grpc"), nil
	case "https":
		return r.TLS != nil, nil
	case "http":
		return r.TLS == nil, nil
	case "http/1.0":
		return r.ProtoMajor == 1 && r.ProtoMinor == 0, nil
	case "http/1.0+":
		return r.ProtoAtLeast(1, 0), nil
	case "http/1.1":
		return r.ProtoMajor == 1 && r.ProtoMinor == 1, nil
	case "http/1.1+":
		return r.ProtoAtLeast(1, 1), nil
	case "http/2":
		return r.ProtoMajor == 2, nil
	case "http/2+":
		return r.ProtoAtLeast(2, 0), nil
	case "http/3":
		return r.ProtoMajor == 3, nil
	case "http/3+":
		return r.ProtoAtLeast(3, 0), nil
	}
	return false, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchProtocol) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// iterate to merge multiple matchers into one
	for d.Next() {
		var proto string
		if !d.Args(&proto) {
			return d.Err("expected exactly one protocol")
		}
		*m = MatchProtocol(proto)
	}
	return nil
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression protocol('https')
func (MatchProtocol) CELLibrary(_ caddy.Context) (cel.Library, error) {
	return CELMatcherImpl(
		"protocol",
		"protocol_request_string",
		[]*cel.Type{cel.StringType},
		func(data ref.Val) (RequestMatcherWithError, error) {
			protocolStr, ok := data.(types.String)
			if !ok {
				return nil, errors.New("protocol argument was not a string")
			}
			return MatchProtocol(strings.ToLower(string(protocolStr))), nil
		},
	)
}

// CaddyModule returns the Caddy module information.
func (MatchTLS) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.tls",
		New: func() caddy.Module { return new(MatchTLS) },
	}
}

// Match returns true if r matches m.
func (m MatchTLS) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchTLS) MatchWithError(r *http.Request) (bool, error) {
	if r.TLS == nil {
		return false, nil
	}
	if m.HandshakeComplete != nil {
		if (!*m.HandshakeComplete && r.TLS.HandshakeComplete) ||
			(*m.HandshakeComplete && !r.TLS.HandshakeComplete) {
			return false, nil
		}
	}
	return true, nil
}

// UnmarshalCaddyfile parses Caddyfile tokens for this matcher. Syntax:
//
// ... tls [early_data]
//
// EXPERIMENTAL SYNTAX: Subject to change.
func (m *MatchTLS) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// iterate to merge multiple matchers into one
	for d.Next() {
		if d.NextArg() {
			switch d.Val() {
			case "early_data":
				var false bool
				m.HandshakeComplete = &false
			}
		}
		if d.NextArg() {
			return d.ArgErr()
		}
		if d.NextBlock(0) {
			return d.Err("malformed tls matcher: blocks are not supported yet")
		}
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
	// iterate to merge multiple matchers into one
	for d.Next() {
		matcherSet, err := ParseCaddyfileNestedMatcherSet(d)
		if err != nil {
			return err
		}
		m.MatcherSetsRaw = append(m.MatcherSetsRaw, matcherSet)
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
	for _, modMap := range matcherSets.([]map[string]any) {
		var ms MatcherSet
		for _, modIface := range modMap {
			if mod, ok := modIface.(RequestMatcherWithError); ok {
				ms = append(ms, mod)
				continue
			}
			if mod, ok := modIface.(RequestMatcher); ok {
				ms = append(ms, mod)
				continue
			}
			return fmt.Errorf("module is not a request matcher: %T", modIface)
		}
		m.MatcherSets = append(m.MatcherSets, ms)
	}
	return nil
}

// Match returns true if r matches m. Since this matcher negates
// the embedded matchers, false is returned if any of its matcher
// sets return true.
func (m MatchNot) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m. Since this matcher
// negates the embedded matchers, false is returned if any of its
// matcher sets return true.
func (m MatchNot) MatchWithError(r *http.Request) (bool, error) {
	for _, ms := range m.MatcherSets {
		matches, err := ms.MatchWithError(r)
		if err != nil {
			return false, err
		}
		if matches {
			return false, nil
		}
	}
	return true, nil
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
}

// Provision compiles the regular expression.
func (mre *MatchRegexp) Provision(caddy.Context) error {
	re, err := regexp.Compile(mre.Pattern)
	if err != nil {
		return fmt.Errorf("compiling matcher regexp %s: %v", mre.Pattern, err)
	}
	mre.compiled = re
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
		keySuffix := "." + strconv.Itoa(i)
		if mre.Name != "" {
			repl.Set(regexpPlaceholderPrefix+"."+mre.Name+keySuffix, match)
		}
		repl.Set(regexpPlaceholderPrefix+keySuffix, match)
	}

	// then by name
	for i, name := range mre.compiled.SubexpNames() {
		// skip the first element (the full match), and empty names
		if i == 0 || name == "" {
			continue
		}

		keySuffix := "." + name
		if mre.Name != "" {
			repl.Set(regexpPlaceholderPrefix+"."+mre.Name+keySuffix, matches[i])
		}
		repl.Set(regexpPlaceholderPrefix+keySuffix, matches[i])
	}

	return true
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (mre *MatchRegexp) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// iterate to merge multiple matchers into one
	for d.Next() {
		// If this is the second iteration of the loop
		// then there's more than one path_regexp matcher
		// and we would end up overwriting the old one
		if mre.Pattern != "" {
			return d.Err("regular expression can only be used once per named matcher")
		}

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

		// Default to the named matcher's name, if no regexp name is provided
		if mre.Name == "" {
			mre.Name = d.GetContextString(caddyfile.MatcherNameCtxKey)
		}

		if d.NextBlock(0) {
			return d.Err("malformed path_regexp matcher: blocks are not supported")
		}
	}
	return nil
}

// ParseCaddyfileNestedMatcher parses the Caddyfile tokens for a nested
// matcher set, and returns its raw module map value.
func ParseCaddyfileNestedMatcherSet(d *caddyfile.Dispenser) (caddy.ModuleMap, error) {
	matcherMap := make(map[string]any)

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
			return nil, d.Errf("getting matcher module '%s': %v", matcherName, err)
		}
		unm, ok := mod.New().(caddyfile.Unmarshaler)
		if !ok {
			return nil, d.Errf("matcher module '%s' is not a Caddyfile unmarshaler", matcherName)
		}
		err = unm.UnmarshalCaddyfile(caddyfile.NewDispenser(tokens))
		if err != nil {
			return nil, err
		}
		if rm, ok := unm.(RequestMatcherWithError); ok {
			matcherMap[matcherName] = rm
			continue
		}
		if rm, ok := unm.(RequestMatcher); ok {
			matcherMap[matcherName] = rm
			continue
		}
		return nil, fmt.Errorf("matcher module '%s' is not a request matcher", matcherName)
	}

	// we should now have a functional matcher, but we also
	// need to be able to marshal as JSON, otherwise config
	// adaptation will be missing the matchers!
	matcherSet := make(caddy.ModuleMap)
	for name, matcher := range matcherMap {
		jsonBytes, err := json.Marshal(matcher)
		if err != nil {
			return nil, fmt.Errorf("marshaling %T matcher: %v", matcher, err)
		}
		matcherSet[name] = jsonBytes
	}

	return matcherSet, nil
}

var wordRE = regexp.MustCompile(`\w+`)

const regexpPlaceholderPrefix = "http.regexp"

// MatcherErrorVarKey is the key used for the variable that
// holds an optional error emitted from a request matcher,
// to short-circuit the handler chain, since matchers cannot
// return errors via the RequestMatcher interface.
//
// Deprecated: Matchers should implement RequestMatcherWithError
// which can return an error directly, instead of smuggling it
// through the vars map.
const MatcherErrorVarKey = "matchers.error"

// Interface guards
var (
	_ RequestMatcherWithError = (*MatchHost)(nil)
	_ caddy.Provisioner       = (*MatchHost)(nil)
	_ RequestMatcherWithError = (*MatchPath)(nil)
	_ RequestMatcherWithError = (*MatchPathRE)(nil)
	_ caddy.Provisioner       = (*MatchPathRE)(nil)
	_ RequestMatcherWithError = (*MatchMethod)(nil)
	_ RequestMatcherWithError = (*MatchQuery)(nil)
	_ RequestMatcherWithError = (*MatchHeader)(nil)
	_ RequestMatcherWithError = (*MatchHeaderRE)(nil)
	_ caddy.Provisioner       = (*MatchHeaderRE)(nil)
	_ RequestMatcherWithError = (*MatchProtocol)(nil)
	_ RequestMatcherWithError = (*MatchNot)(nil)
	_ caddy.Provisioner       = (*MatchNot)(nil)
	_ caddy.Provisioner       = (*MatchRegexp)(nil)

	_ caddyfile.Unmarshaler = (*MatchHost)(nil)
	_ caddyfile.Unmarshaler = (*MatchPath)(nil)
	_ caddyfile.Unmarshaler = (*MatchPathRE)(nil)
	_ caddyfile.Unmarshaler = (*MatchMethod)(nil)
	_ caddyfile.Unmarshaler = (*MatchQuery)(nil)
	_ caddyfile.Unmarshaler = (*MatchHeader)(nil)
	_ caddyfile.Unmarshaler = (*MatchHeaderRE)(nil)
	_ caddyfile.Unmarshaler = (*MatchProtocol)(nil)
	_ caddyfile.Unmarshaler = (*VarsMatcher)(nil)
	_ caddyfile.Unmarshaler = (*MatchVarsRE)(nil)

	_ CELLibraryProducer = (*MatchHost)(nil)
	_ CELLibraryProducer = (*MatchPath)(nil)
	_ CELLibraryProducer = (*MatchPathRE)(nil)
	_ CELLibraryProducer = (*MatchMethod)(nil)
	_ CELLibraryProducer = (*MatchQuery)(nil)
	_ CELLibraryProducer = (*MatchHeader)(nil)
	_ CELLibraryProducer = (*MatchHeaderRE)(nil)
	_ CELLibraryProducer = (*MatchProtocol)(nil)
	_ CELLibraryProducer = (*VarsMatcher)(nil)
	_ CELLibraryProducer = (*MatchVarsRE)(nil)

	_ json.Marshaler   = (*MatchNot)(nil)
	_ json.Unmarshaler = (*MatchNot)(nil)
)
