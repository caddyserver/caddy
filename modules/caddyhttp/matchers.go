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
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/parser"
	"golang.org/x/net/idna"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"

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
	// Paths are compared under Unicode default case folding and canonical
	// normalization, which is how case-insensitive APFS volumes on macOS
	// compare names, so `/secret` also matches `/SECRET` and `/ſecret`,
	// `/password` matches `/paßword`, and `/café` matches the same name
	// spelled with `e` and a combining acute accent (U+0301). Turkic
	// mappings are not applied, so `ı` does not match `i`.
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
	// escaped form, `%25`. Escape sequences that encode a character outside
	// ASCII, such as `%C3%A9`, are compared like the character itself.
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
		normalizedHost := strings.ToLower(asciiHost)
		if firstI, ok := seen[normalizedHost]; ok {
			return fmt.Errorf("host at index %d is repeated at index %d: %s", firstI, i, host)
		}
		// Normalize exact hosts for standardized comparison in large-list fastpath later on.
		// Keep wildcards/placeholders untouched.
		if m.fuzzy(asciiHost) {
			m[i] = asciiHost
		} else {
			m[i] = normalizedHost
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
		reqHostLower := strings.ToLower(reqHost)
		// fast path: locate exact match using binary search (about 100-1000x faster for large lists)
		pos := sort.Search(len(m), func(i int) bool {
			if m.fuzzy(m[i]) {
				return false
			}
			return m[i] >= reqHostLower
		})
		if pos < len(m) && m[pos] == reqHostLower {
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
			refStringList := stringSliceType
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

// Provision folds the paths in m to ensure case-insensitive matching.
func (m MatchPath) Provision(_ caddy.Context) error {
	for i := range m {
		if m[i] == "*" && i > 0 {
			// will always match, so just put it first
			m[0] = m[i]
			break
		}
		// patterns with escape sequences are folded around their escape
		// sequences when they are parsed, in matchPatternWithEscapeSequence
		if !strings.Contains(m[i], "%") {
			m[i] = foldPath(m[i])
		}
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
	reqPath := normalizeWindowsPath(foldPath(r.URL.Path))

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
			escapedPath := r.URL.EscapedPath()
			if runtime.GOOS == "windows" {
				escapedPath = windowsEscapedPathSeparatorRepl.Replace(escapedPath)
				matchPattern = windowsEscapedPathSeparatorRepl.Replace(matchPattern)
				escapedPath = normalizeWindowsEscapedPath(escapedPath)
			}
			reqPathForPattern := CleanPath(escapedPath, mergeSlashes)
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

// matchPatternWithEscapeSequence reports whether escapedPath matches pattern,
// a path pattern containing '%'. An escape sequence of an ASCII byte in the
// pattern only matches that same escape sequence in the path, and a "%*" span
// may contain escaped slashes; everything else is compared in unescaped space
// after foldPath, like patterns without escape sequences. Wildcards and
// character classes otherwise behave as in path.Match.
func (MatchPath) matchPatternWithEscapeSequence(escapedPath, pattern string) bool {
	elems, keep, ok := parseEscapedPattern(pattern)
	if !ok {
		return false
	}
	units := escapedPathUnits(escapedPath, &keep)

	// matched[j] reports whether the elements so far match units[:j]
	rows := make([]bool, 2*(len(units)+1))
	matched, next := rows[:len(units)+1], rows[len(units)+1:]
	matched[0] = true
	for _, e := range elems {
		alive := false
		if e.kind == escStar || e.kind == escRawStar {
			next[0] = matched[0]
			alive = next[0]
			for j, u := range units {
				next[j+1] = matched[j+1] || (next[j] && e.spans(u))
				alive = alive || next[j+1]
			}
		} else {
			next[0] = false
			for j, u := range units {
				next[j+1] = matched[j] && e.matches(u)
				alive = alive || next[j+1]
			}
		}
		if !alive {
			return false
		}
		matched, next = next, matched
	}
	return matched[len(units)]
}

// escapedPathUnit is one character of a request path being matched against a
// pattern with escape sequences.
type escapedPathUnit struct {
	// r is the character after foldPath, or -1 for a byte that is not
	// valid UTF-8.
	r rune
	// esc is the byte encoded by the escape sequence the character was
	// written as, if the pattern may need to compare it in escaped space,
	// or -1.
	esc int16
}

// escapedPatternElem is one element of a path pattern with escape sequences.
type escapedPatternElem struct {
	kind  escapedPatternKind
	r     rune   // for escLiteral
	b     byte   // for escByte
	class string // for escClass, including the brackets
}

type escapedPatternKind uint8

const (
	escLiteral escapedPatternKind = iota // a character, compared in unescaped space
	escByte                              // an escape sequence, compared in escaped space
	escAny                               // '?'
	escClass                             // a character class, such as "[a-z]"
	escStar                              // '*'
	escRawStar                           // "%*"
)

// matches reports whether e, which is not a wildcard, matches u.
func (e escapedPatternElem) matches(u escapedPathUnit) bool {
	switch e.kind {
	case escLiteral:
		return u.r == e.r
	case escByte:
		return u.esc == int16(e.b)
	case escAny:
		return u.r != '/'
	case escClass:
		ok, _ := path.Match(e.class, string(u.r))
		return ok
	case escStar, escRawStar:
		// wildcards span units instead; see spans
	}
	return false
}

// spans reports whether u may be part of the span matched by e, a wildcard.
// Neither wildcard spans a slash, but "%*" spans an escaped one.
func (e escapedPatternElem) spans(u escapedPathUnit) bool {
	return u.r != '/' || (e.kind == escRawStar && u.esc >= 0)
}

// parseEscapedPattern splits pattern into the elements compared by
// matchPatternWithEscapeSequence. It also returns the ASCII bytes whose escape
// sequences in a request path must be kept escaped to be compared with the
// pattern. It reports false if pattern is malformed.
func parseEscapedPattern(pattern string) ([]escapedPatternElem, [utf8.RuneSelf]bool, bool) {
	var (
		elems = make([]escapedPatternElem, 0, len(pattern))
		keep  [utf8.RuneSelf]bool
		lit   []byte // literal text not yet folded
	)
	flush := func() {
		foldEach(lit, func(r rune) {
			elems = append(elems, escapedPatternElem{kind: escLiteral, r: r})
		})
		lit = lit[:0]
	}
	for i := 0; i < len(pattern); {
		if b, ok := unescapeByte(pattern[i:]); ok {
			if b < utf8.RuneSelf {
				flush()
				elems = append(elems, escapedPatternElem{kind: escByte, b: b})
				keep[b] = true
				i += 3
				continue
			}
			// a character outside ASCII has only one escaped form, so
			// it is compared like the character itself
			r, n := unescapeChar(pattern[i:])
			if n == 3 && r == utf8.RuneError {
				flush()
				elems = append(elems, escapedPatternElem{kind: escByte, b: b})
			} else {
				lit = utf8.AppendRune(lit, r)
			}
			i += n
			continue
		}
		switch pattern[i] {
		case '%':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				flush()
				elems = append(elems, escapedPatternElem{kind: escRawStar})
				keep['/'] = true
				i += 2
				continue
			}
			lit = append(lit, '%')
			i++
		case '*':
			flush()
			elems = append(elems, escapedPatternElem{kind: escStar})
			i++
		case '?':
			flush()
			elems = append(elems, escapedPatternElem{kind: escAny})
			i++
		case '[':
			n := classLen(pattern[i:])
			if n < 0 {
				return nil, keep, false
			}
			class := foldPath(pattern[i : i+n])
			if _, err := path.Match(class, ""); err != nil {
				return nil, keep, false
			}
			flush()
			elems = append(elems, escapedPatternElem{kind: escClass, class: class})
			i += n
		case '\\':
			if i+1 >= len(pattern) {
				return nil, keep, false
			}
			_, n := utf8.DecodeRuneInString(pattern[i+1:])
			lit = append(lit, pattern[i+1:i+1+n]...)
			i += 1 + n
		default:
			lit = append(lit, pattern[i])
			i++
		}
	}
	flush()
	return elems, keep, true
}

// escapedPathUnits decodes escapedPath into the characters compared by
// matchPatternWithEscapeSequence. The escape sequences of the ASCII bytes in
// keep are kept as units of their own; everything else is unescaped and run
// through foldPath, so the unescaped text is folded and normalized as a whole
// (e.g. "e%CC%81" becomes one 'é').
func escapedPathUnits(escapedPath string, keep *[utf8.RuneSelf]bool) []escapedPathUnit {
	units := make([]escapedPathUnit, 0, len(escapedPath))
	text := make([]byte, 0, len(escapedPath)) // unescaped text not yet folded
	flush := func() {
		foldEach(text, func(r rune) {
			units = append(units, escapedPathUnit{r: r, esc: -1})
		})
		text = text[:0]
	}
	for i := 0; i < len(escapedPath); {
		b, ok := unescapeByte(escapedPath[i:])
		switch {
		case !ok:
			text = append(text, escapedPath[i])
			i++
		case b < utf8.RuneSelf && keep[b]:
			flush()
			r := rune(b)
			if 'A' <= r && r <= 'Z' {
				r += 'a' - 'A'
			}
			units = append(units, escapedPathUnit{r: r, esc: int16(b)})
			i += 3
		case b < utf8.RuneSelf:
			text = append(text, b)
			i += 3
		default:
			r, n := unescapeChar(escapedPath[i:])
			if n == 3 && r == utf8.RuneError {
				flush()
				units = append(units, escapedPathUnit{r: -1, esc: int16(b)})
			} else {
				text = utf8.AppendRune(text, r)
			}
			i += n
		}
	}
	flush()
	return units
}

// foldEach calls fn with each character of foldPath(text).
func foldEach(text []byte, fn func(rune)) {
	for _, c := range text {
		if c >= utf8.RuneSelf {
			for _, r := range foldPath(string(text)) {
				fn(r)
			}
			return
		}
	}
	for _, c := range text {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		fn(rune(c))
	}
}

// unescapeByte decodes the escape sequence at the start of s, if any.
func unescapeByte(s string) (byte, bool) {
	if len(s) < 3 || s[0] != '%' {
		return 0, false
	}
	hi, ok1 := unhex(s[1])
	lo, ok2 := unhex(s[2])
	return hi<<4 | lo, ok1 && ok2
}

// unescapeChar decodes the character outside ASCII that is written at the
// start of s as one escape sequence per UTF-8 byte. It returns the character
// and the number of bytes of s it spans, or utf8.RuneError and 3 if the first
// byte does not start a valid UTF-8 sequence.
func unescapeChar(s string) (rune, int) {
	var buf [utf8.UTFMax]byte
	n := 0
	for n < len(buf) && !utf8.FullRune(buf[:n]) {
		b, ok := unescapeByte(s[3*n:])
		if !ok {
			break
		}
		buf[n] = b
		n++
	}
	r, size := utf8.DecodeRune(buf[:n])
	if r == utf8.RuneError && size <= 1 {
		return utf8.RuneError, 3
	}
	return r, 3 * size
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// classLen returns the length of the character class at the start of s, or
// -1 if it is not closed.
func classLen(s string) int {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case ']':
			return i + 1
		}
	}
	return -1
}

// pathFolder case-folds paths for foldPath. It is stateless and safe for
// concurrent use.
var pathFolder = cases.Fold()

// foldPath maps p to the form the case-insensitive path matcher compares:
// Unicode default case folding (the C and F mappings in CaseFolding.txt) of
// its canonical decomposition, recomposed into NFC. Two paths fold to the same
// string exactly when they are canonical caseless matches (Unicode section
// 3.13), which is how case-insensitive APFS volumes on macOS compare names:
// /SECRET, /ſecret and /secret fold together, as do /paßword and /password,
// and "café" spelled with a precomposed 'é' or with 'e' and a combining acute
// accent. Turkic mappings are not applied, so 'ı' (U+0131) stays distinct
// from 'i'.
func foldPath(p string) string {
	for i := 0; i < len(p); i++ {
		if p[i] >= utf8.RuneSelf {
			return norm.NFC.String(pathFolder.String(norm.NFD.String(p)))
		}
	}
	return strings.ToLower(p)
}

// windowsEscapedPathSeparatorRepl normalizes Windows backslash separators
// while preserving escaped-path matching semantics.
var windowsEscapedPathSeparatorRepl = strings.NewReplacer(
	`\`, "%2f",
	"%5c", "%2f",
	"%5C", "%2f",
)

// NormalizedPath returns a decoded request path in the form the path matchers
// evaluate it: rewritten the way the Windows filesystem resolves it (a no-op on
// other platforms), then cleaned. Consumers that act on a path a matcher has
// already judged should derive it with this, so the two cannot disagree about
// which resource a request names. An empty path is returned unchanged.
func NormalizedPath(p string, mergeSlashes bool) string {
	if p == "" {
		return ""
	}
	return CleanPath(normalizeWindowsPath(p), mergeSlashes)
}

// normalizeWindowsPath rewrites a decoded request path the way the Windows
// filesystem resolves it, so that path matchers (both `path` and `path_regexp`)
// cannot be bypassed on Windows: backslashes are treated as path separators,
// and trailing dots and spaces are ignored on EVERY path component (not only at
// the end of the whole path — e.g. a guard on `/private/` must also cover
// `/private./secret`). Path navigation segments ("." and "..") are left intact
// for cleanPath to resolve. It is a no-op on non-Windows systems. See #5613.
func normalizeWindowsPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	p = strings.ReplaceAll(p, `\`, "/")
	segments := strings.Split(p, "/")
	for i, s := range segments {
		if s == "." || s == ".." {
			continue
		}
		segments[i] = strings.TrimRight(s, ". ")
	}
	return strings.Join(segments, "/")
}

// normalizeWindowsEscapedPath applies the same Windows normalization as
// normalizeWindowsPath, but in raw/escaped space (used when a matcher pattern
// contains '%'), where path separators may be percent-encoded ("%2f") and a
// component's trailing dots and spaces may be literal ("." / " ") or
// percent-encoded ("%2e" / "%20"). Without this, a '%'-containing matcher such
// as `/private%2f*` is bypassed on Windows by e.g. GET /private.%5csecret.txt,
// because only backslash separators — not the per-component trailing dots and
// spaces — were folded. The caller must have already folded backslash
// separators to "%2f" via windowsEscapedPathSeparatorRepl. Navigation segments
// ("." and "..") are left intact for CleanPath to resolve. Only the request
// path is normalized, not the matcher pattern (mirroring normalizeWindowsPath).
// It is a no-op on non-Windows systems. See #5613.
func normalizeWindowsEscapedPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	var sb strings.Builder
	sb.Grow(len(p))
	// walk the path, splitting on separators that are meaningful on Windows:
	// the literal '/' and the encoded '%2f'/'%2F' (backslashes were already
	// folded to "%2f" by the caller). Trim each component, preserving the
	// separators exactly so escaped-space comparison still lines up.
	start := 0
	flush := func(end int) {
		seg := p[start:end]
		if seg != "." && seg != ".." {
			seg = trimWindowsEscapedTrailingDotSpace(seg)
		}
		sb.WriteString(seg)
	}
	for i := 0; i < len(p); {
		switch {
		case p[i] == '/':
			flush(i)
			sb.WriteByte('/')
			i++
			start = i
		case p[i] == '%' && i+3 <= len(p) && p[i+1] == '2' && (p[i+2] == 'f' || p[i+2] == 'F'):
			flush(i)
			sb.WriteString(p[i : i+3])
			i += 3
			start = i
		default:
			i++
		}
	}
	flush(len(p))
	return sb.String()
}

// trimWindowsEscapedTrailingDotSpace strips trailing dots and spaces — whether
// literal ("." / " ") or percent-encoded ("%2e"/"%2E" / "%20") — from a single
// escaped-space path component, matching how Windows ignores them.
func trimWindowsEscapedTrailingDotSpace(s string) string {
	for len(s) > 0 {
		if c := s[len(s)-1]; c == '.' || c == ' ' {
			s = s[:len(s)-1]
			continue
		}
		if len(s) >= 3 {
			if tail := s[len(s)-3:]; strings.EqualFold(tail, "%2e") || tail == "%20" {
				s = s[:len(s)-3]
				continue
			}
		}
		return s
	}
	return s
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
			refStringList := stringSliceType
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
	// the path matcher. See #4407 (path cleaning) and #5613
	// (Windows backslash / trailing dot-and-space normalization,
	// shared with the path matcher).
	cleanedPath := cleanPath(normalizeWindowsPath(r.URL.Path))

	return m.MatchRegexp.Match(cleanedPath, repl), nil
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression path_regexp('^/bar')
//
// The pattern is a CEL string literal, so CEL's own escape sequences
// (e.g. \b, \n, \t) are interpreted before the result reaches the regexp
// engine. A pattern that needs a literal backslash escape meant for the
// regexp engine, such as \b for a word boundary, should be written as a
// CEL raw string (prefixed with r) so CEL passes the backslash through
// unchanged: expression path_regexp(r'^/bar\b').
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
			refStringList := stringSliceType
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

// Provision uppercases all configured methods to ensure case-insensitive
// matching against incoming requests, whose methods are always uppercase.
func (m MatchMethod) Provision(_ caddy.Context) error {
	for i := range m {
		m[i] = strings.ToUpper(m[i])
	}
	return nil
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
			refStringList := stringSliceType
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
//
// The pattern is a CEL string literal, so CEL's own escape sequences
// (e.g. \b, \n, \t) are interpreted before the result reaches the regexp
// engine. A pattern that needs a literal backslash escape meant for the
// regexp engine, such as \b for a word boundary, should be written as a
// CEL raw string (prefixed with r) so CEL passes the backslash through
// unchanged: expression header_regexp('foo', 'User-Agent', r'bot\b').
// Without the r prefix, \b is interpreted by CEL as a backspace
// character before the regexp engine ever sees the pattern.
func (MatchHeaderRE) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	unnamedPattern, err := CELMatcherImpl(
		"header_regexp",
		"header_regexp_request_string_string",
		[]*cel.Type{cel.StringType, cel.StringType},
		func(data ref.Val) (RequestMatcherWithError, error) {
			refStringList := stringSliceType
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
			refStringList := stringSliceType
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
		return strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc"), nil
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
			default:
				return d.Errf("unrecognized option '%s'", d.Val())
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

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers. It mirrors the three states the Caddyfile `tls`
// matcher itself supports: bare `tls` (any TLS connection, regardless of
// handshake completion), `tls early_data` (handshake not yet complete), and
// the otherwise-implicit "handshake complete" case. `tls()` is sugar for
// `tls('any')`; both spellings are equivalent and supported.
//
// Example:
//
//	expression tls() && !tls('early_data')
func (MatchTLS) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	const funcName = "tls_request_string"
	factory := func(data ref.Val) (RequestMatcherWithError, error) {
		str, ok := data.(types.String)
		if !ok {
			return nil, errors.New("tls argument was not a string")
		}
		switch string(str) {
		case "any":
			// Also reachable directly as tls('any'), not just via the
			// zero-arg tls() macro below -- both are valid and equivalent.
			return MatchTLS{}, nil
		case "complete":
			complete := true
			return MatchTLS{HandshakeComplete: &complete}, nil
		case "early_data":
			complete := false
			return MatchTLS{HandshakeComplete: &complete}, nil
		default:
			return nil, fmt.Errorf("tls argument must be 'any', 'complete', or 'early_data', got %q", str)
		}
	}

	// tls() is sugar for tls('any'): it expands to the same 2-arg call the
	// one-argument form produces, just with the argument injected by the
	// macro itself instead of typed out by the caller.
	zeroArgMacro := parser.NewGlobalMacro("tls", 0,
		func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
			return eh.NewCall(funcName, eh.NewIdent(CELRequestVarName), eh.NewLiteral(types.String("any"))), nil
		})
	oneArgMacro := parser.NewGlobalMacro("tls", 1, celMatcherStringMacroExpander(funcName))

	envOptions := []cel.EnvOption{
		cel.Macros(zeroArgMacro, oneArgMacro),
		cel.Function(funcName,
			cel.Overload(funcName, []*cel.Type{cel.ObjectType("http.Request"), cel.StringType}, cel.BoolType),
			cel.SingletonBinaryBinding(CELMatcherRuntimeFunction(funcName, factory))),
	}
	programOptions := []cel.ProgramOption{
		cel.CustomDecorator(CELMatcherDecorator(funcName, factory)),
	}
	return NewMatcherCELLibrary(envOptions, programOptions), nil
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

// ParseCaddyfileNestedMatcherSet parses the Caddyfile tokens for a nested
// matcher set, and returns its raw module map value.
func ParseCaddyfileNestedMatcherSet(d *caddyfile.Dispenser) (caddy.ModuleMap, error) {
	matcherMap := make(map[string]any)

	// in case there are multiple instances of the same matcher, concatenate
	// their tokens (we expect that UnmarshalCaddyfile should be able to
	// handle more than one segment); otherwise, we'd overwrite other
	// instances of the matcher in this set
	tokensByMatcherName := make(map[string][]caddyfile.Token)
	for nesting := d.Nesting(); d.NextArg() || d.NextBlock(nesting); {
		// if the token is quoted (backtick), treat it as a shorthand
		// for an expression matcher, same as @named matcher parsing
		if d.Token().Quoted() {
			expressionToken := d.Token().Clone()
			expressionToken.Text = "expression"
			tokensByMatcherName["expression"] = append(tokensByMatcherName["expression"], expressionToken, d.Token())
			continue
		}
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
	_ caddy.Provisioner       = (*MatchPath)(nil)
	_ RequestMatcherWithError = (*MatchPathRE)(nil)
	_ caddy.Provisioner       = (*MatchPathRE)(nil)
	_ RequestMatcherWithError = (*MatchMethod)(nil)
	_ caddy.Provisioner       = (*MatchMethod)(nil)
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
	_ CELLibraryProducer = (*MatchTLS)(nil)
	_ CELLibraryProducer = (*VarsMatcher)(nil)
	_ CELLibraryProducer = (*MatchVarsRE)(nil)

	_ json.Marshaler   = (*MatchNot)(nil)
	_ json.Unmarshaler = (*MatchNot)(nil)
)
