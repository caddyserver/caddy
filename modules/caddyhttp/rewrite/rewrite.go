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

package rewrite

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Rewrite{})
}

// Rewrite is a middleware which can rewrite/mutate HTTP requests.
//
// The Method and URI properties are "setters" (the request URI
// will be overwritten with the given values). Other properties are
// "modifiers" (they modify existing values in a differentiable
// way). It is atypical to combine the use of setters and
// modifiers in a single rewrite.
//
// To ensure consistent behavior, prefix and suffix stripping is
// performed in the URL-decoded (unescaped, normalized) space by
// default except for the specific bytes where an escape sequence
// is used in the prefix or suffix pattern.
//
// For all modifiers, paths are cleaned before being modified so that
// multiple, consecutive slashes are collapsed into a single slash,
// and dot elements are resolved and removed. In the special case
// of a prefix, suffix, or substring containing "//" (repeated slashes),
// slashes will not be merged while cleaning the path so that
// the rewrite can be interpreted literally.
type Rewrite struct {
	// Changes the request's HTTP verb.
	Method string `json:"method,omitempty"`

	// Changes the request's URI, which consists of path and query string.
	// Only components of the URI that are specified will be changed.
	// For example, a value of "/foo.html" or "foo.html" will only change
	// the path and will preserve any existing query string. Similarly, a
	// value of "?a=b" will only change the query string and will not affect
	// the path. Both can also be changed: "/foo?a=b" - this sets both the
	// path and query string at the same time.
	//
	// You can also use placeholders. For example, to preserve the existing
	// query string, you might use: "?{http.request.uri.query}&a=b". Any
	// key-value pairs you add to the query string will not overwrite
	// existing values (individual pairs are append-only).
	//
	// To clear the query string, explicitly set an empty one: "?"
	URI string `json:"uri,omitempty"`

	// Strips the given prefix from the beginning of the URI path.
	// The prefix should be written in normalized (unescaped) form,
	// but if an escaping (`%xx`) is used, the path will be required
	// to have that same escape at that position in order to match.
	StripPathPrefix string `json:"strip_path_prefix,omitempty"`

	// Strips the given suffix from the end of the URI path.
	// The suffix should be written in normalized (unescaped) form,
	// but if an escaping (`%xx`) is used, the path will be required
	// to have that same escape at that position in order to match.
	StripPathSuffix string `json:"strip_path_suffix,omitempty"`

	// Performs substring replacements on the URI.
	URISubstring []substrReplacer `json:"uri_substring,omitempty"`

	// Performs regular expression replacements on the URI path.
	PathRegexp []*regexReplacer `json:"path_regexp,omitempty"`

	// Mutates the query string of the URI.
	Query *queryOps `json:"query,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Rewrite) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.rewrite",
		New: func() caddy.Module { return new(Rewrite) },
	}
}

// Provision sets up rewr.
func (rewr *Rewrite) Provision(ctx caddy.Context) error {
	rewr.logger = ctx.Logger()

	for i, rep := range rewr.PathRegexp {
		if rep.Find == "" {
			return fmt.Errorf("path_regexp find cannot be empty")
		}
		re, err := regexp.Compile(rep.Find)
		if err != nil {
			return fmt.Errorf("compiling regular expression %d: %v", i, err)
		}
		rep.re = re
	}
	if rewr.Query != nil {
		for _, replacementOp := range rewr.Query.Replace {
			err := replacementOp.Provision(ctx)
			if err != nil {
				return fmt.Errorf("compiling regular expression %s in query rewrite replace operation: %v", replacementOp.SearchRegexp, err)
			}
		}
	}

	return nil
}

func (rewr Rewrite) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	const message = "rewrote request"

	c := rewr.logger.Check(zap.DebugLevel, message)
	if c == nil {
		rewr.Rewrite(r, repl)
		return next.ServeHTTP(w, r)
	}

	changed := rewr.Rewrite(r, repl)

	if changed {
		c.Write(
			zap.Object("request", caddyhttp.LoggableHTTPRequest{Request: r}),
			zap.String("method", r.Method),
			zap.String("uri", r.RequestURI),
		)
	}

	return next.ServeHTTP(w, r)
}

// rewrite performs the rewrites on r using repl, which should
// have been obtained from r, but is passed in for efficiency.
// It returns true if any changes were made to r.
func (rewr Rewrite) Rewrite(r *http.Request, repl *caddy.Replacer) bool {
	oldMethod := r.Method
	oldURI := r.RequestURI

	// method
	if rewr.Method != "" {
		r.Method = strings.ToUpper(repl.ReplaceAll(rewr.Method, ""))
	}

	// uri (path, query string and... fragment, because why not)
	if uri := rewr.URI; uri != "" {
		// find the bounds of each part of the URI that exist
		pathStart, qsStart, fragStart := -1, -1, -1
		pathEnd, qsEnd := -1, -1
	loop:
		for i, ch := range uri {
			switch {
			case ch == '?' && qsStart < 0:
				pathEnd, qsStart = i, i+1
			case ch == '#' && fragStart < 0: // everything after fragment is fragment (very clear in RFC 3986 section 4.2)
				if qsStart < 0 {
					pathEnd = i
				} else {
					qsEnd = i
				}
				fragStart = i + 1
				break loop
			case pathStart < 0 && qsStart < 0:
				pathStart = i
			}
		}
		if pathStart >= 0 && pathEnd < 0 {
			pathEnd = len(uri)
		}
		if qsStart >= 0 && qsEnd < 0 {
			qsEnd = len(uri)
		}

		// isolate the three main components of the URI
		var path, query, frag string
		if pathStart > -1 {
			path = uri[pathStart:pathEnd]
		}
		if qsStart > -1 {
			query = uri[qsStart:qsEnd]
		}
		if fragStart > -1 {
			frag = uri[fragStart:]
		}

		// build components which are specified, and store them
		// in a temporary variable so that they all read the
		// same version of the URI
		var newPath, newQuery, newFrag string

		if path != "" {
			path = escapePathPlaceholders(path, r, repl)
			newPath = repl.ReplaceAll(path, "")
		}

		// a fragment may have snuck into the path component during
		// replacements; everything after the first '#' is fragment
		// (RFC 3986 section 4.2), which is never sent to the server,
		// so drop it. this mirrors how a literal '#' in the configured
		// URI is handled by the scan above, and prevents the fragment
		// from being mistaken for part of the path or query below.
		if before, _, found := strings.Cut(newPath, "#"); found {
			newPath = before
		}

		// before continuing, we need to check if a query string
		// snuck into the path component during replacements
		queryInjected := false
		if before, after, found := strings.Cut(newPath, "?"); found {
			// recompute; new path contains a query string
			var injectedQuery string
			newPath, injectedQuery = before, after
			// don't overwrite explicitly-configured query string
			if query == "" {
				// the injected query came from the first-pass placeholder
				// expansion above, which means any '{' or '}' bytes in it
				// must have come from replacement values (e.g. a request
				// header), not from operator-written placeholder syntax.
				// escape them so buildQueryString does not re-expand them,
				// which would allow attacker input like {env.SECRET} to be
				// evaluated (see GHSA-j8px-rmrx-76h9).
				injectedQuery = strings.ReplaceAll(injectedQuery, "{", "%7B")
				injectedQuery = strings.ReplaceAll(injectedQuery, "}", "%7D")
				query = injectedQuery

				// the replacement value spoke about the query string, so the
				// query must be written back even though the configured URI
				// had no literal '?' to set qsStart. an injected query that
				// is empty (a value ending in '?') clears the query, which is
				// consistent with configuring a bare '?'.
				queryInjected = true
			}
		}

		if query != "" {
			newQuery = buildQueryString(query, repl)
		}
		if frag != "" {
			newFrag = repl.ReplaceAll(frag, "")
		}

		// update the URI with the new components
		// only after building them
		if pathStart >= 0 {
			if path, err := url.PathUnescape(newPath); err != nil {
				r.URL.Path = newPath
			} else {
				r.URL.Path = path
			}
			r.URL.RawPath = "" // force recomputing when EscapedPath() is called
		}
		if qsStart >= 0 || queryInjected {
			r.URL.RawQuery = newQuery
		}
		if fragStart >= 0 {
			r.URL.Fragment = newFrag
		}
	}

	// strip path prefix or suffix
	if rewr.StripPathPrefix != "" {
		prefix := repl.ReplaceAll(rewr.StripPathPrefix, "")
		if !strings.HasPrefix(prefix, "/") {
			prefix = "/" + prefix
		}
		mergeSlashes := !strings.Contains(prefix, "//")
		stripped := false
		changePath(r, func(escapedPath string) string {
			escapedPath = caddyhttp.CleanPath(escapedPath, mergeSlashes)
			trimmed := trimPathPrefix(escapedPath, prefix)
			stripped = stripped || trimmed != escapedPath
			return trimmed
		})
		if stripped {
			canonicalizePath(r)
		}
	}
	if rewr.StripPathSuffix != "" {
		suffix := repl.ReplaceAll(rewr.StripPathSuffix, "")
		mergeSlashes := !strings.Contains(suffix, "//")
		stripped := false
		changePath(r, func(escapedPath string) string {
			escapedPath = caddyhttp.CleanPath(escapedPath, mergeSlashes)
			trimmed := trimPathSuffix(escapedPath, suffix)
			stripped = stripped || trimmed != escapedPath
			return trimmed
		})
		if stripped {
			canonicalizePath(r)
		}
	}

	// substring replacements in URI
	for _, rep := range rewr.URISubstring {
		rep.do(r, repl)
	}

	// regular expression replacements on the path
	for _, rep := range rewr.PathRegexp {
		rep.do(r, repl)
	}

	// apply query operations
	if rewr.Query != nil {
		rewr.Query.do(r, repl)
	}

	// update the encoded copy of the URI
	r.RequestURI = r.URL.RequestURI()

	// return true if anything changed
	return r.Method != oldMethod || r.RequestURI != oldURI
}

func escapePathPlaceholders(path string, r *http.Request, repl *caddy.Replacer) string {
	// Replace path-valued placeholders in escaped form before the URI is parsed,
	// otherwise literal '?' and '%' bytes from the path can be interpreted as URI
	// delimiters or percent-escape sequences during the rewrite.
	pathPlaceholder := "{http.request.uri.path}"
	if strings.Contains(path, pathPlaceholder) {
		path = strings.ReplaceAll(path, pathPlaceholder, r.URL.EscapedPath())
	}

	fileMatchRelativePlaceholder := "{http.matchers.file.relative}"
	if strings.Contains(path, fileMatchRelativePlaceholder) {
		if val, ok := repl.Get("http.matchers.file.relative"); ok {
			if relativePath, ok := val.(string); ok {
				path = strings.ReplaceAll(path, fileMatchRelativePlaceholder, escapePathPreservingSlashes(relativePath))
			}
		}
	}

	return path
}

func escapePathPreservingSlashes(path string) string {
	return strings.ReplaceAll(url.PathEscape(path), "%2F", "/")
}

// buildQueryString takes an input query string and
// performs replacements on each component, returning
// the resulting query string. This function appends
// duplicate keys rather than replaces.
func buildQueryString(qs string, repl *caddy.Replacer) string {
	var sb strings.Builder

	// first component must be key, which is the same
	// as if we just wrote a value in previous iteration
	wroteVal := true

	for len(qs) > 0 {
		// determine the end of this component, which will be at
		// the next equal sign or ampersand, whichever comes first
		nextEq, nextAmp := strings.Index(qs, "="), strings.Index(qs, "&")
		if !wroteVal {
			// we are consuming a value, and '=' only delimits a key from
			// its value; any further '=' bytes are literal data, such as
			// base64 padding in a signature. only '&' ends a value.
			nextEq = -1
		}
		ampIsNext := nextAmp >= 0 && (nextAmp < nextEq || nextEq < 0)
		end := len(qs) // assume no delimiter remains...
		if ampIsNext {
			end = nextAmp // ...unless ampersand is first...
		} else if nextEq >= 0 && (nextEq < nextAmp || nextAmp < 0) {
			end = nextEq // ...or unless equal is first.
		}

		// consume the component and write the result
		comp := qs[:end]
		comp, _ = repl.ReplaceFunc(comp, func(name string, val any) (any, error) {
			if name == "http.request.uri.query" && wroteVal {
				return val, nil // already escaped
			}
			var valStr string
			switch v := val.(type) {
			case string:
				valStr = v
			case fmt.Stringer:
				valStr = v.String()
			case int:
				valStr = strconv.Itoa(v)
			default:
				valStr = fmt.Sprintf("%+v", v)
			}
			return url.QueryEscape(valStr), nil
		})
		if end < len(qs) {
			end++ // consume delimiter
		}
		qs = qs[end:]

		// if previous iteration wrote a value,
		// that means we are writing a key
		if wroteVal {
			if sb.Len() > 0 && len(comp) > 0 {
				sb.WriteRune('&')
			}
		} else {
			sb.WriteRune('=')
		}
		sb.WriteString(comp)

		// remember for the next iteration that we just wrote a value,
		// which means the next iteration MUST write a key
		wroteVal = ampIsNext
	}

	return sb.String()
}

// trimPathPrefix is like strings.TrimPrefix, but customized for advanced URI
// path prefix matching. The string prefix will be trimmed from the beginning
// of escapedPath if escapedPath starts with prefix. Rather than a naive 1:1
// comparison of each byte to determine if escapedPath starts with prefix,
// literal patterns are compared as decoded Unicode. If prefix uses a '%'
// encoding, escapedPath must use the same representation at that position.
func trimPathPrefix(escapedPath, prefix string) string {
	iPath := 0
	for _, token := range pathPatternTokens(prefix) {
		if token.escaped {
			if len(escapedPath)-iPath < len(token.value) ||
				!strings.EqualFold(escapedPath[iPath:iPath+len(token.value)], token.value) {
				return escapedPath
			}
			iPath += len(token.value)
			continue
		}

		consumed, ok := matchEscapedPrefix(escapedPath[iPath:], token.value)
		if !ok {
			return escapedPath
		}
		iPath += consumed
	}
	return escapedPath[iPath:]
}

// trimPathSuffix is the suffix counterpart of trimPathPrefix: it trims suffix
// from the end of escapedPath using the same decoded and escaped comparison
// semantics.
func trimPathSuffix(escapedPath, suffix string) string {
	iPath := len(escapedPath)
	tokens := pathPatternTokens(suffix)
	for i := len(tokens) - 1; i >= 0; i-- {
		token := tokens[i]
		if token.escaped {
			if iPath < len(token.value) ||
				!strings.EqualFold(escapedPath[iPath-len(token.value):iPath], token.value) {
				return escapedPath
			}
			iPath -= len(token.value)
			continue
		}

		start, ok := matchEscapedSuffix(escapedPath[:iPath], token.value)
		if !ok {
			return escapedPath
		}
		iPath = start
	}
	return escapedPath[:iPath]
}

type pathPatternToken struct {
	value   string
	escaped bool
}

func pathPatternTokens(pattern string) []pathPatternToken {
	var tokens []pathPatternToken
	for len(pattern) > 0 {
		if pattern[0] == '%' {
			length := 1
			if len(pattern) >= 3 {
				if decoded, err := url.PathUnescape(pattern[:3]); err == nil && len(decoded) == 1 {
					length = 3
				}
			}
			tokens = append(tokens, pathPatternToken{value: pattern[:length], escaped: true})
			pattern = pattern[length:]
			continue
		}

		end := strings.IndexByte(pattern, '%')
		if end < 0 {
			end = len(pattern)
		}
		tokens = append(tokens, pathPatternToken{value: pattern[:end]})
		pattern = pattern[end:]
	}
	return tokens
}

func matchEscapedPrefix(escapedPath, literal string) (int, bool) {
	iPath := 0
	for len(literal) > 0 {
		patternRune, patternSize := utf8.DecodeRuneInString(literal)
		patternValid := patternRune != utf8.RuneError || patternSize > 1
		if !patternValid {
			patternRune = rune(literal[0])
			pathByte, pathSize := nextEscapedByte(escapedPath[iPath:])
			if pathSize == 0 || !asciiEqualFold(pathByte, byte(patternRune)) {
				return 0, false
			}
			iPath += pathSize
			literal = literal[patternSize:]
			continue
		}

		pathRune, pathSize, pathValid := nextEscapedRune(escapedPath[iPath:])
		if pathSize == 0 || !equalPathRune(pathRune, pathValid, patternRune, patternValid) {
			return 0, false
		}
		iPath += pathSize
		literal = literal[patternSize:]
	}
	return iPath, true
}

func matchEscapedSuffix(escapedPath, literal string) (int, bool) {
	iPath := len(escapedPath)
	for len(literal) > 0 {
		patternRune, patternSize := utf8.DecodeLastRuneInString(literal)
		patternValid := patternRune != utf8.RuneError || patternSize > 1
		if !patternValid {
			patternRune = rune(literal[len(literal)-1])
			pathByte, pathStart := prevEscapedByte(escapedPath[:iPath])
			if pathStart == iPath || !asciiEqualFold(pathByte, byte(patternRune)) {
				return 0, false
			}
			iPath = pathStart
			literal = literal[:len(literal)-patternSize]
			continue
		}

		pathRune, pathStart, pathValid := prevEscapedRune(escapedPath[:iPath])
		if pathStart == iPath || !equalPathRune(pathRune, pathValid, patternRune, patternValid) {
			return 0, false
		}
		iPath = pathStart
		literal = literal[:len(literal)-patternSize]
	}
	return iPath, true
}

func nextEscapedRune(s string) (rune, int, bool) {
	var decoded [utf8.UTFMax]byte
	var rawEnds [utf8.UTFMax]int
	rawPos := 0
	for i := range decoded {
		b, size := nextEscapedByte(s[rawPos:])
		if size == 0 {
			break
		}
		decoded[i] = b
		rawPos += size
		rawEnds[i] = rawPos
		r, runeSize := utf8.DecodeRune(decoded[:i+1])
		if runeSize == i+1 && (r != utf8.RuneError || runeSize > 1) {
			return r, rawEnds[runeSize-1], true
		}
	}
	b, size := nextEscapedByte(s)
	return rune(b), size, false
}

func prevEscapedRune(s string) (rune, int, bool) {
	var decoded [utf8.UTFMax]byte
	end := len(s)
	for count := 1; count <= len(decoded); count++ {
		b, start := prevEscapedByte(s[:end])
		if start == end {
			break
		}
		decoded[len(decoded)-count] = b
		end = start
		candidate := decoded[len(decoded)-count:]
		r, size := utf8.DecodeRune(candidate)
		if size == count && (r != utf8.RuneError || size > 1) {
			return r, end, true
		}
	}
	b, start := prevEscapedByte(s)
	return rune(b), start, false
}

func nextEscapedByte(s string) (byte, int) {
	if len(s) >= 3 && s[0] == '%' {
		if decoded, err := url.PathUnescape(s[:3]); err == nil && len(decoded) == 1 {
			return decoded[0], 3
		}
	}
	if len(s) == 0 {
		return 0, 0
	}
	return s[0], 1
}

func prevEscapedByte(s string) (byte, int) {
	if len(s) >= 3 && s[len(s)-3] == '%' {
		if decoded, err := url.PathUnescape(s[len(s)-3:]); err == nil && len(decoded) == 1 {
			return decoded[0], len(s) - 3
		}
	}
	if len(s) == 0 {
		return 0, 0
	}
	return s[len(s)-1], len(s) - 1
}

func equalPathRune(a rune, aValid bool, b rune, bValid bool) bool {
	if aValid && bValid {
		return unicode.ToLower(a) == unicode.ToLower(b)
	}
	if aValid != bValid || a > 0xff || b > 0xff {
		return false
	}
	return asciiEqualFold(byte(a), byte(b))
}

func asciiEqualFold(a, b byte) bool {
	if 'A' <= a && a <= 'Z' {
		a += 'a' - 'A'
	}
	if 'A' <= b && b <= 'Z' {
		b += 'a' - 'A'
	}
	return a == b
}

// substrReplacer describes either a simple and fast substring replacement.
type substrReplacer struct {
	// A substring to find. Supports placeholders.
	Find string `json:"find,omitempty"`

	// The substring to replace with. Supports placeholders.
	Replace string `json:"replace,omitempty"`

	// Maximum number of replacements per string.
	// Set to <= 0 for no limit (default).
	Limit int `json:"limit,omitempty"`
}

// do performs the substring replacement on r.
func (rep substrReplacer) do(r *http.Request, repl *caddy.Replacer) {
	if rep.Find == "" {
		return
	}

	lim := rep.Limit
	if lim == 0 {
		lim = -1
	}

	find := repl.ReplaceAll(rep.Find, "")
	replace := repl.ReplaceAll(rep.Replace, "")

	mergeSlashes := !strings.Contains(rep.Find, "//")

	changePath(r, func(pathOrRawPath string) string {
		return strings.Replace(caddyhttp.CleanPath(pathOrRawPath, mergeSlashes), find, replace, lim)
	})

	r.URL.RawQuery = strings.Replace(r.URL.RawQuery, find, replace, lim)
}

// regexReplacer describes a replacement using a regular expression.
type regexReplacer struct {
	// The regular expression to find.
	Find string `json:"find,omitempty"`

	// The substring to replace with. Supports placeholders and
	// regular expression capture groups.
	Replace string `json:"replace,omitempty"`

	re *regexp.Regexp
}

func (rep regexReplacer) do(r *http.Request, repl *caddy.Replacer) {
	if rep.Find == "" || rep.re == nil {
		return
	}
	replace := repl.ReplaceAll(rep.Replace, "")
	changePath(r, func(pathOrRawPath string) string {
		return rep.re.ReplaceAllString(pathOrRawPath, replace)
	})
}

func changePath(req *http.Request, newVal func(pathOrRawPath string) string) {
	req.URL.RawPath = newVal(req.URL.EscapedPath())
	if p, err := url.PathUnescape(req.URL.RawPath); err == nil && p != "" {
		req.URL.Path = p
	} else {
		req.URL.Path = newVal(req.URL.Path)
	}
	// RawPath is only needed if it is a valid, non-canonical encoding of Path;
	// (see #6578). Mirror net/url.URL.setPath by comparing against the default
	// escaping of Path instead.
	if req.URL.RawPath == defaultEscapedPath(req.URL.Path) {
		req.URL.RawPath = ""
	}
}

// canonicalizePath anchors and cleans a stripped origin-form path while
// preserving an alternate RawPath encoding when it still represents the
// canonical Path. It is applied after prefix or suffix removal because stripping can
// expose a relative path or dot segments that downstream handlers interpret
// differently.
func canonicalizePath(req *http.Request) {
	p := req.URL.Path
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	cleaned := caddyhttp.CleanPath(defaultEscapedPath(p), false)
	p, _ = url.PathUnescape(cleaned) // defaultEscapedPath always returns valid escapes

	rawPath := req.URL.RawPath
	if rawPath != "" {
		if !strings.HasPrefix(rawPath, "/") {
			rawPath = "/" + rawPath
		}
		decoded, err := url.PathUnescape(rawPath)
		if err != nil || decoded != p || rawPath == defaultEscapedPath(p) {
			rawPath = ""
		}
	}

	req.URL.Path = p
	req.URL.RawPath = rawPath
}

// defaultEscapedPath returns the canonical percent-encoding of p, matching
// what net/url.URL.EscapedPath() produces when RawPath is empty. It mirrors
// the comparison net/url.URL.setPath uses to decide whether RawPath is needed.
func defaultEscapedPath(p string) string {
	return (&url.URL{Path: p}).EscapedPath()
}

// queryOps describes the operations to perform on query keys: add, set, rename and delete.
type queryOps struct {
	// Renames a query key from Key to Val, without affecting the value.
	Rename []queryOpsArguments `json:"rename,omitempty"`

	// Sets query parameters; overwrites a query key with the given value.
	Set []queryOpsArguments `json:"set,omitempty"`

	// Adds query parameters; does not overwrite an existing query field,
	// and only appends an additional value for that key if any already exist.
	Add []queryOpsArguments `json:"add,omitempty"`

	// Replaces query parameters.
	Replace []*queryOpsReplacement `json:"replace,omitempty"`

	// Deletes a given query key by name.
	Delete []string `json:"delete,omitempty"`
}

// Provision compiles the query replace operation regex.
func (replacement *queryOpsReplacement) Provision(_ caddy.Context) error {
	if replacement.SearchRegexp != "" {
		re, err := regexp.Compile(replacement.SearchRegexp)
		if err != nil {
			return fmt.Errorf("replacement for query field '%s': %v", replacement.Key, err)
		}
		replacement.re = re
	}
	return nil
}

func (q *queryOps) do(r *http.Request, repl *caddy.Replacer) {
	query := r.URL.Query()
	for _, renameParam := range q.Rename {
		key := repl.ReplaceAll(renameParam.Key, "")
		val := repl.ReplaceAll(renameParam.Val, "")
		if key == "" || val == "" {
			continue
		}
		if key == val {
			continue
		}
		originalValues, ok := query[key]
		if !ok {
			continue
		}
		query[val] = originalValues
		delete(query, key)
	}

	for _, setParam := range q.Set {
		key := repl.ReplaceAll(setParam.Key, "")
		if key == "" {
			continue
		}
		val := repl.ReplaceAll(setParam.Val, "")
		query[key] = []string{val}
	}

	for _, addParam := range q.Add {
		key := repl.ReplaceAll(addParam.Key, "")
		if key == "" {
			continue
		}
		val := repl.ReplaceAll(addParam.Val, "")
		query[key] = append(query[key], val)
	}

	for _, replaceParam := range q.Replace {
		key := repl.ReplaceAll(replaceParam.Key, "")
		search := repl.ReplaceKnown(replaceParam.Search, "")
		replace := repl.ReplaceKnown(replaceParam.Replace, "")

		// replace all query keys...
		if key == "*" {
			for fieldName, vals := range query {
				for i := range vals {
					if replaceParam.re != nil {
						query[fieldName][i] = replaceParam.re.ReplaceAllString(query[fieldName][i], replace)
					} else {
						query[fieldName][i] = strings.ReplaceAll(query[fieldName][i], search, replace)
					}
				}
			}
			continue
		}

		vals, ok := query[key]
		if !ok {
			continue
		}
		for i := range vals {
			if replaceParam.re != nil {
				query[key][i] = replaceParam.re.ReplaceAllString(query[key][i], replace)
			} else {
				query[key][i] = strings.ReplaceAll(query[key][i], search, replace)
			}
		}
	}

	for _, deleteParam := range q.Delete {
		param := repl.ReplaceAll(deleteParam, "")
		if param == "" {
			continue
		}
		delete(query, param)
	}

	r.URL.RawQuery = query.Encode()
}

type queryOpsArguments struct {
	// A key in the query string. Note that query string keys may appear multiple times.
	Key string `json:"key,omitempty"`

	// The value for the given operation; for add and set, this is
	// simply the value of the query, and for rename this is the
	// query key to rename to.
	Val string `json:"val,omitempty"`
}

type queryOpsReplacement struct {
	// The key to replace in the query string.
	Key string `json:"key,omitempty"`

	// The substring to search for.
	Search string `json:"search,omitempty"`

	// The regular expression to search with.
	SearchRegexp string `json:"search_regexp,omitempty"`

	// The string with which to replace matches.
	Replace string `json:"replace,omitempty"`

	re *regexp.Regexp
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*Rewrite)(nil)
