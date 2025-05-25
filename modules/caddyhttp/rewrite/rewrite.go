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
			// replace the `path` placeholder to escaped path
			pathPlaceholder := "{http.request.uri.path}"
			if strings.Contains(path, pathPlaceholder) {
				path = strings.ReplaceAll(path, pathPlaceholder, r.URL.EscapedPath())
			}

			newPath = repl.ReplaceAll(path, "")
		}

		// before continuing, we need to check if a query string
		// snuck into the path component during replacements
		if before, after, found := strings.Cut(newPath, "?"); found {
			// recompute; new path contains a query string
			var injectedQuery string
			newPath, injectedQuery = before, after
			// don't overwrite explicitly-configured query string
			if query == "" {
				query = injectedQuery
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
		}
		if qsStart >= 0 {
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
		changePath(r, func(escapedPath string) string {
			escapedPath = caddyhttp.CleanPath(escapedPath, mergeSlashes)
			return trimPathPrefix(escapedPath, prefix)
		})
	}
	if rewr.StripPathSuffix != "" {
		suffix := repl.ReplaceAll(rewr.StripPathSuffix, "")
		mergeSlashes := !strings.Contains(suffix, "//")
		changePath(r, func(escapedPath string) string {
			escapedPath = caddyhttp.CleanPath(escapedPath, mergeSlashes)
			return reverse(trimPathPrefix(reverse(escapedPath), reverse(suffix)))
		})
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
// both strings are iterated in lock-step, and if prefix has a '%' encoding
// at a particular position, escapedPath must also have the same encoding
// representation for that character. In other words, if the prefix string
// uses the escaped form for a character, escapedPath must literally use the
// same escape at that position. Otherwise, all character comparisons are
// performed in normalized/unescaped space.
func trimPathPrefix(escapedPath, prefix string) string {
	var iPath, iPrefix int
	for {
		if iPath >= len(escapedPath) || iPrefix >= len(prefix) {
			break
		}

		prefixCh := prefix[iPrefix]
		ch := string(escapedPath[iPath])

		if ch == "%" && prefixCh != '%' && len(escapedPath) >= iPath+3 {
			var err error
			ch, err = url.PathUnescape(escapedPath[iPath : iPath+3])
			if err != nil {
				// should be impossible unless EscapedPath() is returning invalid values!
				return escapedPath
			}
			iPath += 2
		}

		// prefix comparisons are case-insensitive to consistency with
		// path matcher, which is case-insensitive for good reasons
		if !strings.EqualFold(ch, string(prefixCh)) {
			return escapedPath
		}

		iPath++
		iPrefix++
	}

	// if we iterated through the entire prefix, we found it, so trim it
	if iPath >= len(prefix) {
		return escapedPath[iPath:]
	}

	// otherwise we did not find the prefix
	return escapedPath
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
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
	// RawPath is only set if it's different from the normalized Path (std lib)
	if req.URL.RawPath == req.URL.Path {
		req.URL.RawPath = ""
	}
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
		query[val] = query[key]
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

		for fieldName, vals := range query {
			for i := range vals {
				if replaceParam.re != nil {
					query[fieldName][i] = replaceParam.re.ReplaceAllString(query[fieldName][i], replace)
				} else {
					query[fieldName][i] = strings.ReplaceAll(query[fieldName][i], search, replace)
				}
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
