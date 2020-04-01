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
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Rewrite{})
}

// Rewrite is a middleware which can rewrite HTTP requests.
//
// The Method and URI properties are "setters": the request URI
// will be set to the given values. Other properties are "modifiers":
// they modify existing files but do not explicitly specify what the
// result will be. It is atypical to combine the use of setters and
// modifiers in a single rewrite.
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
	StripPathPrefix string `json:"strip_path_prefix,omitempty"`

	// Strips the given suffix from the end of the URI path.
	StripPathSuffix string `json:"strip_path_suffix,omitempty"`

	// Performs substring replacements on the URI.
	URISubstring []replacer `json:"uri_substring,omitempty"`

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
	rewr.logger = ctx.Logger(rewr)
	return nil
}

func (rewr Rewrite) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	logger := rewr.logger.With(
		zap.Object("request", caddyhttp.LoggableHTTPRequest{Request: r}),
	)

	changed := rewr.rewrite(r, repl, logger)

	if changed {
		logger.Debug("rewrote request",
			zap.String("method", r.Method),
			zap.String("uri", r.RequestURI),
		)
	}

	return next.ServeHTTP(w, r)
}

// rewrite performs the rewrites on r using repl, which should
// have been obtained from r, but is passed in for efficiency.
// It returns true if any changes were made to r.
func (rewr Rewrite) rewrite(r *http.Request, repl *caddy.Replacer, logger *zap.Logger) bool {
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
		for i, ch := range uri {
			switch {
			case ch == '?' && qsStart < 0:
				pathEnd, qsStart = i, i+1
			case ch == '#' && fragStart < 0:
				qsEnd, fragStart = i, i+1
			case pathStart < 0 && qsStart < 0 && fragStart < 0:
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
			newPath = repl.ReplaceAll(path, "")
		}

		// before continuing, we need to check if a query string
		// snuck into the path component during replacements
		if quPos := strings.Index(newPath, "?"); quPos > -1 {
			// recompute; new path contains a query string
			var injectedQuery string
			newPath, injectedQuery = newPath[:quPos], newPath[quPos+1:]
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
			r.URL.Path = newPath
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
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
	}
	if rewr.StripPathSuffix != "" {
		suffix := repl.ReplaceAll(rewr.StripPathSuffix, "")
		r.URL.Path = strings.TrimSuffix(r.URL.Path, suffix)
	}

	// substring replacements in URI
	for _, rep := range rewr.URISubstring {
		rep.do(r, repl)
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
		comp, _ = repl.ReplaceFunc(comp, func(name string, val interface{}) (interface{}, error) {
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

// replacer describes a simple and fast substring replacement.
type replacer struct {
	// The substring to find. Supports placeholders.
	Find string `json:"find,omitempty"`

	// The substring to replace. Supports placeholders.
	Replace string `json:"replace,omitempty"`

	// Maximum number of replacements per string.
	// Set to <= 0 for no limit (default).
	Limit int `json:"limit,omitempty"`
}

// do performs the replacement on r and returns true if any changes were made.
func (rep replacer) do(r *http.Request, repl *caddy.Replacer) bool {
	if rep.Find == "" || rep.Replace == "" {
		return false
	}

	lim := rep.Limit
	if lim == 0 {
		lim = -1
	}

	find := repl.ReplaceAll(rep.Find, "")
	replace := repl.ReplaceAll(rep.Replace, "")

	oldPath := r.URL.Path
	oldQuery := r.URL.RawQuery

	r.URL.Path = strings.Replace(oldPath, find, replace, lim)
	r.URL.RawQuery = strings.Replace(oldQuery, find, replace, lim)

	return r.URL.Path != oldPath && r.URL.RawQuery != oldQuery
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*Rewrite)(nil)
