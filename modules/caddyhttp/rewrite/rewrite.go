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
// The Rehandle and HTTPRedirect properties are mutually exclusive
// (you cannot both rehandle and issue a redirect).
//
// These rewrite properties are applied to a request in this order:
// Method, URI, StripPathPrefix, StripPathSuffix, URISubstring.
//
// TODO: This module is still a WIP and may experience breaking changes.
type Rewrite struct {
	// Changes the request's HTTP verb.
	Method string `json:"method,omitempty"`

	// Changes the request's URI (path, query string, and fragment if present).
	// Only components of the URI that are specified will be changed.
	URI string `json:"uri,omitempty"`

	// Strips the given prefix from the beginning of the URI path.
	StripPathPrefix string `json:"strip_path_prefix,omitempty"`

	// Strips the given suffix from the end of the URI path.
	StripPathSuffix string `json:"strip_path_suffix,omitempty"`

	// Performs substring replacements on the URI.
	URISubstring []replacer `json:"uri_substring,omitempty"`

	// If set to a 3xx HTTP status code and if the URI was rewritten (changed),
	// the handler will issue a simple HTTP redirect to the new URI using the
	// given status code.
	HTTPRedirect caddyhttp.WeakString `json:"http_redirect,omitempty"`

	// If true, the request will sent for rehandling after rewriting
	// only if anything about the request was changed.
	Rehandle bool `json:"rehandle,omitempty"`

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

// Validate ensures rewr's configuration is valid.
func (rewr Rewrite) Validate() error {
	if rewr.HTTPRedirect != "" && rewr.Rehandle {
		return fmt.Errorf("cannot be configured to both redirect externally and rehandle internally")
	}
	return nil
}

func (rewr Rewrite) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)

	logger := rewr.logger.With(
		zap.Object("request", caddyhttp.LoggableHTTPRequest{Request: r}),
	)

	changed := rewr.rewrite(r, repl, logger)

	if changed {
		logger.Debug("rewrote request",
			zap.String("method", r.Method),
			zap.String("uri", r.RequestURI),
		)
		if rewr.Rehandle {
			return caddyhttp.ErrRehandle
		}
		if rewr.HTTPRedirect != "" {
			statusCode, err := strconv.Atoi(repl.ReplaceAll(rewr.HTTPRedirect.String(), ""))
			if err != nil {
				return caddyhttp.Error(http.StatusInternalServerError, err)
			}
			w.Header().Set("Location", r.RequestURI)
			w.WriteHeader(statusCode)
			return nil
		}
	}

	return next.ServeHTTP(w, r)
}

// rewrite performs the rewrites on r using repl, which
// should have been obtained from r, but is passed in for
// efficiency. It returns true if any changes were made to r.
func (rewr Rewrite) rewrite(r *http.Request, repl caddy.Replacer, logger *zap.Logger) bool {
	oldMethod := r.Method
	oldURI := r.RequestURI

	// method
	if rewr.Method != "" {
		r.Method = strings.ToUpper(repl.ReplaceAll(rewr.Method, ""))
	}

	// uri (which consists of path, query string, and maybe fragment?)
	if rewr.URI != "" {
		newURI := repl.ReplaceAll(rewr.URI, "")

		newU, err := url.Parse(newURI)
		if err != nil {
			logger.Error("parsing new URI",
				zap.String("raw_input", rewr.URI),
				zap.String("input", newURI),
				zap.Error(err),
			)
		}

		if newU.Path != "" {
			r.URL.Path = newU.Path
		}
		if strings.Contains(newURI, "?") {
			// you'll notice we check for existence of a question mark
			// instead of RawQuery != "". We do this because if the user
			// wants to remove an existing query string, they do that by
			// appending "?" to the path: "/foo?" -- in this case, then,
			// RawQuery is "" but we still want to set it to that; hence,
			// we check for a "?", which always starts a query string
			inputQuery := newU.Query()
			outputQuery := make(url.Values)
			for k := range inputQuery {
				// overwrite existing values; we don't simply keep
				// appending because it can cause rewrite rules like
				// "{path}{query}&a=b" with rehandling enabled to go
				// on forever: "/foo.html?a=b&a=b&a=b..."
				outputQuery.Set(k, inputQuery.Get(k))
			}
			// this sorts the keys, oh well
			r.URL.RawQuery = outputQuery.Encode()
		}
		if newU.Fragment != "" {
			r.URL.Fragment = newU.Fragment
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
func (rep replacer) do(r *http.Request, repl caddy.Replacer) bool {
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
