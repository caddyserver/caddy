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
)

func init() {
	caddy.RegisterModule(Rewrite{})
}

// Rewrite is a middleware which can rewrite HTTP requests.
type Rewrite struct {
	Method string `json:"method,omitempty"`
	URI    string `json:"uri,omitempty"`

	StripPathPrefix string `json:"strip_path_prefix,omitempty"`
	StripPathSuffix string `json:"strip_path_suffix,omitempty"`

	HTTPRedirect caddyhttp.WeakString `json:"http_redirect,omitempty"`
	Rehandle     bool                 `json:"rehandle,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Rewrite) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.rewrite",
		New:  func() caddy.Module { return new(Rewrite) },
	}
}

// Validate ensures rewr's configuration is valid.
func (rewr Rewrite) Validate() error {
	if rewr.HTTPRedirect != "" && rewr.Rehandle {
		return fmt.Errorf("cannot be configured to both write a redirect response and rehandle internally")
	}
	return nil
}

func (rewr Rewrite) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)
	var changed bool

	// rewrite the method
	if rewr.Method != "" {
		method := r.Method
		r.Method = strings.ToUpper(repl.ReplaceAll(rewr.Method, ""))
		if r.Method != method {
			changed = true
		}
	}

	// rewrite the URI
	if rewr.URI != "" {
		oldURI := r.RequestURI
		newURI := repl.ReplaceAll(rewr.URI, "")

		u, err := url.Parse(newURI)
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}

		r.RequestURI = newURI
		r.URL.Path = u.Path
		if u.RawQuery != "" {
			r.URL.RawQuery = u.RawQuery
		}
		if u.Fragment != "" {
			r.URL.Fragment = u.Fragment
		}

		if newURI != oldURI {
			changed = true
		}
	}

	// strip path prefix or suffix
	if rewr.StripPathPrefix != "" {
		prefix := repl.ReplaceAll(rewr.StripPathPrefix, "")
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
		newURI := r.URL.String()
		if newURI != r.RequestURI {
			changed = true
		}
		r.RequestURI = newURI
	}
	if rewr.StripPathSuffix != "" {
		suffix := repl.ReplaceAll(rewr.StripPathSuffix, "")
		r.URL.Path = strings.TrimSuffix(r.URL.Path, suffix)
		newURI := r.URL.String()
		if newURI != r.RequestURI {
			changed = true
		}
		r.RequestURI = newURI
	}

	if changed && rewr.Rehandle {
		return caddyhttp.ErrRehandle
	}

	if changed && rewr.HTTPRedirect != "" {
		statusCode, err := strconv.Atoi(repl.ReplaceAll(rewr.HTTPRedirect.String(), ""))
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		w.Header().Set("Location", r.RequestURI)
		w.WriteHeader(statusCode)
		return nil
	}

	return next.ServeHTTP(w, r)
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*Rewrite)(nil)
