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
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.handlers.rewrite",
		New:  func() interface{} { return new(Rewrite) },
	})
}

// Rewrite is a middleware which can rewrite HTTP requests.
type Rewrite struct {
	Method   string `json:"method,omitempty"`
	URI      string `json:"uri,omitempty"`
	Rehandle bool   `json:"rehandle,omitempty"`
}

func (rewr Rewrite) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)
	var rehandleNeeded bool

	if rewr.Method != "" {
		method := r.Method
		r.Method = strings.ToUpper(repl.ReplaceAll(rewr.Method, ""))
		if r.Method != method {
			rehandleNeeded = true
		}
	}

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
			rehandleNeeded = true
		}
	}

	if rehandleNeeded && rewr.Rehandle {
		return caddyhttp.ErrRehandle
	}

	return next.ServeHTTP(w, r)
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*Rewrite)(nil)
