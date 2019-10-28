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
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Rewrite{})
}

// Rewrite is a middleware which can rewrite HTTP requests.
type Rewrite struct {
	Method   string `json:"method,omitempty"`
	URI      string `json:"uri,omitempty"`
	Rehandle bool   `json:"rehandle,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Rewrite) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.rewrite",
		New:  func() caddy.Module { return new(Rewrite) },
	}
}

// Provision sets up rewr.
func (rewr *Rewrite) Provision(ctx caddy.Context) error {
	rewr.logger = ctx.Logger(rewr)
	return nil
}

func (rewr Rewrite) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)
	var changed bool

	logger := rewr.logger.With(
		zap.Object("request", caddyhttp.LoggableHTTPRequest{Request: r}),
	)

	if rewr.Method != "" {
		method := r.Method
		r.Method = strings.ToUpper(repl.ReplaceAll(rewr.Method, ""))
		if r.Method != method {
			changed = true
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
			changed = true
		}
	}

	if changed {
		logger.Debug("rewrote request",
			zap.String("method", r.Method),
			zap.String("uri", r.RequestURI),
		)
		if rewr.Rehandle {
			return caddyhttp.ErrRehandle
		}
	}

	return next.ServeHTTP(w, r)
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*Rewrite)(nil)
