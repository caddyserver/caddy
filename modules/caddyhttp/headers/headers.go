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

package headers

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a middleware which can mutate HTTP headers.
type Handler struct {
	Request  *HeaderOps     `json:"request,omitempty"`
	Response *RespHeaderOps `json:"response,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.headers",
		New:  func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up h's configuration.
func (h *Handler) Provision(_ caddy.Context) error {
	if h.Request != nil {
		err := h.Request.provision()
		if err != nil {
			return err
		}
	}
	if h.Response != nil {
		err := h.Response.provision()
		if err != nil {
			return err
		}
	}
	return nil
}

// Validate ensures h's configuration is valid.
func (h Handler) Validate() error {
	if h.Request != nil {
		err := h.Request.validate()
		if err != nil {
			return err
		}
	}
	if h.Response != nil {
		err := h.Response.validate()
		if err != nil {
			return err
		}
	}
	return nil
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)

	h.Request.applyTo(r.Header, repl)

	// request header's Host is handled specially by the
	// Go standard library, so if that header was changed,
	// change it in the Host field since the Header won't
	// be used
	if intendedHost := r.Header.Get("Host"); intendedHost != "" {
		r.Host = intendedHost
		r.Header.Del("Host")
	}

	if h.Response != nil {
		if h.Response.Deferred || h.Response.Require != nil {
			w = &responseWriterWrapper{
				ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
				replacer:              repl,
				require:               h.Response.Require,
				headerOps:             h.Response.HeaderOps,
			}
		} else {
			h.Response.applyTo(w.Header(), repl)
		}
	}

	return next.ServeHTTP(w, r)
}

// HeaderOps defines some operations to
// perform on HTTP headers.
type HeaderOps struct {
	Add     http.Header              `json:"add,omitempty"`
	Set     http.Header              `json:"set,omitempty"`
	Delete  []string                 `json:"delete,omitempty"`
	Replace map[string][]Replacement `json:"replace,omitempty"`
}

func (ops *HeaderOps) provision() error {
	for fieldName, replacements := range ops.Replace {
		for i, r := range replacements {
			if r.SearchRegexp != "" {
				re, err := regexp.Compile(r.SearchRegexp)
				if err != nil {
					return fmt.Errorf("replacement %d for header field '%s': %v", i, fieldName, err)
				}
				replacements[i].re = re
			}
		}
	}
	return nil
}

func (ops HeaderOps) validate() error {
	for fieldName, replacements := range ops.Replace {
		for _, r := range replacements {
			if r.Search != "" && r.SearchRegexp != "" {
				return fmt.Errorf("cannot specify both a substring search and a regular expression search for field '%s'", fieldName)
			}
		}
	}
	return nil
}

// Replacement describes a string replacement,
// either a simple and fast sugbstring search
// or a slower but more powerful regex search.
type Replacement struct {
	Search       string `json:"search,omitempty"`
	SearchRegexp string `json:"search_regexp,omitempty"`
	Replace      string `json:"replace,omitempty"`

	re *regexp.Regexp
}

// RespHeaderOps is like HeaderOps, but
// optionally deferred until response time.
type RespHeaderOps struct {
	*HeaderOps
	Require  *caddyhttp.ResponseMatcher `json:"require,omitempty"`
	Deferred bool                       `json:"deferred,omitempty"`
}

func (ops *HeaderOps) applyTo(hdr http.Header, repl caddy.Replacer) {
	if ops == nil {
		return
	}

	for fieldName, vals := range ops.Add {
		fieldName = repl.ReplaceAll(fieldName, "")
		for _, v := range vals {
			hdr.Add(fieldName, repl.ReplaceAll(v, ""))
		}
	}

	for fieldName, vals := range ops.Set {
		fieldName = repl.ReplaceAll(fieldName, "")
		for i := range vals {
			vals[i] = repl.ReplaceAll(vals[i], "")
		}
		hdr.Set(fieldName, strings.Join(vals, ","))
	}

	for _, fieldName := range ops.Delete {
		hdr.Del(repl.ReplaceAll(fieldName, ""))
	}

	for fieldName, replacements := range ops.Replace {
		fieldName = repl.ReplaceAll(fieldName, "")

		// perform replacements across all fields
		if fieldName == "*" {
			for _, r := range replacements {
				search := repl.ReplaceAll(r.Search, "")
				replace := repl.ReplaceAll(r.Replace, "")
				for fieldName, vals := range hdr {
					for i := range vals {
						if r.re != nil {
							hdr[fieldName][i] = r.re.ReplaceAllString(hdr[fieldName][i], replace)
						} else {
							hdr[fieldName][i] = strings.ReplaceAll(hdr[fieldName][i], search, replace)
						}
					}
				}
			}
			continue
		}

		// perform replacements only with the named field
		for _, r := range replacements {
			search := repl.ReplaceAll(r.Search, "")
			replace := repl.ReplaceAll(r.Replace, "")
			for i := range hdr[fieldName] {
				if r.re != nil {
					hdr[fieldName][i] = r.re.ReplaceAllString(hdr[fieldName][i], replace)
				} else {
					hdr[fieldName][i] = strings.ReplaceAll(hdr[fieldName][i], search, replace)
				}
			}
		}
	}
}

// responseWriterWrapper defers response header
// operations until WriteHeader is called.
type responseWriterWrapper struct {
	*caddyhttp.ResponseWriterWrapper
	replacer    caddy.Replacer
	require     *caddyhttp.ResponseMatcher
	headerOps   *HeaderOps
	wroteHeader bool
}

func (rww *responseWriterWrapper) WriteHeader(status int) {
	if rww.wroteHeader {
		return
	}
	rww.wroteHeader = true
	if rww.require == nil || rww.require.Match(status, rww.ResponseWriterWrapper.Header()) {
		rww.headerOps.applyTo(rww.ResponseWriterWrapper.Header(), rww.replacer)
	}
	rww.ResponseWriterWrapper.WriteHeader(status)
}

func (rww *responseWriterWrapper) Write(d []byte) (int, error) {
	if !rww.wroteHeader {
		rww.WriteHeader(http.StatusOK)
	}
	return rww.ResponseWriterWrapper.Write(d)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyhttp.HTTPInterfaces    = (*responseWriterWrapper)(nil)
)
