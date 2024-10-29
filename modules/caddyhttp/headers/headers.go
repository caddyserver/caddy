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

// Handler is a middleware which modifies request and response headers.
//
// Changes to headers are applied immediately, except for the response
// headers when Deferred is true or when Required is set. In those cases,
// the changes are applied when the headers are written to the response.
// Note that deferred changes do not take effect if an error occurs later
// in the middleware chain.
//
// Properties in this module accept placeholders.
//
// Response header operations can be conditioned upon response status code
// and/or other header values.
type Handler struct {
	Request  *HeaderOps     `json:"request,omitempty"`
	Response *RespHeaderOps `json:"response,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.headers",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up h's configuration.
func (h *Handler) Provision(ctx caddy.Context) error {
	if h.Request != nil {
		err := h.Request.Provision(ctx)
		if err != nil {
			return err
		}
	}
	if h.Response != nil {
		err := h.Response.Provision(ctx)
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
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	if h.Request != nil {
		h.Request.ApplyToRequest(r)
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
			h.Response.ApplyTo(w.Header(), repl)
		}
	}

	return next.ServeHTTP(w, r)
}

// HeaderOps defines manipulations for HTTP headers.
type HeaderOps struct {
	// Adds HTTP headers; does not replace any existing header fields.
	Add http.Header `json:"add,omitempty"`

	// Sets HTTP headers; replaces existing header fields.
	Set http.Header `json:"set,omitempty"`

	// Names of HTTP header fields to delete. Basic wildcards are supported:
	//
	// - Start with `*` for all field names with the given suffix;
	// - End with `*` for all field names with the given prefix;
	// - Start and end with `*` for all field names containing a substring.
	Delete []string `json:"delete,omitempty"`

	// Performs in-situ substring replacements of HTTP headers.
	// Keys are the field names on which to perform the associated replacements.
	// If the field name is `*`, the replacements are performed on all header fields.
	Replace map[string][]Replacement `json:"replace,omitempty"`
}

// Provision sets up the header operations.
func (ops *HeaderOps) Provision(_ caddy.Context) error {
	for fieldName, replacements := range ops.Replace {
		for i, r := range replacements {
			if r.SearchRegexp == "" {
				continue
			}
			re, err := regexp.Compile(r.SearchRegexp)
			if err != nil {
				return fmt.Errorf("replacement %d for header field '%s': %v", i, fieldName, err)
			}
			replacements[i].re = re
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
// either a simple and fast substring search
// or a slower but more powerful regex search.
type Replacement struct {
	// The substring to search for.
	Search string `json:"search,omitempty"`

	// The regular expression to search with.
	SearchRegexp string `json:"search_regexp,omitempty"`

	// The string with which to replace matches.
	Replace string `json:"replace,omitempty"`

	re *regexp.Regexp
}

// RespHeaderOps defines manipulations for response headers.
type RespHeaderOps struct {
	*HeaderOps

	// If set, header operations will be deferred until
	// they are written out and only performed if the
	// response matches these criteria.
	Require *caddyhttp.ResponseMatcher `json:"require,omitempty"`

	// If true, header operations will be deferred until
	// they are written out. Superseded if Require is set.
	// Usually you will need to set this to true if any
	// fields are being deleted.
	Deferred bool `json:"deferred,omitempty"`
}

// ApplyTo applies ops to hdr using repl.
func (ops HeaderOps) ApplyTo(hdr http.Header, repl *caddy.Replacer) {
	// before manipulating headers in other ways, check if there
	// is configuration to delete all headers, and do that first
	// because if a header is to be added, we don't want to delete
	// it also
	for _, fieldName := range ops.Delete {
		fieldName = repl.ReplaceKnown(fieldName, "")
		if fieldName == "*" {
			clear(hdr)
		}
	}

	// add
	for fieldName, vals := range ops.Add {
		fieldName = repl.ReplaceKnown(fieldName, "")
		for _, v := range vals {
			hdr.Add(fieldName, repl.ReplaceKnown(v, ""))
		}
	}

	// set
	for fieldName, vals := range ops.Set {
		fieldName = repl.ReplaceKnown(fieldName, "")
		var newVals []string
		for i := range vals {
			// append to new slice so we don't overwrite
			// the original values in ops.Set
			newVals = append(newVals, repl.ReplaceKnown(vals[i], ""))
		}
		hdr.Set(fieldName, strings.Join(newVals, ","))
	}

	// delete
	for _, fieldName := range ops.Delete {
		fieldName = strings.ToLower(repl.ReplaceKnown(fieldName, ""))
		if fieldName == "*" {
			continue // handled above
		}
		switch {
		case strings.HasPrefix(fieldName, "*") && strings.HasSuffix(fieldName, "*"):
			for existingField := range hdr {
				if strings.Contains(strings.ToLower(existingField), fieldName[1:len(fieldName)-1]) {
					delete(hdr, existingField)
				}
			}
		case strings.HasPrefix(fieldName, "*"):
			for existingField := range hdr {
				if strings.HasSuffix(strings.ToLower(existingField), fieldName[1:]) {
					delete(hdr, existingField)
				}
			}
		case strings.HasSuffix(fieldName, "*"):
			for existingField := range hdr {
				if strings.HasPrefix(strings.ToLower(existingField), fieldName[:len(fieldName)-1]) {
					delete(hdr, existingField)
				}
			}
		default:
			hdr.Del(fieldName)
		}
	}

	// replace
	for fieldName, replacements := range ops.Replace {
		fieldName = http.CanonicalHeaderKey(repl.ReplaceKnown(fieldName, ""))

		// all fields...
		if fieldName == "*" {
			for _, r := range replacements {
				search := repl.ReplaceKnown(r.Search, "")
				replace := repl.ReplaceKnown(r.Replace, "")
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

		// ...or only with the named field
		for _, r := range replacements {
			search := repl.ReplaceKnown(r.Search, "")
			replace := repl.ReplaceKnown(r.Replace, "")
			for hdrFieldName, vals := range hdr {
				// see issue #4330 for why we don't simply use hdr[fieldName]
				if http.CanonicalHeaderKey(hdrFieldName) != fieldName {
					continue
				}
				for i := range vals {
					if r.re != nil {
						hdr[hdrFieldName][i] = r.re.ReplaceAllString(hdr[hdrFieldName][i], replace)
					} else {
						hdr[hdrFieldName][i] = strings.ReplaceAll(hdr[hdrFieldName][i], search, replace)
					}
				}
			}
		}
	}
}

// ApplyToRequest applies ops to r, specially handling the Host
// header which the standard library does not include with the
// header map with all the others. This method mutates r.Host.
func (ops HeaderOps) ApplyToRequest(r *http.Request) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// capture the current Host header so we can
	// reset to it when we're done
	origHost, hadHost := r.Header["Host"]

	// append r.Host; this way, we know that our value
	// was last in the list, and if an Add operation
	// appended something else after it, that's probably
	// fine because it's weird to have multiple Host
	// headers anyway and presumably the one they added
	// is the one they wanted
	r.Header["Host"] = append(r.Header["Host"], r.Host)

	// apply header operations
	ops.ApplyTo(r.Header, repl)

	// retrieve the last Host value (likely the one we appended)
	if len(r.Header["Host"]) > 0 {
		r.Host = r.Header["Host"][len(r.Header["Host"])-1]
	} else {
		r.Host = ""
	}

	// reset the Host header slice
	if hadHost {
		r.Header["Host"] = origHost
	} else {
		delete(r.Header, "Host")
	}
}

// responseWriterWrapper defers response header
// operations until WriteHeader is called.
type responseWriterWrapper struct {
	*caddyhttp.ResponseWriterWrapper
	replacer    *caddy.Replacer
	require     *caddyhttp.ResponseMatcher
	headerOps   *HeaderOps
	wroteHeader bool
}

func (rww *responseWriterWrapper) WriteHeader(status int) {
	if rww.wroteHeader {
		return
	}
	// 1xx responses aren't final; just informational
	if status < 100 || status > 199 {
		rww.wroteHeader = true
	}
	if rww.require == nil || rww.require.Match(status, rww.ResponseWriterWrapper.Header()) {
		if rww.headerOps != nil {
			rww.headerOps.ApplyTo(rww.ResponseWriterWrapper.Header(), rww.replacer)
		}
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
	_ http.ResponseWriter         = (*responseWriterWrapper)(nil)
)
