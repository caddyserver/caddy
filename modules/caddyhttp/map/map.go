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

package maphandler

import (
	"net/http"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is a middleware that maps a source placeholder to a destination
// placeholder.
//
// The mapping process happens early in the request handling lifecycle so that
// the Destination placeholder is calculated and available for substitution.
// The Items array contains pairs of regex expressions and values, the
// Source is matched against the expression, if they match then the destination
// placeholder is set to the value.
//
// The Default is optional, if no Item expression is matched then the value of
// the Default will be used.
//
type Handler struct {
	// Source is a placeholder
	Source string `json:"source,omitempty"`
	// Destination is a new placeholder
	Destination string `json:"destination,omitempty"`
	// Default is an optional value to use if no other was found
	Default string `json:"default,omitempty"`
	// Items is an array of regex expressions and values
	Items []Item `json:"items,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.map",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision will compile all regular expressions
func (h *Handler) Provision(_ caddy.Context) error {
	for i := 0; i < len(h.Items); i++ {
		h.Items[i].compiled = regexp.MustCompile(h.Items[i].Expression)
	}
	return nil
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// get the source value, if the source value was not found do no
	// replacement.
	val, ok := repl.GetString(h.Source)
	if ok {
		found := false
		for i := 0; i < len(h.Items); i++ {
			if h.Items[i].compiled.MatchString(val) {
				found = true
				repl.Set(h.Destination, h.Items[i].Value)
				break
			}
		}

		if !found && h.Default != "" {
			repl.Set(h.Destination, h.Default)
		}
	}
	return next.ServeHTTP(w, r)
}

// Item defines each entry in the map
type Item struct {
	// Expression is the regular expression searched for
	Expression string `json:"expression,omitempty"`
	// Value to use once the expression has been found
	Value string `json:"value,omitempty"`
	// compiled expression, internal use
	compiled *regexp.Regexp
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
