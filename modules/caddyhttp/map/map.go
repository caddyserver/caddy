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

package mmap

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler - Map
//
//
type Handler struct {
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Default     string `json:"default,omitempty"`
	Items       []Item `json:"items,omitempty"`
	internalMap map[interface{}]string
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.map",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision -
func (h *Handler) Provision(_ caddy.Context) error {
	h.internalMap = make(map[interface{}]string)
	return nil
}

// Validate ensures h's configuration is valid.
func (h Handler) Validate() error {

	//TODO: detect and compile regular expressions
	//TODO: organise a data structure to determine the order in which
	// the static keys and regular expressions can be deterministically
	// evaluated. Static keys first then regular expressions in order?
	// Or evaluated in order of appearance?

	// load the values
	for _, v := range h.Items {
		h.internalMap[v.Key] = v.Value
	}
	return nil
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// get the source value, if the source value was not found do no
	// replacement.
	//TODO: has the potential to miss changes in variables made later
	// in the request pipeline but perhaps that is a simplier mental
	// model to start with.
	val, ok := repl.Get(h.Source)
	if ok {
		lookup := func(key string) (interface{}, bool) {
			if v, ok := h.internalMap[val]; ok {
				return v, true
			}
			if h.Default != "" {
				return h.Default, true
			}
			return "", false
		}

		// add the lookup function
		repl.Map(lookup)
	}

	return next.ServeHTTP(w, r)
}

// Item defines manipulations for HTTP headers.
type Item struct {
	// Key
	Key string `json:"key,omitempty"`

	// Value
	Value string `json:"value,omitempty"`
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
