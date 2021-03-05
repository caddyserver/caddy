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

// Handler implements a middleware that maps inputs to outputs. Specifically, it
// compares a source value against the map inputs, and for one that matches, it
// applies the output values to each destination. Destinations become placeholder
// names.
//
// Mapped placeholders are not evaluated until they are used, so even for very
// large mappings, this handler is quite efficient.
type Handler struct {
	// Source is the placeholder from which to get the input value.
	Source string `json:"source,omitempty"`

	// Destinations are the names of placeholders in which to store the outputs.
	Destinations []string `json:"destinations,omitempty"`

	// Mappings from source values (inputs) to destination values (outputs).
	// The first matching, non-nil mapping will be applied.
	Mappings []Mapping `json:"mappings,omitempty"`

	// If no mappings match or if the mapped output is null/nil, the associated
	// default output will be applied (optional).
	Defaults []string `json:"defaults,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.map",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up h.
func (h *Handler) Provision(_ caddy.Context) error {
	for j, dest := range h.Destinations {
		h.Destinations[j] = strings.Trim(dest, "{}")
	}

	for i, m := range h.Mappings {
		if m.InputRegexp == "" {
			continue
		}
		var err error
		h.Mappings[i].re, err = regexp.Compile(m.InputRegexp)
		if err != nil {
			return fmt.Errorf("compiling regexp for mapping %d: %v", i, err)
		}
	}

	// TODO: improve efficiency even further by using an actual map type
	// for the non-regexp mappings, OR sort them and do a binary search

	return nil
}

// Validate ensures that h is configured properly.
func (h *Handler) Validate() error {
	nDest, nDef := len(h.Destinations), len(h.Defaults)
	if nDef > 0 && nDef != nDest {
		return fmt.Errorf("%d destinations != %d defaults", nDest, nDef)
	}

	seen := make(map[string]int)
	for i, m := range h.Mappings {
		// prevent confusing/ambiguous mappings
		if m.Input != "" && m.InputRegexp != "" {
			return fmt.Errorf("mapping %d has both input and input_regexp fields specified, which is confusing", i)
		}

		// prevent duplicate mappings
		input := m.Input
		if m.InputRegexp != "" {
			input = m.InputRegexp
		}
		if prev, ok := seen[input]; ok {
			return fmt.Errorf("mapping %d has a duplicate input '%s' previously used with mapping %d", i, input, prev)
		}
		seen[input] = i

		// ensure mappings have 1:1 output-to-destination correspondence
		nOut := len(m.Outputs)
		if nOut != nDest {
			return fmt.Errorf("mapping %d has %d outputs but there are %d destinations defined", i, nOut, nDest)
		}
	}
	return nil
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// defer work until a variable is actually evaluated by using replacer's Map callback
	repl.Map(func(key string) (interface{}, bool) {
		// return early if the variable is not even a configured destination
		destIdx := h.destinationIndex(key)
		if destIdx < 0 {
			return nil, false
		}

		input := repl.ReplaceAll(h.Source, "")

		// find the first mapping matching the input and return
		// the requested destination/output value
		for _, m := range h.Mappings {
			if m.re != nil {
				if m.re.MatchString(input) {
					if output := m.Outputs[destIdx]; output == nil {
						continue
					} else {
						output = m.re.ReplaceAllString(input, m.Outputs[destIdx].(string))
						return output, true
					}
				}
				continue
			}
			if input == m.Input {
				if output := m.Outputs[destIdx]; output == nil {
					continue
				} else {
					return output, true
				}
			}
		}

		// fall back to default if no match or if matched nil value
		if len(h.Defaults) > destIdx {
			return h.Defaults[destIdx], true
		}

		return nil, true
	})

	return next.ServeHTTP(w, r)
}

// destinationIndex returns the positional index of the destination
// is name is a known destination; otherwise it returns -1.
func (h Handler) destinationIndex(name string) int {
	for i, dest := range h.Destinations {
		if dest == name {
			return i
		}
	}
	return -1
}

// Mapping describes a mapping from input to outputs.
type Mapping struct {
	// The input value to match. Must be distinct from other mappings.
	// Mutually exclusive to input_regexp.
	Input string `json:"input,omitempty"`

	// The input regular expression to match. Mutually exclusive to input.
	InputRegexp string `json:"input_regexp,omitempty"`

	// Upon a match with the input, each output is positionally correlated
	// with each destination of the parent handler. An output that is null
	// (nil) will be treated as if it was not mapped at all.
	Outputs []interface{} `json:"outputs,omitempty"`

	re *regexp.Regexp
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
