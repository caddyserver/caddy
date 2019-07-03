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

package caddy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Replacer can replace values in strings.
type Replacer interface {
	Set(variable, value string)
	Delete(variable string)
	Map(func() map[string]string)
	ReplaceAll(input, empty string) string
}

// NewReplacer returns a new Replacer.
func NewReplacer() Replacer {
	rep := &replacer{
		static: make(map[string]string),
	}
	rep.providers = []ReplacementsFunc{
		defaultReplacements,
		func() map[string]string { return rep.static },
	}
	return rep
}

type replacer struct {
	providers []ReplacementsFunc
	static    map[string]string
}

// Map augments the map of replacements with those returned
// by the given replacements function. The function is only
// executed at replace-time.
func (r *replacer) Map(replacements func() map[string]string) {
	r.providers = append(r.providers, replacements)
}

// Set sets a custom variable to a static value.
func (r *replacer) Set(variable, value string) {
	r.static[variable] = value
}

// Delete removes a variable with a static value
// that was created using Set.
func (r *replacer) Delete(variable string) {
	delete(r.static, variable)
}

// ReplaceAll replaces placeholders in input with their values.
// Values that are empty string will be substituted with the
// empty parameter.
func (r *replacer) ReplaceAll(input, empty string) string {
	if !strings.Contains(input, phOpen) {
		return input
	}
	for _, replacements := range r.providers {
		for key, val := range replacements() {
			if val == "" {
				val = empty
			}
			input = strings.ReplaceAll(input, phOpen+key+phClose, val)
		}
	}
	return input
}

// ReplacementsFunc is a function that returns replacements,
// which is variable names mapped to their values. The
// function will be evaluated only at replace-time to ensure
// the most current values are mapped.
type ReplacementsFunc func() map[string]string

var defaultReplacements = func() map[string]string {
	m := map[string]string{
		"system.hostname": func() string {
			// OK if there is an error; just return empty string
			name, _ := os.Hostname()
			return name
		}(),
		"system.slash": string(filepath.Separator),
		"system.os":    runtime.GOOS,
		"system.arch":  runtime.GOARCH,
	}

	// add environment variables
	for _, keyval := range os.Environ() {
		parts := strings.SplitN(keyval, "=", 2)
		if len(parts) != 2 {
			continue
		}
		m["env."+strings.ToLower(parts[0])] = parts[1]
	}

	return m
}

// ReplacerCtxKey is the context key for a replacer.
const ReplacerCtxKey CtxKey = "replacer"

const phOpen, phClose = "{", "}"
