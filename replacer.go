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
	"time"
)

// Replacer can replace values in strings.
type Replacer interface {
	Set(variable, value string)
	Delete(variable string)
	Map(ReplacementFunc)
	ReplaceAll(input, empty string) string
}

// NewReplacer returns a new Replacer.
func NewReplacer() Replacer {
	rep := &replacer{
		static: make(map[string]string),
	}
	rep.providers = []ReplacementFunc{
		globalDefaultReplacements,
		rep.fromStatic,
	}
	return rep
}

type replacer struct {
	providers []ReplacementFunc
	static    map[string]string
}

// Map adds mapFunc to the list of value providers.
// mapFunc will be executed only at replace-time.
func (r *replacer) Map(mapFunc ReplacementFunc) {
	r.providers = append(r.providers, mapFunc)
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

// fromStatic provides values from r.static.
func (r *replacer) fromStatic(key string) (val string, ok bool) {
	val, ok = r.static[key]
	return
}

// ReplaceAll efficiently replaces placeholders in input with
// their values. Unrecognized placeholders will not be replaced.
// Values that are empty string will be substituted with empty.
func (r *replacer) ReplaceAll(input, empty string) string {
	if !strings.Contains(input, string(phOpen)) {
		return input
	}

	var sb strings.Builder

	// it is reasonable to assume that the output
	// will be approximately as long as the input
	sb.Grow(len(input))

	// iterate the input to find each placeholder
	var lastWriteCursor int
	for i := 0; i < len(input); i++ {
		if input[i] != phOpen {
			continue
		}

		// write the substring from the last cursor to this point
		sb.WriteString(input[lastWriteCursor:i])

		// find the end of the placeholder
		end := strings.Index(input[i:], string(phClose)) + i

		// trim opening bracket
		key := input[i+1 : end]

		// try to get a value for this key; if
		// the key is not recognized, do not
		// perform any replacement
		var found bool
		for _, mapFunc := range r.providers {
			if val, ok := mapFunc(key); ok {
				found = true
				if val != "" {
					sb.WriteString(val)
				} else if empty != "" {
					sb.WriteString(empty)
				}
				break
			}
		}
		if !found {
			lastWriteCursor = i
			continue
		}

		// advance cursor to end of placeholder
		i = end
		lastWriteCursor = i + 1
	}

	// flush any unwritten remainder
	sb.WriteString(input[lastWriteCursor:])

	return sb.String()
}

// ReplacementFunc is a function that returns a replacement
// for the given key along with true if the function is able
// to service that key (even if the value is blank). If the
// function does not recognize the key, false should be
// returned.
type ReplacementFunc func(key string) (val string, ok bool)

func globalDefaultReplacements(key string) (string, bool) {
	// check environment variable
	const envPrefix = "env."
	if strings.HasPrefix(key, envPrefix) {
		val := os.Getenv(key[len(envPrefix):])
		return val, val != ""
	}

	switch key {
	case "system.hostname":
		// OK if there is an error; just return empty string
		name, _ := os.Hostname()
		return name, true
	case "system.slash":
		return string(filepath.Separator), true
	case "system.os":
		return runtime.GOOS, true
	case "system.arch":
		return runtime.GOARCH, true
	case "time.now.common_log":
		return nowFunc().Format("02/Jan/2006:15:04:05 -0700"), true
	}

	return "", false
}

// nowFunc is a variable so tests can change it
// in order to obtain a deterministic time.
var nowFunc = time.Now

// ReplacerCtxKey is the context key for a replacer.
const ReplacerCtxKey CtxKey = "replacer"

const phOpen, phClose = '{', '}'
