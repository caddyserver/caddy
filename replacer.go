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
	"fmt"
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
	ReplaceKnown(input, empty string) string
	ReplaceOrErr(input string, errOnEmpty, errOnUnknown bool) (string, error)
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

// ReplaceOrErr is like ReplaceAll, but any placeholders
// that are empty or not recognized will cause an error to
// be returned.
func (r *replacer) ReplaceOrErr(input string, errOnEmpty, errOnUnknown bool) (string, error) {
	return r.replace(input, "", false, errOnEmpty, errOnUnknown)
}

// ReplaceKnown is like ReplaceAll but only replaces
// placeholders that are known (recognized). Unrecognized
// placeholders will remain in the output.
func (r *replacer) ReplaceKnown(input, empty string) string {
	out, _ := r.replace(input, empty, false, false, false)
	return out
}

// ReplaceAll efficiently replaces placeholders in input with
// their values. All placeholders are replaced in the output
// whether they are recognized or not. Values that are empty
// string will be substituted with empty.
func (r *replacer) ReplaceAll(input, empty string) string {
	out, _ := r.replace(input, empty, true, false, false)
	return out
}

func (r *replacer) replace(input, empty string,
	treatUnknownAsEmpty, errOnEmpty, errOnUnknown bool) (string, error) {
	if !strings.Contains(input, string(phOpen)) {
		return input, nil
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

		// try to get a value for this key,
		// handle empty values accordingly
		var found bool
		for _, mapFunc := range r.providers {
			if val, ok := mapFunc(key); ok {
				found = true
				if val == "" {
					if errOnEmpty {
						return "", fmt.Errorf("evaluated placeholder %s%s%s is empty",
							string(phOpen), key, string(phClose))
					} else if empty != "" {
						sb.WriteString(empty)
					}
				} else {
					sb.WriteString(val)
				}
				break
			}
		}
		if !found {
			// placeholder is unknown (unrecognized), handle accordingly
			switch {
			case errOnUnknown:
				return "", fmt.Errorf("unrecognized placeholder %s%s%s",
					string(phOpen), key, string(phClose))
			case treatUnknownAsEmpty:
				if empty != "" {
					sb.WriteString(empty)
				}
			default:
				lastWriteCursor = i
				continue
			}
		}

		// advance cursor to end of placeholder
		i = end
		lastWriteCursor = i + 1
	}

	// flush any unwritten remainder
	sb.WriteString(input[lastWriteCursor:])

	return sb.String(), nil
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
		return os.Getenv(key[len(envPrefix):]), true
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
