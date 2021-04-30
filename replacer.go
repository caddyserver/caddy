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
	"strconv"
	"strings"
	"time"
)

// NewReplacer returns a new Replacer.
func NewReplacer() *Replacer {
	rep := &Replacer{
		static: make(map[string]interface{}),
	}
	rep.providers = []ReplacerFunc{
		globalDefaultReplacements,
		rep.fromStatic,
	}
	return rep
}

// NewEmptyReplacer returns a new Replacer,
// without the global default replacements.
func NewEmptyReplacer() *Replacer {
	rep := &Replacer{
		static: make(map[string]interface{}),
	}
	rep.providers = []ReplacerFunc{
		rep.fromStatic,
	}
	return rep
}

// Replacer can replace values in strings.
// A default/empty Replacer is not valid;
// use NewReplacer to make one.
type Replacer struct {
	providers []ReplacerFunc
	static    map[string]interface{}
}

// Map adds mapFunc to the list of value providers.
// mapFunc will be executed only at replace-time.
func (r *Replacer) Map(mapFunc ReplacerFunc) {
	r.providers = append(r.providers, mapFunc)
}

// Set sets a custom variable to a static value.
func (r *Replacer) Set(variable string, value interface{}) {
	r.static[variable] = value
}

// Get gets a value from the replacer. It returns
// the value and whether the variable was known.
func (r *Replacer) Get(variable string) (interface{}, bool) {
	for _, mapFunc := range r.providers {
		if val, ok := mapFunc(variable); ok {
			return val, true
		}
	}
	return nil, false
}

// GetString  is the same as Get, but coerces the value to a
// string representation.
func (r *Replacer) GetString(variable string) (string, bool) {
	s, found := r.Get(variable)
	return toString(s), found
}

// Delete removes a variable with a static value
// that was created using Set.
func (r *Replacer) Delete(variable string) {
	delete(r.static, variable)
}

// fromStatic provides values from r.static.
func (r *Replacer) fromStatic(key string) (interface{}, bool) {
	val, ok := r.static[key]
	return val, ok
}

// ReplaceOrErr is like ReplaceAll, but any placeholders
// that are empty or not recognized will cause an error to
// be returned.
func (r *Replacer) ReplaceOrErr(input string, errOnEmpty, errOnUnknown bool) (string, error) {
	return r.replace(input, "", false, errOnEmpty, errOnUnknown, nil)
}

// ReplaceKnown is like ReplaceAll but only replaces
// placeholders that are known (recognized). Unrecognized
// placeholders will remain in the output.
func (r *Replacer) ReplaceKnown(input, empty string) string {
	out, _ := r.replace(input, empty, false, false, false, nil)
	return out
}

// ReplaceAll efficiently replaces placeholders in input with
// their values. All placeholders are replaced in the output
// whether they are recognized or not. Values that are empty
// string will be substituted with empty.
func (r *Replacer) ReplaceAll(input, empty string) string {
	out, _ := r.replace(input, empty, true, false, false, nil)
	return out
}

// ReplaceFunc is the same as ReplaceAll, but calls f for every
// replacement to be made, in case f wants to change or inspect
// the replacement.
func (r *Replacer) ReplaceFunc(input string, f ReplacementFunc) (string, error) {
	return r.replace(input, "", true, false, false, f)
}

func (r *Replacer) replace(input, empty string,
	treatUnknownAsEmpty, errOnEmpty, errOnUnknown bool,
	f ReplacementFunc) (string, error) {
	if !strings.Contains(input, string(phOpen)) {
		return input, nil
	}

	var sb strings.Builder

	// it is reasonable to assume that the output
	// will be approximately as long as the input
	sb.Grow(len(input))

	// iterate the input to find each placeholder
	var lastWriteCursor int

scan:
	for i := 0; i < len(input); i++ {

		// check for escaped braces
		if i > 0 && input[i-1] == phEscape && (input[i] == phClose || input[i] == phOpen) {
			sb.WriteString(input[lastWriteCursor : i-1])
			lastWriteCursor = i
			continue
		}

		if input[i] != phOpen {
			continue
		}

		// find the end of the placeholder
		end := strings.Index(input[i:], string(phClose)) + i
		if end < i {
			continue
		}

		// if necessary look for the first closing brace that is not escaped
		for end > 0 && end < len(input)-1 && input[end-1] == phEscape {
			nextEnd := strings.Index(input[end+1:], string(phClose))
			if nextEnd < 0 {
				continue scan
			}
			end += nextEnd + 1
		}

		// write the substring from the last cursor to this point
		sb.WriteString(input[lastWriteCursor:i])

		// trim opening bracket
		key := input[i+1 : end]

		// try to get a value for this key, handle empty values accordingly
		val, found := r.Get(key)
		if !found {
			// placeholder is unknown (unrecognized); handle accordingly
			if errOnUnknown {
				return "", fmt.Errorf("unrecognized placeholder %s%s%s",
					string(phOpen), key, string(phClose))
			} else if !treatUnknownAsEmpty {
				// if treatUnknownAsEmpty is true, we'll handle an empty
				// val later; so only continue otherwise
				lastWriteCursor = i
				continue
			}
		}

		// apply any transformations
		if f != nil {
			var err error
			val, err = f(key, val)
			if err != nil {
				return "", err
			}
		}

		// convert val to a string as efficiently as possible
		valStr := toString(val)

		// write the value; if it's empty, either return
		// an error or write a default value
		if valStr == "" {
			if errOnEmpty {
				return "", fmt.Errorf("evaluated placeholder %s%s%s is empty",
					string(phOpen), key, string(phClose))
			} else if empty != "" {
				sb.WriteString(empty)
			}
		} else {
			sb.WriteString(valStr)
		}

		// advance cursor to end of placeholder
		i = end
		lastWriteCursor = i + 1
	}

	// flush any unwritten remainder
	sb.WriteString(input[lastWriteCursor:])

	return sb.String(), nil
}

func toString(val interface{}) string {
	switch v := val.(type) {
	case nil:
		return ""
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case byte:
		return string(v)
	case []byte:
		return string(v)
	case []rune:
		return string(v)
	case int:
		return strconv.Itoa(v)
	case int32:
		return strconv.Itoa(int(v))
	case int64:
		return strconv.Itoa(int(v))
	case uint:
		return strconv.Itoa(int(v))
	case uint32:
		return strconv.Itoa(int(v))
	case uint64:
		return strconv.Itoa(int(v))
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%+v", v)
	}
}

// ReplacerFunc is a function that returns a replacement
// for the given key along with true if the function is able
// to service that key (even if the value is blank). If the
// function does not recognize the key, false should be
// returned.
type ReplacerFunc func(key string) (interface{}, bool)

func globalDefaultReplacements(key string) (interface{}, bool) {
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
	case "time.now":
		return nowFunc(), true
	case "time.now.common_log":
		return nowFunc().Format("02/Jan/2006:15:04:05 -0700"), true
	case "time.now.year":
		return strconv.Itoa(nowFunc().Year()), true
	}

	return nil, false
}

// ReplacementFunc is a function that is called when a
// replacement is being performed. It receives the
// variable (i.e. placeholder name) and the value that
// will be the replacement, and returns the value that
// will actually be the replacement, or an error. Note
// that errors are sometimes ignored by replacers.
type ReplacementFunc func(variable string, val interface{}) (interface{}, error)

// nowFunc is a variable so tests can change it
// in order to obtain a deterministic time.
var nowFunc = time.Now

// ReplacerCtxKey is the context key for a replacer.
const ReplacerCtxKey CtxKey = "replacer"

const phOpen, phClose, phEscape = '{', '}', '\\'
