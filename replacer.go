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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// NewReplacer returns a new Replacer.
func NewReplacer() *Replacer {
	rep := &Replacer{
		static: make(map[string]any),
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
		static: make(map[string]any),
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
	static    map[string]any
}

// Map adds mapFunc to the list of value providers.
// mapFunc will be executed only at replace-time.
func (r *Replacer) Map(mapFunc ReplacerFunc) {
	r.providers = append(r.providers, mapFunc)
}

// Set sets a custom variable to a static value.
func (r *Replacer) Set(variable string, value any) {
	r.static[variable] = value
}

// Get gets a value from the replacer. It returns
// the value and whether the variable was known.
func (r *Replacer) Get(variable string) (any, bool) {
	for _, mapFunc := range r.providers {
		if val, ok := mapFunc(variable); ok {
			return val, true
		}
	}
	return nil, false
}

// GetString is the same as Get, but coerces the value to a
// string representation as efficiently as possible.
func (r *Replacer) GetString(variable string) (string, bool) {
	s, found := r.Get(variable)
	return ToString(s), found
}

// Delete removes a variable with a static value
// that was created using Set.
func (r *Replacer) Delete(variable string) {
	delete(r.static, variable)
}

// fromStatic provides values from r.static.
func (r *Replacer) fromStatic(key string) (any, bool) {
	val, ok := r.static[key]
	return val, ok
}

// ReplaceOrErr is like ReplaceAll, but any placeholders
// that are empty or not recognized will cause an error to
// be returned.
func (r *Replacer) ReplaceOrErr(input string, errOnEmpty, errOnUnknown bool) (string, error) {
	out, _, err := r.replace(input, "", false, errOnEmpty, errOnUnknown, nil)
	return out, err
}

// ReplaceKnown is like ReplaceAll but only replaces
// placeholders that are known (recognized). Unrecognized
// placeholders will remain in the output.
func (r *Replacer) ReplaceKnown(input, empty string) string {
	out, _, _ := r.replace(input, empty, false, false, false, nil)
	return out
}

// ReplaceAll efficiently replaces placeholders in input with
// their values. All placeholders are replaced in the output
// whether they are recognized or not. Values that are empty
// string will be substituted with empty.
func (r *Replacer) ReplaceAll(input, empty string) string {
	out, _, _ := r.replace(input, empty, true, false, false, nil)
	return out
}

// ReplaceFunc is the same as ReplaceAll, but calls f for every
// replacement to be made, in case f wants to change or inspect
// the replacement.
func (r *Replacer) ReplaceFunc(input string, f ReplacementFunc) (string, error) {
	out, _, err := r.replace(input, "", true, false, false, f)
	return out, err
}

func (r *Replacer) replace(input, empty string, treatUnknownAsEmpty, errOnEmpty, errOnUnknown bool, f ReplacementFunc) (string, bool, error) {
	var result strings.Builder

	// it is reasonable to assume that the output will be approximately as long as the input
	result.Grow(len(input))
	allPlaceholdersFound := true

	// iterate the input to find each placeholder
	var lastWriteCursor int
	for placeholderStart := 0; placeholderStart < len(input); placeholderStart++ {
		switch input[placeholderStart] {
		case phOpen:
			// process possible placeholder in remaining loop (do not drop into default)
		case phEscape:
			// escape character at the end of the input or next character not a brace or escape character
			if placeholderStart+1 == len(input) || (input[placeholderStart+1] != phOpen && input[placeholderStart+1] != phClose && input[placeholderStart+1] != phEscape) {
				continue
			}
			// if there's anything to copy (until the escape character), do so
			if placeholderStart > lastWriteCursor {
				result.WriteString(input[lastWriteCursor:placeholderStart])
			}
			// skip handling escaped character, get it copied with the next special character
			placeholderStart++
			lastWriteCursor = placeholderStart
			continue
		default:
			// just copy anything else
			continue
		}

		// our iterator is now on an unescaped open brace (start of placeholder), find matching closing brace
		var placeholderEnd int
		bracesLevel := 0
		placeHolderEndFound := false
	placeholderEndScanner:
		for placeholderEnd = placeholderStart + 1; placeholderEnd < len(input); placeholderEnd++ {
			switch input[placeholderEnd] {
			case phOpen:
				bracesLevel++
			case phClose:
				if bracesLevel > 0 {
					bracesLevel--
					continue
				}
				placeHolderEndFound = true
				break placeholderEndScanner
			case phEscape:
				// skip escaped character
				placeholderEnd++
			default:
			}
		}
		// no matching closing brace found, this is not a complete placeholder, continue search
		if !placeHolderEndFound {
			continue
		}

		// write the substring from the last cursor to this point
		result.WriteString(input[lastWriteCursor:placeholderStart])

		// split to key and default (if exists), allowing for escaped colons
		var keyBuilder strings.Builder
		var key, defaultKey string
		// both key and defaultKey are bound to placeholder length
		keyBuilder.Grow(placeholderEnd - placeholderStart)
		defaultKeyExists := false
	keyScanner:
		for dividerScanner := placeholderStart + 1; dividerScanner < placeholderEnd; dividerScanner++ {
			switch input[dividerScanner] {
			case phColon:
				defaultKeyExists = true
				// default key will be parsed recursively
				defaultKey = input[dividerScanner+1 : placeholderEnd]
				break keyScanner
			case phEscape:
				// skip escape character, then copy escaped character
				dividerScanner++
				fallthrough
			default:
				keyBuilder.WriteByte(input[dividerScanner])
			}
		}
		key = keyBuilder.String()
		unescapedPlaceholder := key

		// try to get a value for this key, handle empty values accordingly
		val, found := r.Get(key)
		// try to replace with variable default, if one is defined; if key contains a quote, consider it JSON and do not apply defaulting
		if !found && defaultKeyExists && !strings.Contains(key, string(phQuote)) {
			var err error
			defaultVal, defaultFound, err := r.replace(defaultKey, empty, treatUnknownAsEmpty, errOnEmpty, errOnUnknown, f)
			if err != nil {
				return "", false, err
			}
			if !defaultFound {
				allPlaceholdersFound = false
				unescapedPlaceholder = unescapedPlaceholder + ":" + defaultVal
			} else {
				found = true
				val = defaultVal
			}
		}

		// if placeholder is still unknown (unrecognized); see if we need to error out or skip the placeholder
		if !found {
			if errOnUnknown {
				return "", false, fmt.Errorf("unrecognized placeholder %s%s%s",
					string(phOpen), key, string(phClose))
			}
			// move cursors over placeholder
			placeholderStart = placeholderEnd + 1
			lastWriteCursor = placeholderStart
			// if not supposed to treat unknown placeholders as empty values, print the unescaped copy
			if !treatUnknownAsEmpty {
				allPlaceholdersFound = false
				result.WriteByte(phOpen)
				result.WriteString(unescapedPlaceholder)
				result.WriteByte(phClose)
			}
		}

		// apply any transformations
		if f != nil {
			var err error
			val, err = f(key, val)
			if err != nil {
				return "", false, err
			}
		}

		// convert val to a string as efficiently as possible
		valStr := ToString(val)

		// write the value; if it's empty, either return an error or write a default value
		if valStr == "" && (found || treatUnknownAsEmpty) {
			if errOnEmpty {
				return "", false, fmt.Errorf("evaluated placeholder %s%s%s is empty",
					string(phOpen), key, string(phClose))
			}
			if empty != "" {
				valStr = empty
			}
		}
		result.WriteString(valStr)

		// advance cursor to end of placeholder
		placeholderStart = placeholderEnd
		lastWriteCursor = placeholderStart + 1
	}

	// flush any unwritten remainder
	if lastWriteCursor < len(input) {
		result.WriteString(input[lastWriteCursor:])
	}

	return result.String(), allPlaceholdersFound, nil
}

// ToString returns val as a string, as efficiently as possible.
// EXPERIMENTAL: may be changed or removed later.
func ToString(val any) string {
	switch v := val.(type) {
	case nil:
		return ""
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case error:
		return v.Error()
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
type ReplacerFunc func(key string) (any, bool)

func globalDefaultReplacements(key string) (any, bool) {
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
	case "system.wd":
		// OK if there is an error; just return empty string
		wd, _ := os.Getwd()
		return wd, true
	case "system.arch":
		return runtime.GOARCH, true
	case "time.now":
		return nowFunc(), true
	case "time.now.common_log":
		return nowFunc().Format("02/Jan/2006:15:04:05 -0700"), true
	case "time.now.year":
		return strconv.Itoa(nowFunc().Year()), true
	case "time.now.unix":
		return strconv.FormatInt(nowFunc().Unix(), 10), true
	case "time.now.unix_ms":
		return strconv.FormatInt(nowFunc().UnixNano()/int64(time.Millisecond), 10), true
	}

	return nil, false
}

// ReplacementFunc is a function that is called when a
// replacement is being performed. It receives the
// variable (i.e. placeholder name) and the value that
// will be the replacement, and returns the value that
// will actually be the replacement, or an error. Note
// that errors are sometimes ignored by replacers.
type ReplacementFunc func(variable string, val any) (any, error)

// nowFunc is a variable so tests can change it
// in order to obtain a deterministic time.
var nowFunc = time.Now

// ReplacerCtxKey is the context key for a replacer.
const ReplacerCtxKey CtxKey = "replacer"

const phOpen, phClose, phEscape, phQuote, phColon = '{', '}', '\\', '"', ':'

var varDefaultDelimiter = regexp.MustCompile(`[^\\](:)`)
var escapedDefaultDelimiter = regexp.MustCompile(`\\:`)
