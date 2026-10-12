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
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2/internal/placeholder"
)

// NewReplacer returns a new Replacer.
func NewReplacer() *Replacer {
	rep := &Replacer{
		static:   make(map[string]any),
		mapMutex: &sync.RWMutex{},
	}
	rep.providers = []replacementProvider{
		globalDefaultReplacementProvider{},
		fileReplacementProvider{},
		ReplacerFunc(rep.fromStatic),
	}
	return rep
}

// NewEmptyReplacer returns a new Replacer,
// without the global default replacements.
func NewEmptyReplacer() *Replacer {
	rep := &Replacer{
		static:   make(map[string]any),
		mapMutex: &sync.RWMutex{},
	}
	rep.providers = []replacementProvider{
		ReplacerFunc(rep.fromStatic),
	}
	return rep
}

// Replacer can replace values in strings.
// A default/empty Replacer is not valid;
// use NewReplacer to make one.
type Replacer struct {
	providers []replacementProvider
	static    map[string]any
	mapMutex  *sync.RWMutex
}

// WithoutFile returns a copy of the current Replacer
// without support for the {file.*} placeholder, which
// may be unsafe in some contexts.
//
// EXPERIMENTAL: Subject to change or removal.
func (r *Replacer) WithoutFile() *Replacer {
	rep := &Replacer{static: r.static}
	for _, v := range r.providers {
		if _, ok := v.(fileReplacementProvider); ok {
			continue
		}
		rep.providers = append(rep.providers, v)
	}
	return rep
}

// Map adds mapFunc to the list of value providers.
// mapFunc will be executed only at replace-time.
func (r *Replacer) Map(mapFunc ReplacerFunc) {
	r.providers = append(r.providers, mapFunc)
}

// Set sets a custom variable to a static value.
func (r *Replacer) Set(variable string, value any) {
	r.mapMutex.Lock()
	r.static[variable] = value
	r.mapMutex.Unlock()
}

// Get looks up variable verbatim and returns its value and whether it was
// known. It does not interpret braces or default syntax; use ResolvePlaceholder
// to evaluate a complete configured placeholder expression.
func (r *Replacer) Get(variable string) (any, bool) {
	for _, mapFunc := range r.providers {
		if val, ok := mapFunc.replace(variable); ok {
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
	r.mapMutex.Lock()
	delete(r.static, variable)
	r.mapMutex.Unlock()
}

// DeleteByPrefix removes all static variables with
// keys starting with the given prefix
func (r *Replacer) DeleteByPrefix(prefix string) {
	r.mapMutex.Lock()
	for key := range r.static {
		if strings.HasPrefix(key, prefix) {
			delete(r.static, key)
		}
	}
	r.mapMutex.Unlock()
}

// fromStatic provides values from r.static.
func (r *Replacer) fromStatic(key string) (any, bool) {
	r.mapMutex.RLock()
	defer r.mapMutex.RUnlock()
	val, ok := r.static[key]
	return val, ok
}

// ReplaceOrErr replaces placeholders and returns syntax errors. If errOnEmpty
// or errOnUnknown is true, an empty or unrecognized selected reference also
// causes an error. Defaults are selected before these checks; providers in
// unused defaults are not queried. Unknown references otherwise remain literal.
func (r *Replacer) ReplaceOrErr(input string, errOnEmpty, errOnUnknown bool) (string, error) {
	return r.replace(input, "", false, errOnEmpty, errOnUnknown, nil)
}

// ReplaceKnown is like ReplaceAll but only replaces
// placeholders that are known (recognized). Unrecognized
// references in the selected expression remain in the output. Explicit
// defaults are recognized even when their primary key is unknown. Malformed
// defaults produce an empty result; use ReplaceOrErr to inspect syntax errors.
func (r *Replacer) ReplaceKnown(input, empty string) string {
	out, _ := r.replace(input, empty, false, false, false, nil)
	return out
}

// ReplaceAll efficiently replaces placeholders in input with
// their values. All placeholders are replaced in the output
// whether they are recognized or not. Values that are empty
// string will be substituted with empty. An explicit {key:-default} selects
// its default when key is unknown or empty; an explicitly empty default
// overrides empty. Defaults may contain nested configured placeholders.
// Malformed defaults produce an empty result; use ReplaceOrErr to inspect
// syntax errors. Provider values are emitted without further expansion.
func (r *Replacer) ReplaceAll(input, empty string) string {
	out, _ := r.replace(input, empty, true, false, false, nil)
	return out
}

// ReplaceFunc is the same as ReplaceAll, but calls f for every
// replacement to be made, in case f wants to change or inspect
// the replacement. For defaults, f receives the selected placeholder
// name, or an empty name for literal or composite defaults, and is called once
// on the selected value. Values returned by providers are never expanded again.
func (r *Replacer) ReplaceFunc(input string, f ReplacementFunc) (string, error) {
	return r.replace(input, "", true, false, false, f)
}

func (r *Replacer) replace(input, empty string,
	treatUnknownAsEmpty, errOnEmpty, errOnUnknown bool,
	f ReplacementFunc,
) (string, error) {
	if !strings.Contains(input, string(phOpen)) && !strings.Contains(input, string(phClose)) {
		return input, nil
	}

	var sb strings.Builder

	// it is reasonable to assume that the output
	// will be approximately as long as the input
	sb.Grow(len(input))

	// iterate the input to find each placeholder
	var lastWriteCursor int

	// fail fast if too many placeholders are unclosed
	var unclosedCount int

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

		// our iterator is now on an unescaped open brace (start of placeholder)

		// too many unclosed placeholders in absolutely ridiculous input can be extremely slow (issue #4170)
		if unclosedCount > 100 {
			return "", fmt.Errorf("too many unclosed placeholders")
		}

		// Parse syntax before invoking providers, which may perform I/O. Only
		// references with an explicit default use balanced-brace matching.
		ref, n, err := placeholder.Parse(input[i:])
		if err != nil {
			return "", err
		}
		if n == 0 {
			unclosedCount++
			continue
		}
		end := i + n - 1
		sb.WriteString(input[lastWriteCursor:i])

		var resolved resolvedPlaceholder
		if !ref.HasDefault {
			// Ordinary references need only exact lookup; reserve the typed
			// default resolver's bookkeeping for expressions with defaults.
			resolved.name = placeholder.UnescapeKey(ref.Key)
			resolved.value, resolved.found = r.Get(resolved.name)
		} else {
			resolved, err = r.resolveReference(ref, replacementPolicy{
				treatUnknownAsEmpty: treatUnknownAsEmpty,
				errOnEmpty:          errOnEmpty,
				errOnUnknown:        errOnUnknown,
			}, 0)
			if err != nil {
				return "", err
			}
		}
		key, val, found := resolved.name, resolved.value, resolved.found
		if !found {
			if errOnUnknown {
				return "", fmt.Errorf("unrecognized placeholder {%s}", key)
			} else if !treatUnknownAsEmpty {
				if !ref.HasDefault {
					// Keep scanning inside unknown legacy references, which may
					// themselves contain a recognized reference.
					lastWriteCursor = i
					continue
				}
				sb.WriteString(resolved.unresolved)
				i = end
				lastWriteCursor = i + 1
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
		valStr := ToString(val)

		// write the value; if it's empty, either return
		// an error or write a default value
		if valStr == "" {
			if errOnEmpty {
				return "", fmt.Errorf("evaluated placeholder %s%s%s is empty",
					string(phOpen), key, string(phClose))
			} else if empty != "" && !resolved.defaulted {
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
		return strconv.FormatUint(uint64(v), 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
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

// ReplacerFunc is a function that returns a replacement for the
// given key along with true if the function is able to service
// that key (even if the value is blank). If the function does
// not recognize the key, false should be returned.
type ReplacerFunc func(key string) (any, bool)

func (f ReplacerFunc) replace(key string) (any, bool) {
	return f(key)
}

// replacementProvider is a type that can provide replacements
// for placeholders. Allows for type assertion to determine
// which type of provider it is.
type replacementProvider interface {
	replace(key string) (any, bool)
}

// fileReplacementProvider handles {file.*} replacements,
// reading a file from disk and replacing with its contents.
type fileReplacementProvider struct{}

func (f fileReplacementProvider) replace(key string) (any, bool) {
	if !strings.HasPrefix(key, filePrefix) {
		return nil, false
	}

	filename := key[len(filePrefix):]
	maxSize := 1024 * 1024
	body, err := readFileIntoBuffer(filename, maxSize)
	if err != nil {
		wd, _ := os.Getwd()
		Log().Error("placeholder: failed to read file",
			zap.String("file", filename),
			zap.String("working_dir", wd),
			zap.Error(err))
		return nil, true
	}
	body = bytes.TrimSuffix(body, []byte("\n"))
	body = bytes.TrimSuffix(body, []byte("\r"))
	return string(body), true
}

// globalDefaultReplacementProvider handles replacements
// that can be used in any context, such as system variables,
// time, or environment variables.
type globalDefaultReplacementProvider struct{}

func (f globalDefaultReplacementProvider) replace(key string) (any, bool) {
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
	case "time.now.http":
		// According to the comment for http.TimeFormat, the timezone must be in UTC
		// to generate the correct format.
		// https://github.com/caddyserver/caddy/issues/5773
		return nowFunc().UTC().Format(http.TimeFormat), true
	case "time.now.rfc3339":
		return nowFunc().Format(time.RFC3339), true
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

// readFileIntoBuffer reads the file at filePath into a size limited buffer.
func readFileIntoBuffer(filename string, size int) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// io.LimitReader ensures we never read more than 'size' bytes.
	// io.ReadAll starts with a small buffer and grows it as needed,
	// preventing a massive 1MB allocation for small files.
	return io.ReadAll(io.LimitReader(file, int64(size)))
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

const phOpen, phClose, phEscape = '{', '}', '\\'

const filePrefix = "file."

// ResolvePlaceholder resolves exactly one complete placeholder expression.
// Unlike Get, it understands {key:-default}: the default is selected when key
// is unknown or ToString(value) is empty. Recognized nil values select defaults;
// false and numeric zero do not. Error-valued providers never select a default,
// even if their error message is empty.
//
// Defaults can contain nested placeholders. Their syntax is validated even
// when unused, but their providers are queried only when selected. Provider
// values are never evaluated as placeholder expressions. In default text,
// backslashes escape braces and backslashes. Escape a key's reserved operator
// as \:- to look up a key containing a literal :-.
//
// Primary values and defaults consisting of a single placeholder retain their
// Go type. Literal and composite defaults produce strings, except that an
// error-valued nested reference stops composition and retains its type. The
// returned error reports invalid syntax or excessive nesting, not errors
// supplied by providers: those are returned as value with found=true, err=nil.
// Callers that consume typed values must inspect error-valued results.
//
// The boolean reports whether the selected result is recognized, including
// recognized nil values and explicit empty defaults. A sole unresolved nested
// reference returns (nil, false, nil); a composite default retains unknown
// references as literal text and returns found=true, as with ReplaceKnown.
//
// Overrides must be non-nil. They are consulted before the regular providers,
// in order, using unescaped provider keys. The first found=true result wins,
// including nil or empty values. Overrides apply throughout the selected expression
// without modifying the replacer and are not retained after this call. They
// let callers supply values whose lifetime belongs to the caller, such as a
// buffered response body.
//
// Get continues to perform exact lookup, including keys containing :-.
func (r *Replacer) ResolvePlaceholder(input string, overrides ...ReplacerFunc) (any, bool, error) {
	ref, single, err := placeholder.ParseSingle(input)
	if err != nil {
		return nil, false, err
	}
	if !single {
		return nil, false, fmt.Errorf("expected a single placeholder expression")
	}
	resolved, err := r.resolveReference(ref, replacementPolicy{overrides: overrides}, 0)
	return resolved.value, resolved.found, err
}

type replacementPolicy struct {
	treatUnknownAsEmpty, errOnEmpty, errOnUnknown bool
	overrides                                     []ReplacerFunc
}

type resolvedPlaceholder struct {
	value      any
	found      bool
	name       string
	defaulted  bool
	unresolved string
}

func (r *Replacer) resolveReference(ref placeholder.Reference, policy replacementPolicy, depth int) (resolvedPlaceholder, error) {
	if depth >= placeholder.MaxDepth {
		return resolvedPlaceholder{}, fmt.Errorf("placeholder default exceeds maximum depth of %d", placeholder.MaxDepth)
	}
	key := placeholder.UnescapeKey(ref.Key)
	var value any
	var found bool
	for _, override := range policy.overrides {
		if value, found = override(key); found {
			break
		}
	}
	if !found {
		value, found = r.Get(key)
	}
	resolved := resolvedPlaceholder{value: value, found: found, name: key}
	// Errors can carry control-flow information even when their text is empty.
	// Never turn an error-valued primary into a successful literal fallback.
	if found {
		if _, ok := value.(error); ok {
			return resolved, nil
		}
	}
	if !ref.HasDefault || (found && ToString(value) != "") {
		return resolved, nil
	}

	// Preserve both the type and source of a sole nested reference. In particular,
	// query rewriting needs to distinguish an already-escaped query from literal
	// fallback text. Composite defaults have no single source placeholder.
	nested, n, err := placeholder.Parse(ref.Default)
	if err != nil {
		return resolvedPlaceholder{}, err
	}
	if n > 0 && n == len(ref.Default) {
		selected, err := r.resolveReference(nested, policy, depth+1)
		if !selected.found && !nested.HasDefault && !policy.treatUnknownAsEmpty {
			selected.unresolved = ref.Default
		}
		selected.defaulted = true
		return selected, err
	}
	selected, err := r.expandDefault(ref.Default, policy, depth+1)
	selected.defaulted = true
	return selected, err
}

// expandDefault only scans configured fallback text. It does not invoke the
// caller's transformation or empty-value substitution on intermediate values.
func (r *Replacer) expandDefault(input string, policy replacementPolicy, depth int) (resolvedPlaceholder, error) {
	var out strings.Builder
	out.Grow(len(input))
	for i := 0; i < len(input); i++ {
		if input[i] == '\\' && i+1 < len(input) && strings.ContainsRune("{}\\", rune(input[i+1])) {
			i++
			out.WriteByte(input[i])
			continue
		}
		if input[i] != '{' {
			out.WriteByte(input[i])
			continue
		}
		ref, n, err := placeholder.Parse(input[i:])
		if err != nil {
			return resolvedPlaceholder{}, err
		}
		if n == 0 {
			out.WriteString(input[i:])
			break
		}
		resolved, err := r.resolveReference(ref, policy, depth)
		if err != nil {
			return resolvedPlaceholder{}, err
		}
		if !resolved.found {
			if policy.errOnUnknown {
				return resolvedPlaceholder{}, fmt.Errorf("unrecognized placeholder {%s}", resolved.name)
			}
			if !policy.treatUnknownAsEmpty {
				if ref.HasDefault {
					out.WriteString(resolved.unresolved)
				} else {
					out.WriteByte(phOpen)
					out.WriteString(ref.Key)
					out.WriteByte(phClose)
				}
			}
		} else {
			// Error values may carry control-flow information, such as an HTTP
			// body-limit status. Do not hide their type in composite text.
			if _, ok := resolved.value.(error); ok {
				return resolved, nil
			}
			text := ToString(resolved.value)
			if text == "" && policy.errOnEmpty {
				return resolvedPlaceholder{}, fmt.Errorf("evaluated placeholder {%s} is empty", resolved.name)
			}
			out.WriteString(text)
		}
		i += n - 1
	}
	return resolvedPlaceholder{value: out.String(), found: true}, nil
}
