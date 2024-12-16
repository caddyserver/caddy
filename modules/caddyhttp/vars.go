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

package caddyhttp

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(VarsMiddleware{})
	caddy.RegisterModule(VarsMatcher{})
	caddy.RegisterModule(MatchVarsRE{})
}

// VarsMiddleware is an HTTP middleware which sets variables to
// have values that can be used in the HTTP request handler
// chain. The primary way to access variables is with placeholders,
// which have the form: `{http.vars.variable_name}`, or with
// the `vars` and `vars_regexp` request matchers.
//
// The key is the variable name, and the value is the value of the
// variable. Both the name and value may use or contain placeholders.
type VarsMiddleware map[string]any

// CaddyModule returns the Caddy module information.
func (VarsMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.vars",
		New: func() caddy.Module { return new(VarsMiddleware) },
	}
}

func (m VarsMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
	vars := r.Context().Value(VarsCtxKey).(map[string]any)
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for k, v := range m {
		keyExpanded := repl.ReplaceAll(k, "")
		if valStr, ok := v.(string); ok {
			v = repl.ReplaceAll(valStr, "")
		}
		vars[keyExpanded] = v

		// Special case: the user ID is in the replacer, pulled from there
		// for access logs. Allow users to override it with the vars handler.
		if keyExpanded == "http.auth.user.id" {
			repl.Set(keyExpanded, v)
		}
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//	vars [<name> <val>] {
//	    <name> <val>
//	    ...
//	}
func (m *VarsMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	if *m == nil {
		*m = make(VarsMiddleware)
	}

	nextVar := func(headerLine bool) error {
		if headerLine {
			// header line is optional
			if !d.NextArg() {
				return nil
			}
		}
		varName := d.Val()

		if !d.NextArg() {
			return d.ArgErr()
		}
		varValue := d.ScalarVal()

		(*m)[varName] = varValue

		if d.NextArg() {
			return d.ArgErr()
		}
		return nil
	}

	if err := nextVar(true); err != nil {
		return err
	}
	for d.NextBlock(0) {
		if err := nextVar(false); err != nil {
			return err
		}
	}

	return nil
}

// VarsMatcher is an HTTP request matcher which can match
// requests based on variables in the context or placeholder
// values. The key is the placeholder or name of the variable,
// and the values are possible values the variable can be in
// order to match (logical OR'ed).
//
// If the key is surrounded by `{ }` it is assumed to be a
// placeholder. Otherwise, it will be considered a variable
// name.
//
// Placeholders in the keys are not expanded, but
// placeholders in the values are.
type VarsMatcher map[string][]string

// CaddyModule returns the Caddy module information.
func (VarsMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.vars",
		New: func() caddy.Module { return new(VarsMatcher) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *VarsMatcher) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if *m == nil {
		*m = make(map[string][]string)
	}
	// iterate to merge multiple matchers into one
	for d.Next() {
		var field string
		if !d.Args(&field) {
			return d.Errf("malformed vars matcher: expected field name")
		}
		vals := d.RemainingArgs()
		if len(vals) == 0 {
			return d.Errf("malformed vars matcher: expected at least one value to match against")
		}
		(*m)[field] = append((*m)[field], vals...)
		if d.NextBlock(0) {
			return d.Err("malformed vars matcher: blocks are not supported")
		}
	}
	return nil
}

// Match matches a request based on variables in the context,
// or placeholders if the key is not a variable.
func (m VarsMatcher) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
func (m VarsMatcher) MatchWithError(r *http.Request) (bool, error) {
	if len(m) == 0 {
		return true, nil
	}

	vars := r.Context().Value(VarsCtxKey).(map[string]any)
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	for key, vals := range m {
		var varValue any
		if strings.HasPrefix(key, "{") &&
			strings.HasSuffix(key, "}") &&
			strings.Count(key, "{") == 1 {
			varValue, _ = repl.Get(strings.Trim(key, "{}"))
		} else {
			varValue = vars[key]
		}

		// see if any of the values given in the matcher match the actual value
		for _, v := range vals {
			matcherValExpanded := repl.ReplaceAll(v, "")
			var varStr string
			switch vv := varValue.(type) {
			case string:
				varStr = vv
			case fmt.Stringer:
				varStr = vv.String()
			case error:
				varStr = vv.Error()
			case nil:
				varStr = ""
			default:
				varStr = fmt.Sprintf("%v", vv)
			}
			if varStr == matcherValExpanded {
				return true, nil
			}
		}
	}
	return false, nil
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression vars({'{magic_number}': ['3', '5']})
//	expression vars({'{foo}': 'single_value'})
func (VarsMatcher) CELLibrary(_ caddy.Context) (cel.Library, error) {
	return CELMatcherImpl(
		"vars",
		"vars_matcher_request_map",
		[]*cel.Type{CELTypeJSON},
		func(data ref.Val) (RequestMatcherWithError, error) {
			mapStrListStr, err := CELValueToMapStrList(data)
			if err != nil {
				return nil, err
			}
			return VarsMatcher(mapStrListStr), nil
		},
	)
}

// MatchVarsRE matches the value of the context variables by a given regular expression.
//
// Upon a match, it adds placeholders to the request: `{http.regexp.name.capture_group}`
// where `name` is the regular expression's name, and `capture_group` is either
// the named or positional capture group from the expression itself. If no name
// is given, then the placeholder omits the name: `{http.regexp.capture_group}`
// (potentially leading to collisions).
type MatchVarsRE map[string]*MatchRegexp

// CaddyModule returns the Caddy module information.
func (MatchVarsRE) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.vars_regexp",
		New: func() caddy.Module { return new(MatchVarsRE) },
	}
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchVarsRE) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if *m == nil {
		*m = make(map[string]*MatchRegexp)
	}
	// iterate to merge multiple matchers into one
	for d.Next() {
		var first, second, third string
		if !d.Args(&first, &second) {
			return d.ArgErr()
		}

		var name, field, val string
		if d.Args(&third) {
			name = first
			field = second
			val = third
		} else {
			field = first
			val = second
		}

		// Default to the named matcher's name, if no regexp name is provided
		if name == "" {
			name = d.GetContextString(caddyfile.MatcherNameCtxKey)
		}

		(*m)[field] = &MatchRegexp{Pattern: val, Name: name}
		if d.NextBlock(0) {
			return d.Err("malformed vars_regexp matcher: blocks are not supported")
		}
	}
	return nil
}

// Provision compiles m's regular expressions.
func (m MatchVarsRE) Provision(ctx caddy.Context) error {
	for _, rm := range m {
		err := rm.Provision(ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchVarsRE) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchVarsRE) MatchWithError(r *http.Request) (bool, error) {
	vars := r.Context().Value(VarsCtxKey).(map[string]any)
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for key, val := range m {
		var varValue any
		if strings.HasPrefix(key, "{") &&
			strings.HasSuffix(key, "}") &&
			strings.Count(key, "{") == 1 {
			varValue, _ = repl.Get(strings.Trim(key, "{}"))
		} else {
			varValue = vars[key]
		}

		var varStr string
		switch vv := varValue.(type) {
		case string:
			varStr = vv
		case fmt.Stringer:
			varStr = vv.String()
		case error:
			varStr = vv.Error()
		case nil:
			varStr = ""
		default:
			varStr = fmt.Sprintf("%v", vv)
		}

		valExpanded := repl.ReplaceAll(varStr, "")
		if match := val.Match(valExpanded, repl); match {
			return match, nil
		}
	}
	return false, nil
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression vars_regexp('foo', '{magic_number}', '[0-9]+')
//	expression vars_regexp('{magic_number}', '[0-9]+')
func (MatchVarsRE) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	unnamedPattern, err := CELMatcherImpl(
		"vars_regexp",
		"vars_regexp_request_string_string",
		[]*cel.Type{cel.StringType, cel.StringType},
		func(data ref.Val) (RequestMatcherWithError, error) {
			refStringList := reflect.TypeOf([]string{})
			params, err := data.ConvertToNative(refStringList)
			if err != nil {
				return nil, err
			}
			strParams := params.([]string)
			matcher := MatchVarsRE{}
			matcher[strParams[0]] = &MatchRegexp{
				Pattern: strParams[1],
				Name:    ctx.Value(MatcherNameCtxKey).(string),
			}
			err = matcher.Provision(ctx)
			return matcher, err
		},
	)
	if err != nil {
		return nil, err
	}
	namedPattern, err := CELMatcherImpl(
		"vars_regexp",
		"vars_regexp_request_string_string_string",
		[]*cel.Type{cel.StringType, cel.StringType, cel.StringType},
		func(data ref.Val) (RequestMatcherWithError, error) {
			refStringList := reflect.TypeOf([]string{})
			params, err := data.ConvertToNative(refStringList)
			if err != nil {
				return nil, err
			}
			strParams := params.([]string)
			name := strParams[0]
			if name == "" {
				name = ctx.Value(MatcherNameCtxKey).(string)
			}
			matcher := MatchVarsRE{}
			matcher[strParams[1]] = &MatchRegexp{
				Pattern: strParams[2],
				Name:    name,
			}
			err = matcher.Provision(ctx)
			return matcher, err
		},
	)
	if err != nil {
		return nil, err
	}
	envOpts := append(unnamedPattern.CompileOptions(), namedPattern.CompileOptions()...)
	prgOpts := append(unnamedPattern.ProgramOptions(), namedPattern.ProgramOptions()...)
	return NewMatcherCELLibrary(envOpts, prgOpts), nil
}

// Validate validates m's regular expressions.
func (m MatchVarsRE) Validate() error {
	for _, rm := range m {
		err := rm.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// GetVar gets a value out of the context's variable table by key.
// If the key does not exist, the return value will be nil.
func GetVar(ctx context.Context, key string) any {
	varMap, ok := ctx.Value(VarsCtxKey).(map[string]any)
	if !ok {
		return nil
	}
	return varMap[key]
}

// SetVar sets a value in the context's variable table with
// the given key. It overwrites any previous value with the
// same key.
//
// If the value is nil (note: non-nil interface with nil
// underlying value does not count) and the key exists in
// the table, the key+value will be deleted from the table.
func SetVar(ctx context.Context, key string, value any) {
	varMap, ok := ctx.Value(VarsCtxKey).(map[string]any)
	if !ok {
		return
	}
	if value == nil {
		if _, ok := varMap[key]; ok {
			delete(varMap, key)
			return
		}
	}
	varMap[key] = value
}

// Interface guards
var (
	_ MiddlewareHandler       = (*VarsMiddleware)(nil)
	_ caddyfile.Unmarshaler   = (*VarsMiddleware)(nil)
	_ RequestMatcherWithError = (*VarsMatcher)(nil)
	_ caddyfile.Unmarshaler   = (*VarsMatcher)(nil)
	_ RequestMatcherWithError = (*MatchVarsRE)(nil)
	_ caddyfile.Unmarshaler   = (*MatchVarsRE)(nil)
)
