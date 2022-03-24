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
type VarsMiddleware map[string]interface{}

// CaddyModule returns the Caddy module information.
func (VarsMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.vars",
		New: func() caddy.Module { return new(VarsMiddleware) },
	}
}

func (m VarsMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
	vars := r.Context().Value(VarsCtxKey).(map[string]interface{})
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for k, v := range m {
		keyExpanded := repl.ReplaceAll(k, "")
		if valStr, ok := v.(string); ok {
			v = repl.ReplaceAll(valStr, "")
		}
		vars[keyExpanded] = v
	}
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//     vars [<name> <val>] {
//         <name> <val>
//         ...
//     }
//
func (m *VarsMiddleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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

	for d.Next() {
		if err := nextVar(true); err != nil {
			return err
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			if err := nextVar(false); err != nil {
				return err
			}
		}
	}

	return nil
}

// VarsMatcher is an HTTP request matcher which can match
// requests based on variables in the context. The key is
// the name of the variable, and the values are possible
// values the variable can be in order to match (OR'ed).
//
// As a special case, this matcher can also match on
// placeholders generally. If the key is not an HTTP chain
// variable, it will be checked to see if it is a
// placeholder name, and if so, will compare its value.
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
	if len(m) == 0 {
		return true
	}

	vars := r.Context().Value(VarsCtxKey).(map[string]interface{})
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	for key, vals := range m {
		// look up the comparison value we will check against with this key
		matcherVarNameExpanded := repl.ReplaceAll(key, "")
		varValue, ok := vars[matcherVarNameExpanded]
		if !ok {
			// as a special case, if it's not an HTTP variable,
			// see if it's a placeholder name
			varValue, _ = repl.Get(matcherVarNameExpanded)
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
			default:
				varStr = fmt.Sprintf("%v", vv)
			}
			if varStr == matcherValExpanded {
				return true
			}
		}
	}
	return false
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
	vars := r.Context().Value(VarsCtxKey).(map[string]interface{})
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for k, rm := range m {
		var varStr string
		switch vv := vars[k].(type) {
		case string:
			varStr = vv
		case fmt.Stringer:
			varStr = vv.String()
		case error:
			varStr = vv.Error()
		default:
			varStr = fmt.Sprintf("%v", vv)
		}
		valExpanded := repl.ReplaceAll(varStr, "")
		if match := rm.Match(valExpanded, repl); match {
			return match
		}

		replacedVal := repl.ReplaceAll(k, "")
		if match := rm.Match(replacedVal, repl); match {
			return match
		}
	}
	return false
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
func GetVar(ctx context.Context, key string) interface{} {
	varMap, ok := ctx.Value(VarsCtxKey).(map[string]interface{})
	if !ok {
		return nil
	}
	return varMap[key]
}

// SetVar sets a value in the context's variable table with
// the given key. It overwrites any previous value with the
// same key.
func SetVar(ctx context.Context, key string, value interface{}) {
	varMap, ok := ctx.Value(VarsCtxKey).(map[string]interface{})
	if !ok {
		return
	}
	varMap[key] = value
}

// Interface guards
var (
	_ MiddlewareHandler     = (*VarsMiddleware)(nil)
	_ caddyfile.Unmarshaler = (*VarsMiddleware)(nil)
	_ RequestMatcher        = (*VarsMatcher)(nil)
	_ caddyfile.Unmarshaler = (*VarsMatcher)(nil)
)
