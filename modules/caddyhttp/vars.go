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
)

func init() {
	caddy.RegisterModule(VarsMiddleware{})
	caddy.RegisterModule(VarsMatcher{})
	caddy.RegisterModule(MatchVarsRE{})
}

// VarsMiddleware is an HTTP middleware which sets variables
// in the context, mainly for use by placeholders. The
// placeholders have the form: `{http.vars.variable_name}`
type VarsMiddleware map[string]string

// CaddyModule returns the Caddy module information.
func (VarsMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.vars",
		New: func() caddy.Module { return new(VarsMiddleware) },
	}
}

func (t VarsMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
	vars := r.Context().Value(VarsCtxKey).(map[string]interface{})
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for k, v := range t {
		keyExpanded := repl.ReplaceAll(k, "")
		valExpanded := repl.ReplaceAll(v, "")
		vars[keyExpanded] = valExpanded
	}
	return next.ServeHTTP(w, r)
}

// VarsMatcher is an HTTP request matcher which can match
// requests based on variables in the context.
type VarsMatcher map[string]string

// CaddyModule returns the Caddy module information.
func (VarsMatcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.vars",
		New: func() caddy.Module { return new(VarsMatcher) },
	}
}

// Match matches a request based on variables in the context.
func (m VarsMatcher) Match(r *http.Request) bool {
	vars := r.Context().Value(VarsCtxKey).(map[string]interface{})
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for k, v := range m {
		keyExpanded := repl.ReplaceAll(k, "")
		valExpanded := repl.ReplaceAll(v, "")
		var varStr string
		switch vv := vars[keyExpanded].(type) {
		case string:
			varStr = vv
		case fmt.Stringer:
			varStr = vv.String()
		case error:
			varStr = vv.Error()
		default:
			varStr = fmt.Sprintf("%v", vv)
		}
		if varStr != valExpanded {
			return false
		}
	}
	return true
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
	_ MiddlewareHandler = (*VarsMiddleware)(nil)
	_ RequestMatcher    = (*VarsMatcher)(nil)
)
