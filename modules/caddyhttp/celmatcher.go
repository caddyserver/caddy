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
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

func init() {
	caddy.RegisterModule(MatchExpression{})
}

// MatchExpression matches requests by evaluating a
// [CEL](https://github.com/google/cel-spec) expression.
// This enables complex logic to be expressed using a comfortable,
// familiar syntax.
//
// COMPATIBILITY NOTE: This module is still experimental and is not
// subject to Caddy's compatibility guarantee.
type MatchExpression struct {
	// The CEL expression to evaluate. Any Caddy placeholders
	// will be expanded and situated into proper CEL function
	// calls before evaluating.
	Expr string

	expandedExpr string
	prg          cel.Program
}

// CaddyModule returns the Caddy module information.
func (MatchExpression) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.expression",
		New: func() caddy.Module { return new(MatchExpression) },
	}
}

// MarshalJSON marshals m's expression.
func (m MatchExpression) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.Expr)
}

// UnmarshalJSON unmarshals m's expression.
func (m *MatchExpression) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &m.Expr)
}

// Provision sets ups m.
func (m *MatchExpression) Provision(_ caddy.Context) error {
	// replace placeholders with a function call - this is just some
	// light (and possibly naïve) syntactic sugar
	m.expandedExpr = placeholderRegexp.ReplaceAllString(m.Expr, placeholderExpansion)

	// create the CEL environment
	env, err := cel.NewEnv(
		cel.Declarations(
			decls.NewIdent("request", httpRequestObjectType, nil),
			decls.NewFunction(placeholderFuncName,
				decls.NewOverload(placeholderFuncName+"_httpRequest_string",
					[]*exprpb.Type{httpRequestObjectType, decls.String},
					decls.String)),
		),
		cel.CustomTypeAdapter(celHTTPRequestTypeAdapter{}),
	)
	if err != nil {
		return fmt.Errorf("setting up CEL environment: %v", err)
	}

	// parse the expression
	parsed, issues := env.Parse(m.expandedExpr)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("parsing CEL program: %s", issues.Err())
	}

	// type-check it
	checked, issues := env.Check(parsed)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("type-checking CEL program: %s", issues.Err())
	}

	// compile the "program"
	m.prg, err = env.Program(checked,
		cel.Functions(
			&functions.Overload{
				Operator: placeholderFuncName,
				Binary:   caddyPlaceholderFunc,
			},
		),
	)

	if err != nil {
		return fmt.Errorf("compiling CEL program: %s", err)
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchExpression) Match(r *http.Request) bool {
	out, _, _ := m.prg.Eval(map[string]interface{}{
		"request": celHTTPRequest{r},
	})
	if outBool, ok := out.Value().(bool); ok {
		return outBool
	}
	return false

}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchExpression) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		m.Expr = strings.Join(d.RemainingArgs(), " ")
	}
	return nil
}

// httpRequestCELType is the type representation of a native HTTP request.
var httpRequestCELType = types.NewTypeValue("http.Request", traits.ReceiverType)

// cellHTTPRequest wraps an http.Request with
// methods to satisfy the ref.Val interface.
type celHTTPRequest struct {
	*http.Request
}

func (cr celHTTPRequest) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
	return cr.Request, nil
}
func (celHTTPRequest) ConvertToType(typeVal ref.Type) ref.Val {
	panic("not implemented")
}
func (cr celHTTPRequest) Equal(other ref.Val) ref.Val {
	if o, ok := other.Value().(celHTTPRequest); ok {
		return types.Bool(o.Request == cr.Request)
	}
	return types.ValOrErr(other, "%v is not comparable type", other)
}
func (celHTTPRequest) Type() ref.Type        { return httpRequestCELType }
func (cr celHTTPRequest) Value() interface{} { return cr }

// celHTTPRequestTypeAdapter can adapt a
// celHTTPRequest to a CEL value.
type celHTTPRequestTypeAdapter struct{}

func (celHTTPRequestTypeAdapter) NativeToValue(value interface{}) ref.Val {
	if celReq, ok := value.(celHTTPRequest); ok {
		return celReq
	}
	return types.DefaultTypeAdapter.NativeToValue(value)
}

// Variables used for replacing Caddy placeholders in CEL
// expressions with a proper CEL function call; this is
// just for syntactic sugar.
var (
	placeholderRegexp    = regexp.MustCompile(`{([\w.-]+)}`)
	placeholderExpansion = `caddyPlaceholder(request, "${1}")`
)

var httpRequestObjectType = decls.NewObjectType("http.Request")

// The name of the CEL function which accesses Replacer values.
const placeholderFuncName = "caddyPlaceholder"

// caddyPlaceholderFunc implements the custom CEL function that
// accesses the Replacer on a request and gets values from it.
func caddyPlaceholderFunc(lhs, rhs ref.Val) ref.Val {
	celReq, ok := lhs.(celHTTPRequest)
	if !ok {
		return types.NewErr(
			"invalid request of type '%v' to "+placeholderFuncName+"(request, placeholderVarName)",
			lhs.Type())
	}
	phStr, ok := rhs.(types.String)
	if !ok {
		return types.NewErr(
			"invalid placeholder variable name of type '%v' to "+placeholderFuncName+"(request, placeholderVarName)",
			rhs.Type())
	}

	repl := celReq.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	val, _ := repl.Get(string(phStr))

	return types.String(val)
}

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchExpression)(nil)
	_ RequestMatcher        = (*MatchExpression)(nil)
	_ caddyfile.Unmarshaler = (*MatchExpression)(nil)
	_ json.Marshaler        = (*MatchExpression)(nil)
	_ json.Unmarshaler      = (*MatchExpression)(nil)
)
