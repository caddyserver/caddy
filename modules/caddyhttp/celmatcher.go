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
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
	"github.com/google/cel-go/interpreter"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/google/cel-go/parser"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(MatchExpression{})
}

// MatchExpression matches requests by evaluating a
// [CEL](https://github.com/google/cel-spec) expression.
// This enables complex logic to be expressed using a comfortable,
// familiar syntax. Please refer to
// [the standard definitions of CEL functions and operators](https://github.com/google/cel-spec/blob/master/doc/langdef.md#standard-definitions).
//
// This matcher's JSON interface is actually a string, not a struct.
// The generated docs are not correct because this type has custom
// marshaling logic.
//
// COMPATIBILITY NOTE: This module is still experimental and is not
// subject to Caddy's compatibility guarantee.
type MatchExpression struct {
	// The CEL expression to evaluate. Any Caddy placeholders
	// will be expanded and situated into proper CEL function
	// calls before evaluating.
	Expr string `json:"expr,omitempty"`

	// Name is an optional name for this matcher.
	// This is used to populate the name for regexp
	// matchers that appear in the expression.
	Name string `json:"name,omitempty"`

	expandedExpr string
	prg          cel.Program
	ta           types.Adapter

	log *zap.Logger
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
	// if the name is empty, then we can marshal just the expression string
	if m.Name == "" {
		return json.Marshal(m.Expr)
	}
	// otherwise, we need to marshal the full object, using an
	// anonymous struct to avoid infinite recursion
	return json.Marshal(struct {
		Expr string `json:"expr"`
		Name string `json:"name"`
	}{
		Expr: m.Expr,
		Name: m.Name,
	})
}

// UnmarshalJSON unmarshals m's expression.
func (m *MatchExpression) UnmarshalJSON(data []byte) error {
	// if the data is a string, then it's just the expression
	if data[0] == '"' {
		return json.Unmarshal(data, &m.Expr)
	}
	// otherwise, it's a full object, so unmarshal it,
	// using an temp map to avoid infinite recursion
	var tmpJson map[string]any
	err := json.Unmarshal(data, &tmpJson)
	*m = MatchExpression{
		Expr: tmpJson["expr"].(string),
		Name: tmpJson["name"].(string),
	}
	return err
}

// Provision sets ups m.
func (m *MatchExpression) Provision(ctx caddy.Context) error {
	m.log = ctx.Logger()

	// replace placeholders with a function call - this is just some
	// light (and possibly naïve) syntactic sugar
	m.expandedExpr = placeholderRegexp.ReplaceAllString(m.Expr, placeholderExpansion)

	// as a second pass, we'll strip the escape character from an escaped
	// placeholder, so that it can be used as an input to other CEL functions
	m.expandedExpr = escapedPlaceholderRegexp.ReplaceAllString(m.expandedExpr, escapedPlaceholderExpansion)

	// our type adapter expands CEL's standard type support
	m.ta = celTypeAdapter{}

	// initialize the CEL libraries from the Matcher implementations which
	// have been configured to support CEL.
	matcherLibProducers := []CELLibraryProducer{}
	for _, info := range caddy.GetModules("http.matchers") {
		p, ok := info.New().(CELLibraryProducer)
		if ok {
			matcherLibProducers = append(matcherLibProducers, p)
		}
	}

	// add the matcher name to the context so that the matcher name
	// can be used by regexp matchers being provisioned
	ctx = ctx.WithValue(MatcherNameCtxKey, m.Name)

	// Assemble the compilation and program options from the different library
	// producers into a single cel.Library implementation.
	matcherEnvOpts := []cel.EnvOption{}
	matcherProgramOpts := []cel.ProgramOption{}
	for _, producer := range matcherLibProducers {
		l, err := producer.CELLibrary(ctx)
		if err != nil {
			return fmt.Errorf("error initializing CEL library for %T: %v", producer, err)
		}
		matcherEnvOpts = append(matcherEnvOpts, l.CompileOptions()...)
		matcherProgramOpts = append(matcherProgramOpts, l.ProgramOptions()...)
	}
	matcherLib := cel.Lib(NewMatcherCELLibrary(matcherEnvOpts, matcherProgramOpts))

	// create the CEL environment
	env, err := cel.NewEnv(
		cel.Function(CELPlaceholderFuncName, cel.SingletonBinaryBinding(m.caddyPlaceholderFunc), cel.Overload(
			CELPlaceholderFuncName+"_httpRequest_string",
			[]*cel.Type{httpRequestObjectType, cel.StringType},
			cel.AnyType,
		)),
		cel.Variable(CELRequestVarName, httpRequestObjectType),
		cel.CustomTypeAdapter(m.ta),
		ext.Strings(),
		ext.Bindings(),
		ext.Lists(),
		ext.Math(),
		matcherLib,
	)
	if err != nil {
		return fmt.Errorf("setting up CEL environment: %v", err)
	}

	// parse and type-check the expression
	checked, issues := env.Compile(m.expandedExpr)
	if issues.Err() != nil {
		return fmt.Errorf("compiling CEL program: %s", issues.Err())
	}

	// request matching is a boolean operation, so we don't really know
	// what to do if the expression returns a non-boolean type
	if checked.OutputType() != cel.BoolType {
		return fmt.Errorf("CEL request matcher expects return type of bool, not %s", checked.OutputType())
	}

	// compile the "program"
	m.prg, err = env.Program(checked, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return fmt.Errorf("compiling CEL program: %s", err)
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchExpression) Match(r *http.Request) bool {
	match, err := m.MatchWithError(r)
	if err != nil {
		SetVar(r.Context(), MatcherErrorVarKey, err)
	}
	return match
}

// MatchWithError returns true if r matches m.
func (m MatchExpression) MatchWithError(r *http.Request) (bool, error) {
	celReq := celHTTPRequest{r}
	out, _, err := m.prg.Eval(celReq)
	if err != nil {
		m.log.Error("evaluating expression", zap.Error(err))
		return false, err
	}
	if outBool, ok := out.Value().(bool); ok {
		return outBool, nil
	}
	return false, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchExpression) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume matcher name

	// if there's multiple args, then we need to keep the raw
	// tokens because the user may have used quotes within their
	// CEL expression (e.g. strings) and we should retain that
	if d.CountRemainingArgs() > 1 {
		m.Expr = strings.Join(d.RemainingArgsRaw(), " ")
		return nil
	}

	// there should at least be one arg
	if !d.NextArg() {
		return d.ArgErr()
	}

	// if there's only one token, then we can safely grab the
	// cleaned token (no quotes) and use that as the expression
	// because there's no valid CEL expression that is only a
	// quoted string; commonly quotes are used in Caddyfile to
	// define the expression
	m.Expr = d.Val()

	// use the named matcher's name, to fill regexp
	// matchers names by default
	m.Name = d.GetContextString(caddyfile.MatcherNameCtxKey)

	return nil
}

// caddyPlaceholderFunc implements the custom CEL function that accesses the
// Replacer on a request and gets values from it.
func (m MatchExpression) caddyPlaceholderFunc(lhs, rhs ref.Val) ref.Val {
	celReq, ok := lhs.(celHTTPRequest)
	if !ok {
		return types.NewErr(
			"invalid request of type '%v' to %s(request, placeholderVarName)",
			lhs.Type(),
			CELPlaceholderFuncName,
		)
	}
	phStr, ok := rhs.(types.String)
	if !ok {
		return types.NewErr(
			"invalid placeholder variable name of type '%v' to %s(request, placeholderVarName)",
			rhs.Type(),
			CELPlaceholderFuncName,
		)
	}

	repl := celReq.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	val, _ := repl.Get(string(phStr))

	return m.ta.NativeToValue(val)
}

// httpRequestCELType is the type representation of a native HTTP request.
var httpRequestCELType = cel.ObjectType("http.Request", traits.ReceiverType)

// celHTTPRequest wraps an http.Request with ref.Val interface methods.
//
// This type also implements the interpreter.Activation interface which
// drops allocation costs for CEL expression evaluations by roughly half.
type celHTTPRequest struct{ *http.Request }

func (cr celHTTPRequest) ResolveName(name string) (any, bool) {
	if name == CELRequestVarName {
		return cr, true
	}
	return nil, false
}

func (cr celHTTPRequest) Parent() interpreter.Activation {
	return nil
}

func (cr celHTTPRequest) ConvertToNative(typeDesc reflect.Type) (any, error) {
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
func (celHTTPRequest) Type() ref.Type { return httpRequestCELType }
func (cr celHTTPRequest) Value() any  { return cr }

var pkixNameCELType = cel.ObjectType("pkix.Name", traits.ReceiverType)

// celPkixName wraps an pkix.Name with
// methods to satisfy the ref.Val interface.
type celPkixName struct{ *pkix.Name }

func (pn celPkixName) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return pn.Name, nil
}

func (pn celPkixName) ConvertToType(typeVal ref.Type) ref.Val {
	if typeVal.TypeName() == "string" {
		return types.String(pn.Name.String())
	}
	panic("not implemented")
}

func (pn celPkixName) Equal(other ref.Val) ref.Val {
	if o, ok := other.Value().(string); ok {
		return types.Bool(pn.Name.String() == o)
	}
	return types.ValOrErr(other, "%v is not comparable type", other)
}
func (celPkixName) Type() ref.Type { return pkixNameCELType }
func (pn celPkixName) Value() any  { return pn }

// celTypeAdapter can adapt our custom types to a CEL value.
type celTypeAdapter struct{}

func (celTypeAdapter) NativeToValue(value any) ref.Val {
	switch v := value.(type) {
	case celHTTPRequest:
		return v
	case pkix.Name:
		return celPkixName{&v}
	case time.Time:
		return types.Timestamp{Time: v}
	case error:
		return types.WrapErr(v)
	}
	return types.DefaultTypeAdapter.NativeToValue(value)
}

// CELLibraryProducer provide CEL libraries that expose a Matcher
// implementation as a first class function within the CEL expression
// matcher.
type CELLibraryProducer interface {
	// CELLibrary creates a cel.Library which makes it possible to use the
	// target object within CEL expression matchers.
	CELLibrary(caddy.Context) (cel.Library, error)
}

// CELMatcherImpl creates a new cel.Library based on the following pieces of
// data:
//
//   - macroName: the function name to be used within CEL. This will be a macro
//     and not a function proper.
//   - funcName: the function overload name generated by the CEL macro used to
//     represent the matcher.
//   - matcherDataTypes: the argument types to the macro.
//   - fac: a matcherFactory implementation which converts from CEL constant
//     values to a Matcher instance.
//
// Note, macro names and function names must not collide with other macros or
// functions exposed within CEL expressions, or an error will be produced
// during the expression matcher plan time.
//
// The existing CELMatcherImpl support methods are configured to support a
// limited set of function signatures. For strong type validation you may need
// to provide a custom macro which does a more detailed analysis of the CEL
// literal provided to the macro as an argument.
func CELMatcherImpl(macroName, funcName string, matcherDataTypes []*cel.Type, fac any) (cel.Library, error) {
	requestType := cel.ObjectType("http.Request")
	var macro parser.Macro
	switch len(matcherDataTypes) {
	case 1:
		matcherDataType := matcherDataTypes[0]
		switch matcherDataType.String() {
		case "list(string)":
			macro = parser.NewGlobalVarArgMacro(macroName, celMatcherStringListMacroExpander(funcName))
		case cel.StringType.String():
			macro = parser.NewGlobalMacro(macroName, 1, celMatcherStringMacroExpander(funcName))
		case CELTypeJSON.String():
			macro = parser.NewGlobalMacro(macroName, 1, celMatcherJSONMacroExpander(funcName))
		default:
			return nil, fmt.Errorf("unsupported matcher data type: %s", matcherDataType)
		}
	case 2:
		if matcherDataTypes[0] == cel.StringType && matcherDataTypes[1] == cel.StringType {
			macro = parser.NewGlobalMacro(macroName, 2, celMatcherStringListMacroExpander(funcName))
			matcherDataTypes = []*cel.Type{cel.ListType(cel.StringType)}
		} else {
			return nil, fmt.Errorf("unsupported matcher data type: %s, %s", matcherDataTypes[0], matcherDataTypes[1])
		}
	case 3:
		if matcherDataTypes[0] == cel.StringType && matcherDataTypes[1] == cel.StringType && matcherDataTypes[2] == cel.StringType {
			macro = parser.NewGlobalMacro(macroName, 3, celMatcherStringListMacroExpander(funcName))
			matcherDataTypes = []*cel.Type{cel.ListType(cel.StringType)}
		} else {
			return nil, fmt.Errorf("unsupported matcher data type: %s, %s, %s", matcherDataTypes[0], matcherDataTypes[1], matcherDataTypes[2])
		}
	}
	envOptions := []cel.EnvOption{
		cel.Macros(macro),
		cel.Function(funcName,
			cel.Overload(funcName, append([]*cel.Type{requestType}, matcherDataTypes...), cel.BoolType),
			cel.SingletonBinaryBinding(CELMatcherRuntimeFunction(funcName, fac))),
	}
	programOptions := []cel.ProgramOption{
		cel.CustomDecorator(CELMatcherDecorator(funcName, fac)),
	}
	return NewMatcherCELLibrary(envOptions, programOptions), nil
}

// CELMatcherFactory converts a constant CEL value into a RequestMatcher.
// Deprecated: Use CELMatcherWithErrorFactory instead.
type CELMatcherFactory = func(data ref.Val) (RequestMatcher, error)

// CELMatcherWithErrorFactory converts a constant CEL value into a RequestMatcherWithError.
type CELMatcherWithErrorFactory = func(data ref.Val) (RequestMatcherWithError, error)

// matcherCELLibrary is a simplistic configurable cel.Library implementation.
type matcherCELLibrary struct {
	envOptions     []cel.EnvOption
	programOptions []cel.ProgramOption
}

// NewMatcherCELLibrary creates a matcherLibrary from option setes.
func NewMatcherCELLibrary(envOptions []cel.EnvOption, programOptions []cel.ProgramOption) cel.Library {
	return &matcherCELLibrary{
		envOptions:     envOptions,
		programOptions: programOptions,
	}
}

func (lib *matcherCELLibrary) CompileOptions() []cel.EnvOption {
	return lib.envOptions
}

func (lib *matcherCELLibrary) ProgramOptions() []cel.ProgramOption {
	return lib.programOptions
}

// CELMatcherDecorator matches a call overload generated by a CEL macro
// that takes a single argument, and optimizes the implementation to precompile
// the matcher and return a function that references the precompiled and
// provisioned matcher.
func CELMatcherDecorator(funcName string, fac any) interpreter.InterpretableDecorator {
	return func(i interpreter.Interpretable) (interpreter.Interpretable, error) {
		call, ok := i.(interpreter.InterpretableCall)
		if !ok {
			return i, nil
		}
		if call.OverloadID() != funcName {
			return i, nil
		}
		callArgs := call.Args()
		reqAttr, ok := callArgs[0].(interpreter.InterpretableAttribute)
		if !ok {
			return nil, errors.New("missing 'req' argument")
		}
		nsAttr, ok := reqAttr.Attr().(interpreter.NamespacedAttribute)
		if !ok {
			return nil, errors.New("missing 'req' argument")
		}
		varNames := nsAttr.CandidateVariableNames()
		if len(varNames) != 1 || len(varNames) == 1 && varNames[0] != CELRequestVarName {
			return nil, errors.New("missing 'req' argument")
		}
		matcherData, ok := callArgs[1].(interpreter.InterpretableConst)
		if !ok {
			// If the matcher arguments are not constant, then this means
			// they contain a Caddy placeholder reference and the evaluation
			// and matcher provisioning should be handled at dynamically.
			return i, nil
		}

		if factory, ok := fac.(CELMatcherWithErrorFactory); ok {
			matcher, err := factory(matcherData.Value())
			if err != nil {
				return nil, err
			}
			return interpreter.NewCall(
				i.ID(), funcName, funcName+"_opt",
				[]interpreter.Interpretable{reqAttr},
				func(args ...ref.Val) ref.Val {
					// The request value, guaranteed to be of type celHTTPRequest
					celReq := args[0]
					// If needed this call could be changed to convert the value
					// to a *http.Request using CEL's ConvertToNative method.
					httpReq := celReq.Value().(celHTTPRequest)
					match, err := matcher.MatchWithError(httpReq.Request)
					if err != nil {
						return types.WrapErr(err)
					}
					return types.Bool(match)
				},
			), nil
		}

		if factory, ok := fac.(CELMatcherFactory); ok {
			matcher, err := factory(matcherData.Value())
			if err != nil {
				return nil, err
			}
			return interpreter.NewCall(
				i.ID(), funcName, funcName+"_opt",
				[]interpreter.Interpretable{reqAttr},
				func(args ...ref.Val) ref.Val {
					// The request value, guaranteed to be of type celHTTPRequest
					celReq := args[0]
					// If needed this call could be changed to convert the value
					// to a *http.Request using CEL's ConvertToNative method.
					httpReq := celReq.Value().(celHTTPRequest)
					if m, ok := matcher.(RequestMatcherWithError); ok {
						match, err := m.MatchWithError(httpReq.Request)
						if err != nil {
							return types.WrapErr(err)
						}
						return types.Bool(match)
					}
					return types.Bool(matcher.Match(httpReq.Request))
				},
			), nil
		}

		return nil, fmt.Errorf("invalid matcher factory, must be CELMatcherFactory or CELMatcherWithErrorFactory: %T", fac)
	}
}

// CELMatcherRuntimeFunction creates a function binding for when the input to the matcher
// is dynamically resolved rather than a set of static constant values.
func CELMatcherRuntimeFunction(funcName string, fac any) functions.BinaryOp {
	return func(celReq, matcherData ref.Val) ref.Val {
		if factory, ok := fac.(CELMatcherWithErrorFactory); ok {
			matcher, err := factory(matcherData)
			if err != nil {
				return types.WrapErr(err)
			}
			httpReq := celReq.Value().(celHTTPRequest)
			match, err := matcher.MatchWithError(httpReq.Request)
			if err != nil {
				return types.WrapErr(err)
			}
			return types.Bool(match)
		}
		if factory, ok := fac.(CELMatcherFactory); ok {
			matcher, err := factory(matcherData)
			if err != nil {
				return types.WrapErr(err)
			}
			httpReq := celReq.Value().(celHTTPRequest)
			if m, ok := matcher.(RequestMatcherWithError); ok {
				match, err := m.MatchWithError(httpReq.Request)
				if err != nil {
					return types.WrapErr(err)
				}
				return types.Bool(match)
			}
			return types.Bool(matcher.Match(httpReq.Request))
		}
		return types.NewErr("CELMatcherRuntimeFunction invalid matcher factory: %T", fac)
	}
}

// celMatcherStringListMacroExpander validates that the macro is called
// with a variable number of string arguments (at least one).
//
// The arguments are collected into a single list argument the following
// function call returned: <funcName>(request, [args])
func celMatcherStringListMacroExpander(funcName string) cel.MacroFactory {
	return func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
		matchArgs := []ast.Expr{}
		if len(args) == 0 {
			return nil, eh.NewError(0, "matcher requires at least one argument")
		}
		for _, arg := range args {
			if isCELStringExpr(arg) {
				matchArgs = append(matchArgs, arg)
			} else {
				return nil, eh.NewError(arg.ID(), "matcher arguments must be string constants")
			}
		}
		return eh.NewCall(funcName, eh.NewIdent(CELRequestVarName), eh.NewList(matchArgs...)), nil
	}
}

// celMatcherStringMacroExpander validates that the macro is called a single
// string argument.
//
// The following function call is returned: <funcName>(request, arg)
func celMatcherStringMacroExpander(funcName string) parser.MacroExpander {
	return func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
		if len(args) != 1 {
			return nil, eh.NewError(0, "matcher requires one argument")
		}
		if isCELStringExpr(args[0]) {
			return eh.NewCall(funcName, eh.NewIdent(CELRequestVarName), args[0]), nil
		}
		return nil, eh.NewError(args[0].ID(), "matcher argument must be a string literal")
	}
}

// celMatcherJSONMacroExpander validates that the macro is called a single
// map literal argument.
//
// The following function call is returned: <funcName>(request, arg)
func celMatcherJSONMacroExpander(funcName string) parser.MacroExpander {
	return func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
		if len(args) != 1 {
			return nil, eh.NewError(0, "matcher requires a map literal argument")
		}
		arg := args[0]

		switch arg.Kind() {
		case ast.StructKind:
			return nil, eh.NewError(arg.ID(),
				fmt.Sprintf("matcher input must be a map literal, not a %s", arg.AsStruct().TypeName()))
		case ast.MapKind:
			mapExpr := arg.AsMap()
			for _, entry := range mapExpr.Entries() {
				isStringPlaceholder := isCELStringExpr(entry.AsMapEntry().Key())
				if !isStringPlaceholder {
					return nil, eh.NewError(entry.ID(), "matcher map keys must be string literals")
				}
				isStringListPlaceholder := isCELStringExpr(entry.AsMapEntry().Value()) ||
					isCELStringListLiteral(entry.AsMapEntry().Value())
				if !isStringListPlaceholder {
					return nil, eh.NewError(entry.AsMapEntry().Value().ID(), "matcher map values must be string or list literals")
				}
			}
			return eh.NewCall(funcName, eh.NewIdent(CELRequestVarName), arg), nil
		case ast.UnspecifiedExprKind, ast.CallKind, ast.ComprehensionKind, ast.IdentKind, ast.ListKind, ast.LiteralKind, ast.SelectKind:
			// appeasing the linter :)
		}

		return nil, eh.NewError(arg.ID(), "matcher requires a map literal argument")
	}
}

// CELValueToMapStrList converts a CEL value to a map[string][]string
//
// Earlier validation stages should guarantee that the value has this type
// at compile time, and that the runtime value type is map[string]any.
// The reason for the slight difference in value type is that CEL allows for
// map literals containing heterogeneous values, in this case string and list
// of string.
func CELValueToMapStrList(data ref.Val) (map[string][]string, error) {
	mapStrType := reflect.TypeOf(map[string]any{})
	mapStrRaw, err := data.ConvertToNative(mapStrType)
	if err != nil {
		return nil, err
	}
	mapStrIface := mapStrRaw.(map[string]any)
	mapStrListStr := make(map[string][]string, len(mapStrIface))
	for k, v := range mapStrIface {
		switch val := v.(type) {
		case string:
			mapStrListStr[k] = []string{val}
		case types.String:
			mapStrListStr[k] = []string{string(val)}
		case []string:
			mapStrListStr[k] = val
		case []ref.Val:
			convVals := make([]string, len(val))
			for i, elem := range val {
				strVal, ok := elem.(types.String)
				if !ok {
					return nil, fmt.Errorf("unsupported value type in header match: %T", val)
				}
				convVals[i] = string(strVal)
			}
			mapStrListStr[k] = convVals
		default:
			return nil, fmt.Errorf("unsupported value type in header match: %T", val)
		}
	}
	return mapStrListStr, nil
}

// isCELStringExpr indicates whether the expression is a supported string expression
func isCELStringExpr(e ast.Expr) bool {
	return isCELStringLiteral(e) || isCELCaddyPlaceholderCall(e) || isCELConcatCall(e)
}

// isCELStringLiteral returns whether the expression is a CEL string literal.
func isCELStringLiteral(e ast.Expr) bool {
	switch e.Kind() {
	case ast.LiteralKind:
		constant := e.AsLiteral()
		switch constant.Type() {
		case types.StringType:
			return true
		}
	case ast.UnspecifiedExprKind, ast.CallKind, ast.ComprehensionKind, ast.IdentKind, ast.ListKind, ast.MapKind, ast.SelectKind, ast.StructKind:
		// appeasing the linter :)
	}
	return false
}

// isCELCaddyPlaceholderCall returns whether the expression is a caddy placeholder call.
func isCELCaddyPlaceholderCall(e ast.Expr) bool {
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		if call.FunctionName() == CELPlaceholderFuncName {
			return true
		}
	case ast.UnspecifiedExprKind, ast.ComprehensionKind, ast.IdentKind, ast.ListKind, ast.LiteralKind, ast.MapKind, ast.SelectKind, ast.StructKind:
		// appeasing the linter :)
	}
	return false
}

// isCELConcatCall tests whether the expression is a concat function (+) with string, placeholder, or
// other concat call arguments.
func isCELConcatCall(e ast.Expr) bool {
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		if call.Target().Kind() != ast.UnspecifiedExprKind {
			return false
		}
		if call.FunctionName() != operators.Add {
			return false
		}
		for _, arg := range call.Args() {
			if !isCELStringExpr(arg) {
				return false
			}
		}
		return true
	case ast.UnspecifiedExprKind, ast.ComprehensionKind, ast.IdentKind, ast.ListKind, ast.LiteralKind, ast.MapKind, ast.SelectKind, ast.StructKind:
		// appeasing the linter :)
	}
	return false
}

// isCELStringListLiteral returns whether the expression resolves to a list literal
// containing only string constants or a placeholder call.
func isCELStringListLiteral(e ast.Expr) bool {
	switch e.Kind() {
	case ast.ListKind:
		list := e.AsList()
		for _, elem := range list.Elements() {
			if !isCELStringExpr(elem) {
				return false
			}
		}
		return true
	case ast.UnspecifiedExprKind, ast.CallKind, ast.ComprehensionKind, ast.IdentKind, ast.LiteralKind, ast.MapKind, ast.SelectKind, ast.StructKind:
		// appeasing the linter :)
	}
	return false
}

// Variables used for replacing Caddy placeholders in CEL
// expressions with a proper CEL function call; this is
// just for syntactic sugar.
var (
	// The placeholder may not be preceded by a backslash; the expansion
	// will include the preceding character if it is not a backslash.
	placeholderRegexp    = regexp.MustCompile(`([^\\]|^){([a-zA-Z][\w.-]+)}`)
	placeholderExpansion = `${1}ph(req, "${2}")`

	// As a second pass, we need to strip the escape character in front of
	// the placeholder, if it exists.
	escapedPlaceholderRegexp    = regexp.MustCompile(`\\{([a-zA-Z][\w.-]+)}`)
	escapedPlaceholderExpansion = `{${1}}`

	CELTypeJSON = cel.MapType(cel.StringType, cel.DynType)
)

var httpRequestObjectType = cel.ObjectType("http.Request")

// The name of the CEL function which accesses Replacer values.
const CELPlaceholderFuncName = "ph"

// The name of the CEL request variable.
const CELRequestVarName = "req"

const MatcherNameCtxKey = "matcher_name"

// Interface guards
var (
	_ caddy.Provisioner       = (*MatchExpression)(nil)
	_ RequestMatcherWithError = (*MatchExpression)(nil)
	_ caddyfile.Unmarshaler   = (*MatchExpression)(nil)
	_ json.Marshaler          = (*MatchExpression)(nil)
	_ json.Unmarshaler        = (*MatchExpression)(nil)
)
