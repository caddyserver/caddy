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

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
	"github.com/google/cel-go/interpreter"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/google/cel-go/parser"
	"go.uber.org/zap"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
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
	Expr string

	expandedExpr string
	prg          cel.Program
	ta           ref.TypeAdapter

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
	return json.Marshal(m.Expr)
}

// UnmarshalJSON unmarshals m's expression.
func (m *MatchExpression) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &m.Expr)
}

// Provision sets ups m.
func (m *MatchExpression) Provision(ctx caddy.Context) error {
	m.log = ctx.Logger()

	// replace placeholders with a function call - this is just some
	// light (and possibly naïve) syntactic sugar
	m.expandedExpr = placeholderRegexp.ReplaceAllString(m.Expr, placeholderExpansion)

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
		cel.Function(placeholderFuncName, cel.SingletonBinaryImpl(m.caddyPlaceholderFunc), cel.Overload(
			placeholderFuncName+"_httpRequest_string",
			[]*cel.Type{httpRequestObjectType, cel.StringType},
			cel.AnyType,
		)),
		cel.Variable("request", httpRequestObjectType),
		cel.CustomTypeAdapter(m.ta),
		ext.Strings(),
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
	celReq := celHTTPRequest{r}
	out, _, err := m.prg.Eval(celReq)
	if err != nil {
		m.log.Error("evaluating expression", zap.Error(err))
		SetVar(r.Context(), MatcherErrorVarKey, err)
		return false
	}
	if outBool, ok := out.Value().(bool); ok {
		return outBool
	}
	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (m *MatchExpression) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.CountRemainingArgs() > 1 {
			m.Expr = strings.Join(d.RemainingArgsRaw(), " ")
		} else {
			m.Expr = d.Val()
		}
	}
	return nil
}

// caddyPlaceholderFunc implements the custom CEL function that accesses the
// Replacer on a request and gets values from it.
func (m MatchExpression) caddyPlaceholderFunc(lhs, rhs ref.Val) ref.Val {
	celReq, ok := lhs.(celHTTPRequest)
	if !ok {
		return types.NewErr(
			"invalid request of type '%v' to "+placeholderFuncName+"(request, placeholderVarName)",
			lhs.Type(),
		)
	}
	phStr, ok := rhs.(types.String)
	if !ok {
		return types.NewErr(
			"invalid placeholder variable name of type '%v' to "+placeholderFuncName+"(request, placeholderVarName)",
			rhs.Type(),
		)
	}

	repl := celReq.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	val, _ := repl.Get(string(phStr))

	return m.ta.NativeToValue(val)
}

// httpRequestCELType is the type representation of a native HTTP request.
var httpRequestCELType = types.NewTypeValue("http.Request", traits.ReceiverType)

// celHTTPRequest wraps an http.Request with ref.Val interface methods.
//
// This type also implements the interpreter.Activation interface which
// drops allocation costs for CEL expression evaluations by roughly half.
type celHTTPRequest struct{ *http.Request }

func (cr celHTTPRequest) ResolveName(name string) (any, bool) {
	if name == "request" {
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

var pkixNameCELType = types.NewTypeValue("pkix.Name", traits.ReceiverType)

// celPkixName wraps an pkix.Name with
// methods to satisfy the ref.Val interface.
type celPkixName struct{ *pkix.Name }

func (pn celPkixName) ConvertToNative(typeDesc reflect.Type) (any, error) {
	return pn.Name, nil
}
func (celPkixName) ConvertToType(typeVal ref.Type) ref.Val {
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
		types.NewErr(v.Error())
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
func CELMatcherImpl(macroName, funcName string, matcherDataTypes []*cel.Type, fac CELMatcherFactory) (cel.Library, error) {
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
			cel.SingletonBinaryImpl(CELMatcherRuntimeFunction(funcName, fac))),
	}
	programOptions := []cel.ProgramOption{
		cel.CustomDecorator(CELMatcherDecorator(funcName, fac)),
	}
	return NewMatcherCELLibrary(envOptions, programOptions), nil
}

// CELMatcherFactory converts a constant CEL value into a RequestMatcher.
type CELMatcherFactory func(data ref.Val) (RequestMatcher, error)

// matcherCELLibrary is a simplistic configurable cel.Library implementation.
type matcherCELLibary struct {
	envOptions     []cel.EnvOption
	programOptions []cel.ProgramOption
}

// NewMatcherCELLibrary creates a matcherLibrary from option setes.
func NewMatcherCELLibrary(envOptions []cel.EnvOption, programOptions []cel.ProgramOption) cel.Library {
	return &matcherCELLibary{
		envOptions:     envOptions,
		programOptions: programOptions,
	}
}

func (lib *matcherCELLibary) CompileOptions() []cel.EnvOption {
	return lib.envOptions
}

func (lib *matcherCELLibary) ProgramOptions() []cel.ProgramOption {
	return lib.programOptions
}

// CELMatcherDecorator matches a call overload generated by a CEL macro
// that takes a single argument, and optimizes the implementation to precompile
// the matcher and return a function that references the precompiled and
// provisioned matcher.
func CELMatcherDecorator(funcName string, fac CELMatcherFactory) interpreter.InterpretableDecorator {
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
			return nil, errors.New("missing 'request' argument")
		}
		nsAttr, ok := reqAttr.Attr().(interpreter.NamespacedAttribute)
		if !ok {
			return nil, errors.New("missing 'request' argument")
		}
		varNames := nsAttr.CandidateVariableNames()
		if len(varNames) != 1 || len(varNames) == 1 && varNames[0] != "request" {
			return nil, errors.New("missing 'request' argument")
		}
		matcherData, ok := callArgs[1].(interpreter.InterpretableConst)
		if !ok {
			// If the matcher arguments are not constant, then this means
			// they contain a Caddy placeholder reference and the evaluation
			// and matcher provisioning should be handled at dynamically.
			return i, nil
		}
		matcher, err := fac(matcherData.Value())
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
				return types.Bool(matcher.Match(httpReq.Request))
			},
		), nil
	}
}

// CELMatcherRuntimeFunction creates a function binding for when the input to the matcher
// is dynamically resolved rather than a set of static constant values.
func CELMatcherRuntimeFunction(funcName string, fac CELMatcherFactory) functions.BinaryOp {
	return func(celReq, matcherData ref.Val) ref.Val {
		matcher, err := fac(matcherData)
		if err != nil {
			return types.NewErr(err.Error())
		}
		httpReq := celReq.Value().(celHTTPRequest)
		return types.Bool(matcher.Match(httpReq.Request))
	}
}

// celMatcherStringListMacroExpander validates that the macro is called
// with a variable number of string arguments (at least one).
//
// The arguments are collected into a single list argument the following
// function call returned: <funcName>(request, [args])
func celMatcherStringListMacroExpander(funcName string) parser.MacroExpander {
	return func(eh parser.ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
		matchArgs := []*exprpb.Expr{}
		if len(args) == 0 {
			return nil, &common.Error{
				Message: "matcher requires at least one argument",
			}
		}
		for _, arg := range args {
			if isCELStringExpr(arg) {
				matchArgs = append(matchArgs, arg)
			} else {
				return nil, &common.Error{
					Location: eh.OffsetLocation(arg.GetId()),
					Message:  "matcher arguments must be string constants",
				}
			}
		}
		return eh.GlobalCall(funcName, eh.Ident("request"), eh.NewList(matchArgs...)), nil
	}
}

// celMatcherStringMacroExpander validates that the macro is called a single
// string argument.
//
// The following function call is returned: <funcName>(request, arg)
func celMatcherStringMacroExpander(funcName string) parser.MacroExpander {
	return func(eh parser.ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
		if len(args) != 1 {
			return nil, &common.Error{
				Message: "matcher requires one argument",
			}
		}
		if isCELStringExpr(args[0]) {
			return eh.GlobalCall(funcName, eh.Ident("request"), args[0]), nil
		}
		return nil, &common.Error{
			Location: eh.OffsetLocation(args[0].GetId()),
			Message:  "matcher argument must be a string literal",
		}
	}
}

// celMatcherStringMacroExpander validates that the macro is called a single
// map literal argument.
//
// The following function call is returned: <funcName>(request, arg)
func celMatcherJSONMacroExpander(funcName string) parser.MacroExpander {
	return func(eh parser.ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
		if len(args) != 1 {
			return nil, &common.Error{
				Message: "matcher requires a map literal argument",
			}
		}
		arg := args[0]
		switch arg.GetExprKind().(type) {
		case *exprpb.Expr_StructExpr:
			structExpr := arg.GetStructExpr()
			if structExpr.GetMessageName() != "" {
				return nil, &common.Error{
					Location: eh.OffsetLocation(arg.GetId()),
					Message: fmt.Sprintf(
						"matcher input must be a map literal, not a %s",
						structExpr.GetMessageName(),
					),
				}
			}
			for _, entry := range structExpr.GetEntries() {
				isStringPlaceholder := isCELStringExpr(entry.GetMapKey())
				if !isStringPlaceholder {
					return nil, &common.Error{
						Location: eh.OffsetLocation(entry.GetId()),
						Message:  "matcher map keys must be string literals",
					}
				}
				isStringListPlaceholder := isCELStringExpr(entry.GetValue()) ||
					isCELStringListLiteral(entry.GetValue())
				if !isStringListPlaceholder {
					return nil, &common.Error{
						Location: eh.OffsetLocation(entry.GetValue().GetId()),
						Message:  "matcher map values must be string or list literals",
					}
				}
			}
			return eh.GlobalCall(funcName, eh.Ident("request"), arg), nil
		}

		return nil, &common.Error{
			Location: eh.OffsetLocation(arg.GetId()),
			Message:  "matcher requires a map literal argument",
		}
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
func isCELStringExpr(e *exprpb.Expr) bool {
	return isCELStringLiteral(e) || isCELCaddyPlaceholderCall(e) || isCELConcatCall(e)
}

// isCELStringLiteral returns whether the expression is a CEL string literal.
func isCELStringLiteral(e *exprpb.Expr) bool {
	switch e.GetExprKind().(type) {
	case *exprpb.Expr_ConstExpr:
		constant := e.GetConstExpr()
		switch constant.GetConstantKind().(type) {
		case *exprpb.Constant_StringValue:
			return true
		}
	}
	return false
}

// isCELCaddyPlaceholderCall returns whether the expression is a caddy placeholder call.
func isCELCaddyPlaceholderCall(e *exprpb.Expr) bool {
	switch e.GetExprKind().(type) {
	case *exprpb.Expr_CallExpr:
		call := e.GetCallExpr()
		if call.GetFunction() == "caddyPlaceholder" {
			return true
		}
	}
	return false
}

// isCELConcatCall tests whether the expression is a concat function (+) with string, placeholder, or
// other concat call arguments.
func isCELConcatCall(e *exprpb.Expr) bool {
	switch e.GetExprKind().(type) {
	case *exprpb.Expr_CallExpr:
		call := e.GetCallExpr()
		if call.GetTarget() != nil {
			return false
		}
		if call.GetFunction() != operators.Add {
			return false
		}
		for _, arg := range call.GetArgs() {
			if !isCELStringExpr(arg) {
				return false
			}
		}
		return true
	}
	return false
}

// isCELStringListLiteral returns whether the expression resolves to a list literal
// containing only string constants or a placeholder call.
func isCELStringListLiteral(e *exprpb.Expr) bool {
	switch e.GetExprKind().(type) {
	case *exprpb.Expr_ListExpr:
		list := e.GetListExpr()
		for _, elem := range list.GetElements() {
			if !isCELStringExpr(elem) {
				return false
			}
		}
		return true
	}
	return false
}

// Variables used for replacing Caddy placeholders in CEL
// expressions with a proper CEL function call; this is
// just for syntactic sugar.
var (
	placeholderRegexp    = regexp.MustCompile(`{([a-zA-Z][\w.-]+)}`)
	placeholderExpansion = `caddyPlaceholder(request, "${1}")`

	CELTypeJSON = cel.MapType(cel.StringType, cel.DynType)
)

var httpRequestObjectType = cel.ObjectType("http.Request")

// The name of the CEL function which accesses Replacer values.
const placeholderFuncName = "caddyPlaceholder"

// Interface guards
var (
	_ caddy.Provisioner     = (*MatchExpression)(nil)
	_ RequestMatcher        = (*MatchExpression)(nil)
	_ caddyfile.Unmarshaler = (*MatchExpression)(nil)
	_ json.Marshaler        = (*MatchExpression)(nil)
	_ json.Unmarshaler      = (*MatchExpression)(nil)
)
