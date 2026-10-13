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
	"fmt"
	"slices"
	"strings"

	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/parser"

	"github.com/caddyserver/caddy/v2"
)

// CELLiteralMatcherFactory opts into distinguishing configured matcher text
// from evaluated CEL arguments. Unlike legacy factories, it must inspect its
// input with the CELMatcherString helpers before converting it to native data.
// Native conversion discards provenance. Evaluated strings are final data:
// use Template only for fields subsequently expanded by a replacer; use Value
// for raw fields such as regex patterns, and IsEvaluated for lookup keys.
// Configured literal arguments retain their existing placeholder semantics.
// CELMatcherImpl marks arguments automatically; custom macros must call
// CELMatcherLiteralArguments on their validated matcher data expression.
// Existing CELMatcherFactory and CELMatcherWithErrorFactory implementations
// retain their legacy behavior; this contract is explicitly opt-in.
type CELLiteralMatcherFactory func(data ref.Val) (RequestMatcherWithError, error)

// CELMatcherString is an immutable matcher string together with its origin.
// Obtain it through the CELMatcherString extraction helpers and copy it intact:
// converting to a plain string discards the distinction between configured
// placeholder syntax and evaluated data.
type CELMatcherString struct {
	value    string
	literal  bool
	segments []celMatcherSegment
	replacer *caddy.Replacer
}

// Value returns the original, unexpanded text. Use it for fields which do not
// interpret placeholders, such as header names or regular expression patterns.
func (s CELMatcherString) Value() string { return s.value }

// IsEvaluated reports whether the argument contains evaluated CEL data. A
// configured string literal returns false; a concatenation containing evaluated
// data returns true even when it also contains configured template segments.
// Matchers which interpret placeholder-shaped keys must use this distinction
// to keep evaluated keys as exact data rather than provider expressions.
func (s CELMatcherString) IsEvaluated() bool { return s.literal }

// Template returns text for exactly one subsequent caddy.Replacer expansion.
// That expansion removes the protection and emits evaluated data literally.
// Configured arguments retain their existing placeholder semantics. For mixed
// concatenations, Template resolves configured segments independently using the
// current request's replacer, so call it while constructing the matcher for
// that request. It may query providers and must not be cached across requests.
// Raw fields which do not use a replacer must use Value instead. Template only
// protects placeholder syntax; it preserves the matcher's other pattern syntax.
func (s CELMatcherString) Template() string {
	if len(s.segments) > 0 {
		var out strings.Builder
		for _, segment := range s.segments {
			text := segment.text
			if !segment.literal {
				// Resolve each configured segment independently, so data cannot
				// complete a placeholder begun by adjacent configured text.
				text = s.replacer.ReplaceAll(text, "")
			}
			out.WriteString(text)
		}
		return celMatcherBraceEscaper.Replace(out.String())
	}
	if !s.literal {
		return s.value
	}
	return celMatcherBraceEscaper.Replace(s.value)
}

// CELMatcherMapEntry preserves provenance for both a map key and its values.
type CELMatcherMapEntry struct {
	Key    CELMatcherString
	Values []CELMatcherString
}

// CELMatcherStringValue extracts a string without discarding its origin.
// An error-valued CEL argument is returned as an error, retaining its cause;
// callers must propagate it rather than stringify it as matcher data.
func CELMatcherStringValue(value ref.Val) (CELMatcherString, error) {
	if literal, ok := value.(*celMatcherLiteralString); ok {
		return CELMatcherString{value: string(literal.String), literal: true, segments: literal.segments, replacer: literal.replacer}, nil
	}
	if text, ok := value.(types.String); ok {
		return CELMatcherString{value: string(text)}, nil
	}
	if err, ok := value.(*types.Err); ok {
		return CELMatcherString{}, err
	}
	return CELMatcherString{}, fmt.Errorf("matcher argument must be a string, got %s", value.Type())
}

// CELMatcherStringList extracts the strings in a CEL list, preserving origin.
func CELMatcherStringList(value ref.Val) ([]CELMatcherString, error) {
	list, ok := value.(traits.Lister)
	if !ok {
		return nil, fmt.Errorf("matcher argument must be a string list, got %s", value.Type())
	}
	var result []CELMatcherString
	for i := types.Int(0); i < list.Size().(types.Int); i++ {
		text, err := CELMatcherStringValue(list.Get(i))
		if err != nil {
			return nil, err
		}
		result = append(result, text)
	}
	return result, nil
}

// CELMatcherStringMap extracts a CEL map whose values are strings or lists of
// strings. It keeps key provenance separate from value provenance. Entry order
// is unspecified. Distinct CEL keys with identical underlying text are rejected;
// callers must also reject collisions introduced by any key transformation.
func CELMatcherStringMap(value ref.Val) ([]CELMatcherMapEntry, error) {
	mapping, ok := value.(traits.Mapper)
	if !ok {
		return nil, fmt.Errorf("matcher argument must be a map, got %s", value.Type())
	}
	var entries []CELMatcherMapEntry
	seen := make(map[string]bool)
	iter := mapping.Iterator()
	for iter.HasNext() == types.True {
		key := iter.Next()
		text, err := CELMatcherStringValue(key)
		if err != nil {
			return nil, err
		}
		// A literal-aware map can have two differently annotated keys with
		// identical text. Reject that ambiguity before converting to a Go map.
		if seen[text.value] {
			return nil, fmt.Errorf("duplicate matcher map key %q", text.value)
		}
		seen[text.value] = true
		val := mapping.Get(key)
		var values []CELMatcherString
		if _, ok := val.(traits.Lister); ok {
			values, err = CELMatcherStringList(val)
		} else {
			var text CELMatcherString
			text, err = CELMatcherStringValue(val)
			values = []CELMatcherString{text}
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, CELMatcherMapEntry{Key: text, Values: values})
	}
	return entries, nil
}

// CELMatcherLiteralArguments preserves configured string literals and marks
// evaluated matcher string leaves as final data. Collection structure stays
// intact; evaluated expressions (including concatenations) are evaluated once.
func CELMatcherLiteralArguments(eh parser.ExprHelper, input ast.Expr) ast.Expr {
	switch input.Kind() {
	case ast.LiteralKind:
		return input
	case ast.ListKind:
		var elements []ast.Expr
		for _, element := range input.AsList().Elements() {
			elements = append(elements, CELMatcherLiteralArguments(eh, element))
		}
		return eh.NewList(elements...)
	case ast.MapKind:
		var entries []ast.EntryExpr
		for _, entry := range input.AsMap().Entries() {
			item := entry.AsMapEntry()
			entries = append(entries, eh.NewMapEntry(
				CELMatcherLiteralArguments(eh, item.Key()),
				CELMatcherLiteralArguments(eh, item.Value()), item.IsOptional()))
		}
		return eh.NewMap(entries...)
	case ast.UnspecifiedExprKind, ast.CallKind, ast.ComprehensionKind, ast.IdentKind, ast.SelectKind, ast.StructKind:
		if isCELConcatCall(input) {
			if !hasCELMatcherDynamicInput(input) {
				return input
			}
			args := input.AsCall().Args()
			return eh.NewCall(celMatcherConcatFuncName,
				CELMatcherLiteralArguments(eh, args[0]),
				CELMatcherLiteralArguments(eh, args[1]))
		}
		return eh.NewCall(celMatcherLiteralFuncName, eh.NewIdent(CELRequestVarName), input)
	}
	return input
}

func hasCELMatcherDynamicInput(input ast.Expr) bool {
	if isCELStringLiteral(input) {
		return false
	}
	if isCELConcatCall(input) {
		return slices.ContainsFunc(input.AsCall().Args(), hasCELMatcherDynamicInput)
	}
	return true
}

// Mark supported string/list/map argument shapes without traversing unsupported
// nested collections. Providers may expose cyclic native data; factories reject
// non-string list elements rather than recursively walking them.
func markCELMatcherLiteral(request, value ref.Val) ref.Val {
	req, ok := request.(celHTTPRequest)
	if !ok {
		return types.NewErr("invalid request type for matcher argument")
	}
	repl := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	markString := func(value ref.Val) ref.Val {
		if text, ok := value.(types.String); ok {
			return &celMatcherLiteralString{String: text, replacer: repl}
		}
		return value
	}
	markList := func(value ref.Val) ref.Val {
		list, ok := value.(traits.Lister)
		if !ok {
			return markString(value)
		}
		var values []ref.Val
		for i := types.Int(0); i < list.Size().(types.Int); i++ {
			values = append(values, markString(list.Get(i)))
		}
		return types.NewRefValList(types.DefaultTypeAdapter, values)
	}
	if mapping, ok := value.(traits.Mapper); ok {
		values := make(map[ref.Val]ref.Val)
		iter := mapping.Iterator()
		for iter.HasNext() == types.True {
			key := iter.Next()
			values[markString(key)] = markList(mapping.Get(key))
		}
		return types.NewRefValMap(types.DefaultTypeAdapter, values)
	}
	return markList(value)
}

func concatCELMatcherLiteral(lhs, rhs ref.Val) ref.Val {
	left, err := CELMatcherStringValue(lhs)
	if err != nil {
		return types.WrapErr(err)
	}
	right, err := CELMatcherStringValue(rhs)
	if err != nil {
		return types.WrapErr(err)
	}
	segments := func(s CELMatcherString) []celMatcherSegment {
		if len(s.segments) > 0 {
			return s.segments
		}
		return []celMatcherSegment{{text: s.value, literal: s.literal}}
	}
	repl := left.replacer
	if repl == nil {
		repl = right.replacer
	}
	return &celMatcherLiteralString{
		String:   types.String(left.value + right.value),
		segments: append(append([]celMatcherSegment{}, segments(left)...), segments(right)...),
		replacer: repl,
	}
}

// Pointer wrappers are comparable when CEL uses them as native Go map keys.
type celMatcherLiteralString struct {
	types.String
	segments []celMatcherSegment
	replacer *caddy.Replacer
}

type celMatcherSegment struct {
	text    string
	literal bool
}

var celMatcherBraceEscaper = strings.NewReplacer("{", `\{`, "}", `\}`)

const (
	celMatcherLiteralFuncName = "__caddy_matcher_literal"
	celMatcherConcatFuncName  = "__caddy_matcher_concat"
)
