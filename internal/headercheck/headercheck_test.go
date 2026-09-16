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

// Package headercheck verifies that every http.Header key written directly
// into the map uses net/http's canonical form.
//
// Hot paths index http.Header directly to skip the canonicalization that
// Get/Set/Add/Del perform on every call. That trades a linted call for an
// unlinted map operation: the canonicalheader linter only inspects method
// calls, and staticcheck's SA1008 stops descending as soon as an assignment
// writes to a header, so neither covers a direct write or a delete. A key
// that is not canonical there is a silent lookup miss, not a compile error.
//
// This covers three shapes the enabled linters miss:
//
//	h["x-key"] = []string{"v"}          // direct write
//	delete(h, "x-key")                  // delete builtin
//	h["x-key"] = append(h["x-key"], "v) // read-modify-write
//
// A helper that takes the key from its caller hides the literal from all of
// the above. Naming such a parameter with a canonical prefix, as
// headerGet(hdr, canonicalKey) does, opts every argument passed to it into
// the same verification.
package headercheck

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// headerType is the type whose map operations must use canonical keys.
const headerType = "net/http.Header"

// allowed are keys deliberately written with the RFC 6455 casing
// ("WebSocket", capital S) instead of net/http's canonical form, because
// some upstreams compare them case-sensitively. They are only ever written
// on the way out, never looked up against a parsed header map.
// See normalizeWebsocketHeaders and
// https://github.com/caddyserver/caddy/pull/6621.
var allowed = map[string]bool{
	"Sec-WebSocket-Accept":     true,
	"Sec-WebSocket-Extensions": true,
	"Sec-WebSocket-Key":        true,
	"Sec-WebSocket-Protocol":   true,
	"Sec-WebSocket-Version":    true,
}

func TestHeaderKeysAreCanonical(t *testing.T) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes |
			packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports,
		Dir:   "../..",
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatalf("loading packages: %v", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("packages failed to load; see errors above")
	}

	var checked int
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			checked += checkFile(t, pkg, file)
		}
	}

	// Guard against the walk silently covering nothing, e.g. if package
	// loading is reconfigured and stops yielding type information.
	if checked == 0 {
		t.Fatal("no http.Header map operations found; the check is not running")
	}
	t.Logf("checked %d direct http.Header map operations", checked)
}

// signatureOf resolves the signature of the function a call invokes.
func signatureOf(pkg *packages.Package, call *ast.CallExpr) (*types.Signature, bool) {
	var ident *ast.Ident
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		ident = fun
	case *ast.SelectorExpr:
		ident = fun.Sel
	default:
		return nil, false
	}
	fn, ok := pkg.TypesInfo.Uses[ident].(*types.Func)
	if !ok {
		return nil, false
	}
	sig, ok := fn.Type().(*types.Signature)
	return sig, ok
}

// checkFile reports the number of direct http.Header map operations examined.
func checkFile(t *testing.T, pkg *packages.Package, file *ast.File) int {
	var checked int

	report := func(pos token.Pos, key, form string) {
		canonical := http.CanonicalHeaderKey(key)
		if key == canonical || allowed[key] {
			return
		}
		t.Errorf("%s: %s uses non-canonical key %q; want %q",
			pkg.Fset.Position(pos), form, key, canonical)
	}

	// keyOf returns the constant string value of an index or argument
	// expression, so both literals and named constants are covered.
	keyOf := func(expr ast.Expr) (string, bool) {
		tv, ok := pkg.TypesInfo.Types[expr]
		if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
			return "", false
		}
		return constant.StringVal(tv.Value), true
	}

	isHeader := func(expr ast.Expr) bool {
		tv, ok := pkg.TypesInfo.Types[expr]
		if !ok || tv.Type == nil {
			return false
		}
		named, ok := tv.Type.(*types.Named)
		if !ok {
			return false
		}
		obj := named.Obj()
		return obj != nil && obj.Pkg() != nil &&
			obj.Pkg().Path()+"."+obj.Name() == headerType
	}

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		// h["Key"], including the assignment form h["Key"] = ...
		// that SA1008 skips.
		case *ast.IndexExpr:
			if !isHeader(node.X) {
				return true
			}
			key, ok := keyOf(node.Index)
			if !ok {
				return true
			}
			checked++
			report(node.Index.Pos(), key, "http.Header index")

		// delete(h, "Key"), which no enabled linter inspects.
		case *ast.CallExpr:
			if ident, ok := node.Fun.(*ast.Ident); ok && ident.Name == "delete" && len(node.Args) == 2 {
				if _, ok := pkg.TypesInfo.Uses[ident].(*types.Builtin); ok && isHeader(node.Args[0]) {
					if key, ok := keyOf(node.Args[1]); ok {
						checked++
						report(node.Args[1].Pos(), key, "delete on http.Header")
					}
					return true
				}
			}

			// Helpers that index a header with a key their caller supplies
			// hide the literal from every check above. Any parameter named
			// canonical* opts that argument into the same verification.
			sig, ok := signatureOf(pkg, node)
			if !ok {
				return true
			}
			params := sig.Params()
			for i := range params.Len() {
				if !strings.HasPrefix(params.At(i).Name(), "canonical") {
					continue
				}
				if sig.Variadic() && i == params.Len()-1 {
					break
				}
				if i >= len(node.Args) {
					break
				}
				key, ok := keyOf(node.Args[i])
				if !ok {
					continue
				}
				checked++
				report(node.Args[i].Pos(), key, "header key argument")
			}
		}
		return true
	})

	return checked
}
