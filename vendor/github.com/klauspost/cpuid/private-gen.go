// +build ignore

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"io/ioutil"
	"log"
	"os"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"
)

var inFiles = []string{"cpuid.go", "cpuid_test.go"}
var copyFiles = []string{"cpuid_amd64.s", "cpuid_386.s", "detect_ref.go", "detect_intel.go"}
var fileSet = token.NewFileSet()
var reWrites = []rewrite{
	initRewrite("CPUInfo -> cpuInfo"),
	initRewrite("Vendor -> vendor"),
	initRewrite("Flags -> flags"),
	initRewrite("Detect -> detect"),
	initRewrite("CPU -> cpu"),
}
var excludeNames = map[string]bool{"string": true, "join": true, "trim": true,
	// cpuid_test.go
	"t": true, "println": true, "logf": true, "log": true, "fatalf": true, "fatal": true,
}

var excludePrefixes = []string{"test", "benchmark"}

func main() {
	Package := "private"
	parserMode := parser.ParseComments
	exported := make(map[string]rewrite)
	for _, file := range inFiles {
		in, err := os.Open(file)
		if err != nil {
			log.Fatalf("opening input", err)
		}

		src, err := ioutil.ReadAll(in)
		if err != nil {
			log.Fatalf("reading input", err)
		}

		astfile, err := parser.ParseFile(fileSet, file, src, parserMode)
		if err != nil {
			log.Fatalf("parsing input", err)
		}

		for _, rw := range reWrites {
			astfile = rw(astfile)
		}

		// Inspect the AST and print all identifiers and literals.
		var startDecl token.Pos
		var endDecl token.Pos
		ast.Inspect(astfile, func(n ast.Node) bool {
			var s string
			switch x := n.(type) {
			case *ast.Ident:
				if x.IsExported() {
					t := strings.ToLower(x.Name)
					for _, pre := range excludePrefixes {
						if strings.HasPrefix(t, pre) {
							return true
						}
					}
					if excludeNames[t] != true {
						//if x.Pos() > startDecl && x.Pos() < endDecl {
						exported[x.Name] = initRewrite(x.Name + " -> " + t)
					}
				}

			case *ast.GenDecl:
				if x.Tok == token.CONST && x.Lparen > 0 {
					startDecl = x.Lparen
					endDecl = x.Rparen
					// fmt.Printf("Decl:%s -> %s\n", fileSet.Position(startDecl), fileSet.Position(endDecl))
				}
			}
			if s != "" {
				fmt.Printf("%s:\t%s\n", fileSet.Position(n.Pos()), s)
			}
			return true
		})

		for _, rw := range exported {
			astfile = rw(astfile)
		}

		var buf bytes.Buffer

		printer.Fprint(&buf, fileSet, astfile)

		// Remove package documentation and insert information
		s := buf.String()
		ind := strings.Index(buf.String(), "\npackage cpuid")
		s = s[ind:]
		s = "// Generated, DO NOT EDIT,\n" +
			"// but copy it to your own project and rename the package.\n" +
			"// See more at http://github.com/klauspost/cpuid\n" +
			s

		outputName := Package + string(os.PathSeparator) + file

		err = ioutil.WriteFile(outputName, []byte(s), 0644)
		if err != nil {
			log.Fatalf("writing output: %s", err)
		}
		log.Println("Generated", outputName)
	}

	for _, file := range copyFiles {
		dst := ""
		if strings.HasPrefix(file, "cpuid") {
			dst = Package + string(os.PathSeparator) + file
		} else {
			dst = Package + string(os.PathSeparator) + "cpuid_" + file
		}
		err := copyFile(file, dst)
		if err != nil {
			log.Fatalf("copying file: %s", err)
		}
		log.Println("Copied", dst)
	}
}

// CopyFile copies a file from src to dst. If src and dst files exist, and are
// the same, then return success. Copy the file contents from src to dst.
func copyFile(src, dst string) (err error) {
	sfi, err := os.Stat(src)
	if err != nil {
		return
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("CopyFile: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return
		}
	}
	err = copyFileContents(src, dst)
	return
}

// copyFileContents copies the contents of the file named src to the file named
// by dst. The file will be created if it does not already exist. If the
// destination file exists, all it's contents will be replaced by the contents
// of the source file.
func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

type rewrite func(*ast.File) *ast.File

// Mostly copied from gofmt
func initRewrite(rewriteRule string) rewrite {
	f := strings.Split(rewriteRule, "->")
	if len(f) != 2 {
		fmt.Fprintf(os.Stderr, "rewrite rule must be of the form 'pattern -> replacement'\n")
		os.Exit(2)
	}
	pattern := parseExpr(f[0], "pattern")
	replace := parseExpr(f[1], "replacement")
	return func(p *ast.File) *ast.File { return rewriteFile(pattern, replace, p) }
}

// parseExpr parses s as an expression.
// It might make sense to expand this to allow statement patterns,
// but there are problems with preserving formatting and also
// with what a wildcard for a statement looks like.
func parseExpr(s, what string) ast.Expr {
	x, err := parser.ParseExpr(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing %s %s at %s\n", what, s, err)
		os.Exit(2)
	}
	return x
}

// Keep this function for debugging.
/*
func dump(msg string, val reflect.Value) {
	fmt.Printf("%s:\n", msg)
	ast.Print(fileSet, val.Interface())
	fmt.Println()
}
*/

// rewriteFile applies the rewrite rule 'pattern -> replace' to an entire file.
func rewriteFile(pattern, replace ast.Expr, p *ast.File) *ast.File {
	cmap := ast.NewCommentMap(fileSet, p, p.Comments)
	m := make(map[string]reflect.Value)
	pat := reflect.ValueOf(pattern)
	repl := reflect.ValueOf(replace)

	var rewriteVal func(val reflect.Value) reflect.Value
	rewriteVal = func(val reflect.Value) reflect.Value {
		// don't bother if val is invalid to start with
		if !val.IsValid() {
			return reflect.Value{}
		}
		for k := range m {
			delete(m, k)
		}
		val = apply(rewriteVal, val)
		if match(m, pat, val) {
			val = subst(m, repl, reflect.ValueOf(val.Interface().(ast.Node).Pos()))
		}
		return val
	}

	r := apply(rewriteVal, reflect.ValueOf(p)).Interface().(*ast.File)
	r.Comments = cmap.Filter(r).Comments() // recreate comments list
	return r
}

// set is a wrapper for x.Set(y); it protects the caller from panics if x cannot be changed to y.
func set(x, y reflect.Value) {
	// don't bother if x cannot be set or y is invalid
	if !x.CanSet() || !y.IsValid() {
		return
	}
	defer func() {
		if x := recover(); x != nil {
			if s, ok := x.(string); ok &&
				(strings.Contains(s, "type mismatch") || strings.Contains(s, "not assignable")) {
				// x cannot be set to y - ignore this rewrite
				return
			}
			panic(x)
		}
	}()
	x.Set(y)
}

// Values/types for special cases.
var (
	objectPtrNil = reflect.ValueOf((*ast.Object)(nil))
	scopePtrNil  = reflect.ValueOf((*ast.Scope)(nil))

	identType     = reflect.TypeOf((*ast.Ident)(nil))
	objectPtrType = reflect.TypeOf((*ast.Object)(nil))
	positionType  = reflect.TypeOf(token.NoPos)
	callExprType  = reflect.TypeOf((*ast.CallExpr)(nil))
	scopePtrType  = reflect.TypeOf((*ast.Scope)(nil))
)

// apply replaces each AST field x in val with f(x), returning val.
// To avoid extra conversions, f operates on the reflect.Value form.
func apply(f func(reflect.Value) reflect.Value, val reflect.Value) reflect.Value {
	if !val.IsValid() {
		return reflect.Value{}
	}

	// *ast.Objects introduce cycles and are likely incorrect after
	// rewrite; don't follow them but replace with nil instead
	if val.Type() == objectPtrType {
		return objectPtrNil
	}

	// similarly for scopes: they are likely incorrect after a rewrite;
	// replace them with nil
	if val.Type() == scopePtrType {
		return scopePtrNil
	}

	switch v := reflect.Indirect(val); v.Kind() {
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			e := v.Index(i)
			set(e, f(e))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			e := v.Field(i)
			set(e, f(e))
		}
	case reflect.Interface:
		e := v.Elem()
		set(v, f(e))
	}
	return val
}

func isWildcard(s string) bool {
	rune, size := utf8.DecodeRuneInString(s)
	return size == len(s) && unicode.IsLower(rune)
}

// match returns true if pattern matches val,
// recording wildcard submatches in m.
// If m == nil, match checks whether pattern == val.
func match(m map[string]reflect.Value, pattern, val reflect.Value) bool {
	// Wildcard matches any expression.  If it appears multiple
	// times in the pattern, it must match the same expression
	// each time.
	if m != nil && pattern.IsValid() && pattern.Type() == identType {
		name := pattern.Interface().(*ast.Ident).Name
		if isWildcard(name) && val.IsValid() {
			// wildcards only match valid (non-nil) expressions.
			if _, ok := val.Interface().(ast.Expr); ok && !val.IsNil() {
				if old, ok := m[name]; ok {
					return match(nil, old, val)
				}
				m[name] = val
				return true
			}
		}
	}

	// Otherwise, pattern and val must match recursively.
	if !pattern.IsValid() || !val.IsValid() {
		return !pattern.IsValid() && !val.IsValid()
	}
	if pattern.Type() != val.Type() {
		return false
	}

	// Special cases.
	switch pattern.Type() {
	case identType:
		// For identifiers, only the names need to match
		// (and none of the other *ast.Object information).
		// This is a common case, handle it all here instead
		// of recursing down any further via reflection.
		p := pattern.Interface().(*ast.Ident)
		v := val.Interface().(*ast.Ident)
		return p == nil && v == nil || p != nil && v != nil && p.Name == v.Name
	case objectPtrType, positionType:
		// object pointers and token positions always match
		return true
	case callExprType:
		// For calls, the Ellipsis fields (token.Position) must
		// match since that is how f(x) and f(x...) are different.
		// Check them here but fall through for the remaining fields.
		p := pattern.Interface().(*ast.CallExpr)
		v := val.Interface().(*ast.CallExpr)
		if p.Ellipsis.IsValid() != v.Ellipsis.IsValid() {
			return false
		}
	}

	p := reflect.Indirect(pattern)
	v := reflect.Indirect(val)
	if !p.IsValid() || !v.IsValid() {
		return !p.IsValid() && !v.IsValid()
	}

	switch p.Kind() {
	case reflect.Slice:
		if p.Len() != v.Len() {
			return false
		}
		for i := 0; i < p.Len(); i++ {
			if !match(m, p.Index(i), v.Index(i)) {
				return false
			}
		}
		return true

	case reflect.Struct:
		for i := 0; i < p.NumField(); i++ {
			if !match(m, p.Field(i), v.Field(i)) {
				return false
			}
		}
		return true

	case reflect.Interface:
		return match(m, p.Elem(), v.Elem())
	}

	// Handle token integers, etc.
	return p.Interface() == v.Interface()
}

// subst returns a copy of pattern with values from m substituted in place
// of wildcards and pos used as the position of tokens from the pattern.
// if m == nil, subst returns a copy of pattern and doesn't change the line
// number information.
func subst(m map[string]reflect.Value, pattern reflect.Value, pos reflect.Value) reflect.Value {
	if !pattern.IsValid() {
		return reflect.Value{}
	}

	// Wildcard gets replaced with map value.
	if m != nil && pattern.Type() == identType {
		name := pattern.Interface().(*ast.Ident).Name
		if isWildcard(name) {
			if old, ok := m[name]; ok {
				return subst(nil, old, reflect.Value{})
			}
		}
	}

	if pos.IsValid() && pattern.Type() == positionType {
		// use new position only if old position was valid in the first place
		if old := pattern.Interface().(token.Pos); !old.IsValid() {
			return pattern
		}
		return pos
	}

	// Otherwise copy.
	switch p := pattern; p.Kind() {
	case reflect.Slice:
		v := reflect.MakeSlice(p.Type(), p.Len(), p.Len())
		for i := 0; i < p.Len(); i++ {
			v.Index(i).Set(subst(m, p.Index(i), pos))
		}
		return v

	case reflect.Struct:
		v := reflect.New(p.Type()).Elem()
		for i := 0; i < p.NumField(); i++ {
			v.Field(i).Set(subst(m, p.Field(i), pos))
		}
		return v

	case reflect.Ptr:
		v := reflect.New(p.Type()).Elem()
		if elem := p.Elem(); elem.IsValid() {
			v.Set(subst(m, elem, pos).Addr())
		}
		return v

	case reflect.Interface:
		v := reflect.New(p.Type()).Elem()
		if elem := p.Elem(); elem.IsValid() {
			v.Set(subst(m, elem, pos))
		}
		return v
	}

	return pattern
}
