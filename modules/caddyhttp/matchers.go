package caddyhttp

import (
	"fmt"
	"log"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"bitbucket.org/lightcodelabs/caddy2"
	"bitbucket.org/lightcodelabs/caddy2/pkg/caddyscript"
	"go.starlark.net/starlark"
)

type (
	// MatchHost matches requests by the Host value.
	MatchHost []string

	// MatchPath matches requests by the URI's path.
	MatchPath []string

	// MatchPathRE matches requests by a regular expression on the URI's path.
	MatchPathRE struct{ MatchRegexp }

	// MatchMethod matches requests by the method.
	MatchMethod []string

	// MatchQuery matches requests by URI's query string.
	MatchQuery url.Values

	// MatchHeader matches requests by header fields.
	MatchHeader http.Header

	// MatchHeaderRE matches requests by a regular expression on header fields.
	MatchHeaderRE map[string]*MatchRegexp

	// MatchProtocol matches requests by protocol.
	MatchProtocol string

	// MatchStarlarkExpr matches requests by evaluating a Starlark expression.
	MatchStarlarkExpr string

	// MatchTable matches requests by values in the table.
	MatchTable string // TODO: finish implementing
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.host",
		New:  func() interface{} { return MatchHost{} },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.path",
		New:  func() interface{} { return MatchPath{} },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.path_regexp",
		New:  func() interface{} { return new(MatchPathRE) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.method",
		New:  func() interface{} { return MatchMethod{} },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.query",
		New:  func() interface{} { return MatchQuery{} },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.header",
		New:  func() interface{} { return MatchHeader{} },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.header_regexp",
		New:  func() interface{} { return MatchHeaderRE{} },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.protocol",
		New:  func() interface{} { return new(MatchProtocol) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.starlark_expr",
		New:  func() interface{} { return new(MatchStarlarkExpr) },
	})
}

// Match returns true if r matches m.
func (m MatchHost) Match(r *http.Request) bool {
outer:
	for _, host := range m {
		if strings.Contains(host, "*") {
			patternParts := strings.Split(host, ".")
			incomingParts := strings.Split(r.Host, ".")
			if len(patternParts) != len(incomingParts) {
				continue
			}
			for i := range patternParts {
				if patternParts[i] == "*" {
					continue
				}
				if !strings.EqualFold(patternParts[i], incomingParts[i]) {
					continue outer
				}
			}
			return true
		} else if strings.EqualFold(r.Host, host) {
			return true
		}
	}
	return false
}

// Match returns true if r matches m.
func (m MatchPath) Match(r *http.Request) bool {
	for _, matchPath := range m {
		compare := r.URL.Path
		if strings.HasPrefix(matchPath, "*") {
			compare = path.Base(compare)
		}
		// can ignore error here because we can't handle it anyway
		matches, _ := filepath.Match(matchPath, compare)
		if matches {
			return true
		}
		if strings.HasPrefix(r.URL.Path, matchPath) {
			return true
		}
	}
	return false
}

// Match returns true if r matches m.
func (m MatchPathRE) Match(r *http.Request) bool {
	repl := r.Context().Value(caddy2.ReplacerCtxKey).(caddy2.Replacer)
	return m.MatchRegexp.Match(r.URL.Path, repl, "path_regexp")
}

// Match returns true if r matches m.
func (m MatchMethod) Match(r *http.Request) bool {
	for _, method := range m {
		if r.Method == method {
			return true
		}
	}
	return false
}

// Match returns true if r matches m.
func (m MatchQuery) Match(r *http.Request) bool {
	for param, vals := range m {
		paramVal := r.URL.Query().Get(param)
		for _, v := range vals {
			if paramVal == v {
				return true
			}
		}
	}
	return false
}

// Match returns true if r matches m.
func (m MatchHeader) Match(r *http.Request) bool {
	for field, allowedFieldVals := range m {
		var match bool
		actualFieldVals := r.Header[textproto.CanonicalMIMEHeaderKey(field)]
	fieldVals:
		for _, actualFieldVal := range actualFieldVals {
			for _, allowedFieldVal := range allowedFieldVals {
				if actualFieldVal == allowedFieldVal {
					match = true
					break fieldVals
				}
			}
		}
		if !match {
			return false
		}
	}
	return true
}

// Match returns true if r matches m.
func (m MatchHeaderRE) Match(r *http.Request) bool {
	for field, rm := range m {
		repl := r.Context().Value(caddy2.ReplacerCtxKey).(caddy2.Replacer)
		match := rm.Match(r.Header.Get(field), repl, "header_regexp")
		if !match {
			return false
		}
	}
	return true
}

// Provision compiles m's regular expressions.
func (m MatchHeaderRE) Provision() error {
	for _, rm := range m {
		err := rm.Provision()
		if err != nil {
			return err
		}
	}
	return nil
}

// Validate validates m's regular expressions.
func (m MatchHeaderRE) Validate() error {
	for _, rm := range m {
		err := rm.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// Match returns true if r matches m.
func (m MatchProtocol) Match(r *http.Request) bool {
	switch string(m) {
	case "grpc":
		return r.Header.Get("content-type") == "application/grpc"
	case "https":
		return r.TLS != nil
	case "http":
		return r.TLS == nil
	}
	return false
}

// Match returns true if r matches m.
func (m MatchStarlarkExpr) Match(r *http.Request) bool {
	input := string(m)
	thread := new(starlark.Thread)
	env := caddyscript.MatcherEnv(r)
	val, err := starlark.Eval(thread, "", input, env)
	if err != nil {
		// TODO: Can we detect this in Provision or Validate instead?
		log.Printf("caddyscript for matcher is invalid: attempting to evaluate expression `%v` error `%v`", input, err)
		return false
	}
	return val.String() == "True"
}

// MatchRegexp is an embeddable type for matching
// using regular expressions.
type MatchRegexp struct {
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`
	compiled *regexp.Regexp
}

// Provision compiles the regular expression.
func (mre *MatchRegexp) Provision() error {
	re, err := regexp.Compile(mre.Pattern)
	if err != nil {
		return fmt.Errorf("compiling matcher regexp %s: %v", mre.Pattern, err)
	}
	mre.compiled = re
	return nil
}

// Validate ensures mre is set up correctly.
func (mre *MatchRegexp) Validate() error {
	if mre.Name != "" && !wordRE.MatchString(mre.Name) {
		return fmt.Errorf("invalid regexp name (must contain only word characters): %s", mre.Name)
	}
	return nil
}

// Match returns true if input matches the compiled regular
// expression in mre. It sets values on the replacer repl
// associated with capture groups, using the given scope
// (namespace). Capture groups stored to repl will take on
// the name "http.matchers.<scope>.<mre.Name>.<N>" where
// <N> is the name or number of the capture group.
func (mre *MatchRegexp) Match(input string, repl caddy2.Replacer, scope string) bool {
	matches := mre.compiled.FindStringSubmatch(input)
	if matches == nil {
		return false
	}

	// save all capture groups, first by index
	for i, match := range matches {
		key := fmt.Sprintf("http.matchers.%s.%s.%d", scope, mre.Name, i)
		repl.Set(key, match)
	}

	// then by name
	for i, name := range mre.compiled.SubexpNames() {
		if i != 0 && name != "" {
			key := fmt.Sprintf("http.matchers.%s.%s.%s", scope, mre.Name, name)
			repl.Set(key, matches[i])
		}
	}

	return true
}

var wordRE = regexp.MustCompile(`\w+`)

// Interface guards
var (
	_ RequestMatcher = (*MatchHost)(nil)
	_ RequestMatcher = (*MatchPath)(nil)
	_ RequestMatcher = (*MatchPathRE)(nil)
	_ RequestMatcher = (*MatchMethod)(nil)
	_ RequestMatcher = (*MatchQuery)(nil)
	_ RequestMatcher = (*MatchHeader)(nil)
	_ RequestMatcher = (*MatchHeaderRE)(nil)
	_ RequestMatcher = (*MatchProtocol)(nil)
	_ RequestMatcher = (*MatchStarlarkExpr)(nil)
)
