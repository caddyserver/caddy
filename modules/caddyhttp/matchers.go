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
	MatchHost         []string
	MatchPath         []string
	MatchPathRE       struct{ matchRegexp }
	MatchMethod       []string
	MatchQuery        url.Values
	MatchHeader       http.Header
	MatchHeaderRE     map[string]*matchRegexp
	MatchProtocol     string
	MatchStarlarkExpr string
	MatchTable        string // TODO: finish implementing
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

func (m MatchPathRE) Match(r *http.Request) bool {
	repl := r.Context().Value(caddy2.ReplacerCtxKey).(caddy2.Replacer)
	return m.match(r.URL.Path, repl, "path_regexp")
}

func (m MatchMethod) Match(r *http.Request) bool {
	for _, method := range m {
		if r.Method == method {
			return true
		}
	}
	return false
}

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

func (m MatchHeaderRE) Match(r *http.Request) bool {
	for field, rm := range m {
		repl := r.Context().Value(caddy2.ReplacerCtxKey).(caddy2.Replacer)
		match := rm.match(r.Header.Get(field), repl, "header_regexp")
		if !match {
			return false
		}
	}
	return true
}

func (m MatchHeaderRE) Provision() error {
	for _, rm := range m {
		err := rm.Provision()
		if err != nil {
			return err
		}
	}
	return nil
}

func (m MatchHeaderRE) Validate() error {
	for _, rm := range m {
		err := rm.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

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

// matchRegexp is just the fields common among
// matchers that can use regular expressions.
type matchRegexp struct {
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`
	compiled *regexp.Regexp
}

func (mre *matchRegexp) Provision() error {
	re, err := regexp.Compile(mre.Pattern)
	if err != nil {
		return fmt.Errorf("compiling matcher regexp %s: %v", mre.Pattern, err)
	}
	mre.compiled = re
	return nil
}

func (mre *matchRegexp) Validate() error {
	if mre.Name != "" && !wordRE.MatchString(mre.Name) {
		return fmt.Errorf("invalid regexp name (must contain only word characters): %s", mre.Name)
	}
	return nil
}

func (mre *matchRegexp) match(input string, repl caddy2.Replacer, scope string) bool {
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
