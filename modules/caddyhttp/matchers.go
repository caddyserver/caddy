package caddyhttp

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
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

	// MatchRemoteIP matches requests by client IP (or CIDR range).
	MatchRemoteIP struct {
		Ranges []string `json:"ranges,omitempty"`

		cidrs []*net.IPNet
	}

	// MatchNegate matches requests by negating its matchers' results.
	MatchNegate struct {
		matchersRaw map[string]json.RawMessage

		matchers MatcherSet
	}

	// MatchStarlarkExpr matches requests by evaluating a Starlark expression.
	MatchStarlarkExpr string

	// MatchTable matches requests by values in the table.
	MatchTable string // TODO: finish implementing
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.host",
		New:  func() interface{} { return new(MatchHost) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.path",
		New:  func() interface{} { return new(MatchPath) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.path_regexp",
		New:  func() interface{} { return new(MatchPathRE) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.method",
		New:  func() interface{} { return new(MatchMethod) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.query",
		New:  func() interface{} { return new(MatchQuery) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.header",
		New:  func() interface{} { return new(MatchHeader) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.header_regexp",
		New:  func() interface{} { return new(MatchHeaderRE) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.protocol",
		New:  func() interface{} { return new(MatchProtocol) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.remote_ip",
		New:  func() interface{} { return new(MatchRemoteIP) },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.not",
		New:  func() interface{} { return new(MatchNegate) },
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

// UnmarshalJSON unmarshals data into m's unexported map field.
// This is done because we cannot embed the map directly into
// the struct, but we need a struct because we need another
// field just for the provisioned modules.
func (m *MatchNegate) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &m.matchersRaw)
}

// Provision loads the matcher modules to be negated.
func (m *MatchNegate) Provision(ctx caddy2.Context) error {
	for modName, rawMsg := range m.matchersRaw {
		val, err := ctx.LoadModule("http.matchers."+modName, rawMsg)
		if err != nil {
			return fmt.Errorf("loading matcher module '%s': %v", modName, err)
		}
		m.matchers = append(m.matchers, val.(RequestMatcher))
	}
	m.matchersRaw = nil // allow GC to deallocate - TODO: Does this help?
	return nil
}

// Match returns true if r matches m. Since this matcher negates the
// embedded matchers, false is returned if any of its matchers match.
func (m MatchNegate) Match(r *http.Request) bool {
	return !m.matchers.Match(r)
}

// Provision parses m's IP ranges, either from IP or CIDR expressions.
func (m *MatchRemoteIP) Provision(ctx caddy2.Context) error {
	for _, str := range m.Ranges {
		if strings.Contains(str, "/") {
			_, ipNet, err := net.ParseCIDR(str)
			if err != nil {
				return fmt.Errorf("parsing CIDR expression: %v", err)
			}
			m.cidrs = append(m.cidrs, ipNet)
		} else {
			ip := net.ParseIP(str)
			if ip == nil {
				return fmt.Errorf("invalid IP address: %s", str)
			}
			mask := len(ip) * 8
			m.cidrs = append(m.cidrs, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(mask, mask),
			})
		}
	}
	return nil
}

func (m MatchRemoteIP) getClientIP(r *http.Request) (net.IP, error) {
	var remote string
	if fwdFor := r.Header.Get("X-Forwarded-For"); fwdFor != "" {
		remote = strings.TrimSpace(strings.Split(fwdFor, ",")[0])
	}
	if remote == "" {
		remote = r.RemoteAddr
	}

	ipStr, _, err := net.SplitHostPort(remote)
	if err != nil {
		ipStr = remote // OK; probably didn't have a port
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid client IP address: %s", ipStr)
	}

	return ip, nil
}

// Match returns true if r matches m.
func (m MatchRemoteIP) Match(r *http.Request) bool {
	clientIP, err := m.getClientIP(r)
	if err != nil {
		log.Printf("[ERROR] remote_ip matcher: %v", err)
		return false
	}
	for _, ipRange := range m.cidrs {
		if ipRange.Contains(clientIP) {
			return true
		}
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

// ResponseMatcher is a type which can determine if a given response
// status code and its headers match some criteria.
type ResponseMatcher struct {
	// If set, one of these status codes would be required.
	// A one-digit status can be used to represent all codes
	// in that class (e.g. 3 for all 3xx codes).
	StatusCode []int `json:"status_code,omitempty"`

	// If set, each header specified must be one of the specified values.
	Headers http.Header `json:"headers,omitempty"`
}

// Match returns true if the given statusCode and hdr match rm.
func (rm ResponseMatcher) Match(statusCode int, hdr http.Header) bool {
	if !rm.matchStatusCode(statusCode) {
		return false
	}
	return rm.matchHeaders(hdr)
}

func (rm ResponseMatcher) matchStatusCode(statusCode int) bool {
	if rm.StatusCode == nil {
		return true
	}
	for _, code := range rm.StatusCode {
		if statusCode == code {
			return true
		}
		if code < 100 && statusCode >= code*100 && statusCode < (code+1)*100 {
			return true
		}
	}
	return false
}

func (rm ResponseMatcher) matchHeaders(hdr http.Header) bool {
	for field, allowedFieldVals := range rm.Headers {
		var match bool
		actualFieldVals := hdr[textproto.CanonicalMIMEHeaderKey(field)]
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

var wordRE = regexp.MustCompile(`\w+`)

// Interface guards
var (
	_ RequestMatcher     = (*MatchHost)(nil)
	_ RequestMatcher     = (*MatchPath)(nil)
	_ RequestMatcher     = (*MatchPathRE)(nil)
	_ RequestMatcher     = (*MatchMethod)(nil)
	_ RequestMatcher     = (*MatchQuery)(nil)
	_ RequestMatcher     = (*MatchHeader)(nil)
	_ RequestMatcher     = (*MatchHeaderRE)(nil)
	_ RequestMatcher     = (*MatchProtocol)(nil)
	_ RequestMatcher     = (*MatchRemoteIP)(nil)
	_ caddy2.Provisioner = (*MatchRemoteIP)(nil)
	_ RequestMatcher     = (*MatchNegate)(nil)
	_ caddy2.Provisioner = (*MatchNegate)(nil)
	_ RequestMatcher     = (*MatchStarlarkExpr)(nil)
)
