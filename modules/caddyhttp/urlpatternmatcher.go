package caddyhttp

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dunglas/go-urlpattern"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// urlPatternPlaceholderPrefix namespaces placeholders for captured groups.
const urlPatternPlaceholderPrefix = "http.url_pattern"

func init() {
	caddy.RegisterModule(&MatchURLPattern{})
}

// MatchURLPattern matches requests against a [URLPattern], giving named
// groups, wildcards and regexp components beyond what the simpler path
// matcher offers.
//
// [URLPattern]: https://urlpattern.spec.whatwg.org/
type MatchURLPattern struct {
	// Pattern is the URLPattern to match against. A relative pattern (e.g.
	// "/books/:id") matches the request path on any host; an absolute pattern
	// (e.g. "https://example.com/books/:id") also constrains scheme and host.
	Pattern string `json:"pattern,omitempty"`

	// BaseURL resolves a relative Pattern against a fixed origin, scoping the
	// match to that scheme and host. Leave empty to match any origin.
	BaseURL string `json:"base_url,omitempty"`

	// IgnoreCase matches the pattern case-insensitively.
	IgnoreCase bool `json:"ignore_case,omitempty"`

	compiledPattern *urlpattern.URLPattern
}

// CaddyModule returns the Caddy module information.
func (*MatchURLPattern) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.url_pattern",
		New: func() caddy.Module { return new(MatchURLPattern) },
	}
}

// Provision compiles the URL pattern.
func (m *MatchURLPattern) Provision(_ caddy.Context) error {
	input := m.Pattern

	// A relative pattern with no base matches any origin: prefix wildcard
	// protocol, host and port so only the path, search and hash are
	// constrained. The port wildcard is needed because a request Host may
	// carry an explicit port. Host-scoped matching stays opt-in via an
	// absolute pattern or base_url.
	if m.BaseURL == "" && !strings.Contains(input, "://") {
		input = "*://*:*" + input
	}

	p, err := urlpattern.New(input, m.BaseURL, &urlpattern.Options{IgnoreCase: m.IgnoreCase})
	if err != nil {
		return fmt.Errorf("unable to parse URL pattern: %w", err)
	}

	m.compiledPattern = p

	return nil
}

// Match returns true if the request matches the URL pattern.
func (m *MatchURLPattern) Match(r *http.Request) bool {
	ok, _ := m.MatchWithError(r)

	return ok
}

// MatchWithError returns true if the request matches the URL pattern. The
// request's origin (scheme://host) is the base against which the path is
// resolved, so an absolute pattern or base_url can match on scheme and host.
//
// On a match, captured groups are exposed as placeholders scoped by URL
// component, mirroring the URLPattern result object: a named group :id in the
// pathname becomes {http.url_pattern.pathname.id}, a group q in the query
// becomes {http.url_pattern.search.q}, and so on.
func (m *MatchURLPattern) MatchWithError(r *http.Request) (bool, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	result := m.compiledPattern.Exec(r.URL.RequestURI(), scheme+"://"+r.Host)
	if result == nil {
		return false, nil
	}

	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		setURLPatternGroups(repl, "protocol", result.Protocol)
		setURLPatternGroups(repl, "username", result.Username)
		setURLPatternGroups(repl, "password", result.Password)
		setURLPatternGroups(repl, "hostname", result.Hostname)
		setURLPatternGroups(repl, "port", result.Port)
		setURLPatternGroups(repl, "pathname", result.Pathname)
		setURLPatternGroups(repl, "search", result.Search)
		setURLPatternGroups(repl, "hash", result.Hash)
	}

	return true, nil
}

// setURLPatternGroups publishes a component's captured groups as
// {http.url_pattern.<component>.<group>} placeholders.
func setURLPatternGroups(repl *caddy.Replacer, component string, c urlpattern.URLPatternComponentResult) {
	for name, value := range c.Groups {
		repl.Set(urlPatternPlaceholderPrefix+"."+component+"."+name, value)
	}
}

// CELLibrary produces options that expose this matcher for use in CEL
// expression matchers.
//
// Example:
//
//	expression url_pattern('/books/:id')
//	expression url_pattern('/books/:id', 'https://example.com')
func (MatchURLPattern) CELLibrary(ctx caddy.Context) (cel.Library, error) {
	pattern, err := CELMatcherImpl(
		"url_pattern",
		"url_pattern_request_string",
		[]*cel.Type{cel.StringType},
		func(data ref.Val) (RequestMatcherWithError, error) {
			pattern, ok := data.Value().(string)
			if !ok {
				return nil, fmt.Errorf("url_pattern expects a string argument")
			}

			matcher := MatchURLPattern{Pattern: pattern}
			err := matcher.Provision(ctx)

			return &matcher, err
		},
	)
	if err != nil {
		return nil, err
	}

	patternWithBase, err := CELMatcherImpl(
		"url_pattern",
		"url_pattern_request_string_string",
		[]*cel.Type{cel.StringType, cel.StringType},
		func(data ref.Val) (RequestMatcherWithError, error) {
			params, err := data.ConvertToNative(stringSliceType)
			if err != nil {
				return nil, err
			}
			strParams := params.([]string)
			matcher := MatchURLPattern{Pattern: strParams[0], BaseURL: strParams[1]}
			err = matcher.Provision(ctx)
			return &matcher, err
		},
	)
	if err != nil {
		return nil, err
	}

	envOpts := append(pattern.CompileOptions(), patternWithBase.CompileOptions()...)
	prgOpts := append(pattern.ProgramOptions(), patternWithBase.ProgramOptions()...)
	return NewMatcherCELLibrary(envOpts, prgOpts), nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler. Syntax:
//
//	url_pattern <pattern> {
//	    base_url    <url>
//	    ignore_case
//	}
func (m *MatchURLPattern) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&m.Pattern) {
			return d.Err("expected exactly one URL pattern")
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "base_url":
				if !d.Args(&m.BaseURL) {
					return d.ArgErr()
				}
			case "ignore_case":
				if d.NextArg() {
					return d.ArgErr()
				}
				m.IgnoreCase = true
			default:
				return d.Errf("unrecognized url_pattern option '%s'", d.Val())
			}
		}
	}

	return nil
}

// Interface guards
var (
	_ RequestMatcherWithError = (*MatchURLPattern)(nil)
	_ caddy.Provisioner       = (*MatchURLPattern)(nil)
	_ caddyfile.Unmarshaler   = (*MatchURLPattern)(nil)
	_ CELLibraryProducer      = (*MatchURLPattern)(nil)
)
