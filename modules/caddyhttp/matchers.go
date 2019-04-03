package caddyhttp

import (
	"log"
	"net/http"
	"strings"

	"bitbucket.org/lightcodelabs/caddy2"
	"bitbucket.org/lightcodelabs/caddy2/internal/caddyscript"
	"go.starlark.net/starlark"
)

// TODO: Matchers should probably support regex of some sort... performance trade-offs?
type (
	matchHost     []string
	matchPath     []string
	matchMethod   []string
	matchQuery    map[string][]string
	matchHeader   map[string][]string
	matchProtocol string
	matchScript   string
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.host",
		New:  func() (interface{}, error) { return matchHost{}, nil },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.path",
		New:  func() (interface{}, error) { return matchPath{}, nil },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.method",
		New:  func() (interface{}, error) { return matchMethod{}, nil },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.query",
		New:  func() (interface{}, error) { return matchQuery{}, nil },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.header",
		New:  func() (interface{}, error) { return matchHeader{}, nil },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.protocol",
		New:  func() (interface{}, error) { return new(matchProtocol), nil },
	})
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.matchers.caddyscript",
		New:  func() (interface{}, error) { return new(matchScript), nil },
	})
}

func (m matchScript) Match(r *http.Request) bool {
	input := string(m)
	thread := new(starlark.Thread)
	env := caddyscript.MatcherEnv(r)
	val, err := starlark.Eval(thread, "", input, env)
	if err != nil {
		log.Printf("caddyscript for matcher is invalid: attempting to evaluate expression `%v` error `%v`", input, err)
		return false
	}

	return val.String() == "True"
}

func (m matchProtocol) Match(r *http.Request) bool {
	switch string(m) {
	case "grpc":
		if r.Header.Get("content-type") == "application/grpc" {
			return true
		}
	case "https":
		if r.TLS != nil {
			return true
		}
	case "http":
		if r.TLS == nil {
			return true
		}
	}

	return false
}

func (m matchHost) Match(r *http.Request) bool {
	for _, host := range m {
		if r.Host == host {
			return true
		}
	}
	return false
}

func (m matchPath) Match(r *http.Request) bool {
	for _, path := range m {
		if strings.HasPrefix(r.URL.Path, path) {
			return true
		}
	}
	return false
}

func (m matchMethod) Match(r *http.Request) bool {
	for _, method := range m {
		if r.Method == method {
			return true
		}
	}
	return false
}

func (m matchQuery) Match(r *http.Request) bool {
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

func (m matchHeader) Match(r *http.Request) bool {
	for field, vals := range m {
		fieldVals := r.Header[field]
		for _, fieldVal := range fieldVals {
			for _, v := range vals {
				if fieldVal == v {
					return true
				}
			}
		}
	}
	return false
}

var (
	_ RouteMatcher = matchHost{}
	_ RouteMatcher = matchPath{}
	_ RouteMatcher = matchMethod{}
	_ RouteMatcher = matchQuery{}
	_ RouteMatcher = matchHeader{}
	_ RouteMatcher = new(matchProtocol)
	_ RouteMatcher = new(matchScript)
)
