package caddyhttp

import (
	"net/http"
	"strings"

	"bitbucket.org/lightcodelabs/caddy2"
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
}

// TODO: Matchers should probably support regex of some sort... performance trade-offs?

type (
	matchHost   []string
	matchPath   []string
	matchMethod []string
	matchQuery  map[string][]string
	matchHeader map[string][]string
)

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
)
