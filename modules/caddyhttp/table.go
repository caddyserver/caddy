package caddyhttp

import (
	"net/http"

	"github.com/caddyserver/caddy"
)

func init() {
	caddy.RegisterModule(caddy.Module{
		Name: "http.middleware.table",
		New:  func() interface{} { return new(tableMiddleware) },
	})

	caddy.RegisterModule(caddy.Module{
		Name: "http.matchers.table",
		New:  func() interface{} { return new(tableMatcher) },
	})
}

type tableMiddleware struct {
}

func (t tableMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
	// tbl := r.Context().Value(TableCtxKey).(map[string]interface{})

	// TODO: implement this...

	return nil
}

type tableMatcher struct {
}

func (m tableMatcher) Match(r *http.Request) bool {
	return false // TODO: implement
}

// Interface guards
var _ MiddlewareHandler = (*tableMiddleware)(nil)
var _ RequestMatcher = (*tableMatcher)(nil)
