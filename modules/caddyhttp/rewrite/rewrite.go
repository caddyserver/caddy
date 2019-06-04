package rewrite

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy2"
	"github.com/caddyserver/caddy2/modules/caddyhttp"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.middleware.rewrite",
		New:  func() interface{} { return new(Rewrite) },
	})
}

// Rewrite is a middleware which can rewrite HTTP requests.
type Rewrite struct {
	Method   string `json:"method,omitempty"`
	URI      string `json:"uri,omitempty"`
	Rehandle bool   `json:"rehandle,omitempty"`
}

func (rewr Rewrite) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy2.ReplacerCtxKey).(caddy2.Replacer)
	var rehandleNeeded bool

	if rewr.Method != "" {
		method := r.Method
		r.Method = strings.ToUpper(repl.ReplaceAll(rewr.Method, ""))
		if r.Method != method {
			rehandleNeeded = true
		}
	}

	if rewr.URI != "" {
		oldURI := r.RequestURI
		newURI := repl.ReplaceAll(rewr.URI, "")

		u, err := url.Parse(newURI)
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}

		r.RequestURI = newURI
		r.URL.Path = u.Path
		if u.RawQuery != "" {
			r.URL.RawQuery = u.RawQuery
		}
		if u.Fragment != "" {
			r.URL.Fragment = u.Fragment
		}

		if newURI != oldURI {
			rehandleNeeded = true
		}
	}

	if rehandleNeeded && rewr.Rehandle {
		return caddyhttp.ErrRehandle
	}

	return next.ServeHTTP(w, r)
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*Rewrite)(nil)
