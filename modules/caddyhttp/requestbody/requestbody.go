package requestbody

import (
	"net/http"

	"github.com/caddyserver/caddy2"
	"github.com/caddyserver/caddy2/modules/caddyhttp"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.middleware.request_body",
		New:  func() interface{} { return new(RequestBody) },
	})
}

// RequestBody is a middleware for manipulating the request body.
type RequestBody struct {
	MaxSize int64 `json:"max_size,omitempty"`
}

func (rb RequestBody) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Body == nil {
		return next.ServeHTTP(w, r)
	}
	if rb.MaxSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, rb.MaxSize)
	}
	return next.ServeHTTP(w, r)
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*RequestBody)(nil)
