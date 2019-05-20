package headers

import (
	"net/http"
	"strings"

	"bitbucket.org/lightcodelabs/caddy2"
	"bitbucket.org/lightcodelabs/caddy2/modules/caddyhttp"
)

func init() {
	caddy2.RegisterModule(caddy2.Module{
		Name: "http.middleware.headers",
		New:  func() (interface{}, error) { return new(Headers), nil },
	})
}

// Headers is a middleware which can mutate HTTP headers.
type Headers struct {
	Request  HeaderOps
	Response RespHeaderOps
}

// HeaderOps defines some operations to
// perform on HTTP headers.
type HeaderOps struct {
	Add    http.Header
	Set    http.Header
	Delete []string
}

// RespHeaderOps is like HeaderOps, but
// optionally deferred until response time.
type RespHeaderOps struct {
	HeaderOps
	Deferred bool `json:"deferred"`
}

func (h Headers) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	apply(h.Request, r.Header)
	if h.Response.Deferred {
		w = &responseWriterWrapper{
			ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
			headerOps:             h.Response.HeaderOps,
		}
	} else {
		apply(h.Response.HeaderOps, w.Header())
	}
	return next.ServeHTTP(w, r)
}

func apply(ops HeaderOps, hdr http.Header) {
	for fieldName, vals := range ops.Add {
		for _, v := range vals {
			hdr.Add(fieldName, v)
		}
	}
	for fieldName, vals := range ops.Set {
		hdr.Set(fieldName, strings.Join(vals, ","))
	}
	for _, fieldName := range ops.Delete {
		hdr.Del(fieldName)
	}
}

// responseWriterWrapper defers response header
// operations until WriteHeader is called.
type responseWriterWrapper struct {
	*caddyhttp.ResponseWriterWrapper
	headerOps HeaderOps
}

func (rww *responseWriterWrapper) WriteHeader(status int) {
	apply(rww.headerOps, rww.ResponseWriterWrapper.Header())
	rww.ResponseWriterWrapper.WriteHeader(status)
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Headers)(nil)
	_ caddyhttp.HTTPInterfaces    = (*responseWriterWrapper)(nil)
)
