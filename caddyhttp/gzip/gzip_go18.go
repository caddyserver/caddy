// +build go1.8

package gzip

import (
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func (w *gzipResponseWriter) Push(target string, opts *http.PushOptions) error {
	return httpserver.Push(w.ResponseWriter, target, opts)
}

// Interface guard
var _ http.Flusher = (*gzipResponseWriter)(nil)
