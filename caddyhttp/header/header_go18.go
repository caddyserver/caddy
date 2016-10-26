// +build go1.8

package header

import "github.com/mholt/caddy/caddyhttp/httpserver"
import "net/http"

func (rww *responseWriterWrapper) Push(target string, opts *http.PushOptions) error {
	return httpserver.Push(rww.ResponseWriter, target, opts)
}
