// +build go1.8

package push

import (
	"net/http"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

func (h Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	pusher, hasPusher := w.(http.Pusher)

	// No Pusher, no cry
	if hasPusher {
	outer:
		for _, rule := range h.Rules {
			if httpserver.Path(r.URL.Path).Matches(rule.Path) {
				for _, resource := range rule.Resources {
					err := pusher.Push(resource.Path, &http.PushOptions{
						Method: resource.Method,
						Header: resource.Header,
					})

					if err != nil {
						// If we cannot push (either not supported or concurrent streams are full - break)
						break outer
					}
				}
			}
		}
	}

	return h.Next.ServeHTTP(w, r)
}

func http2PushSupported() bool {
	return true
}
