// +build !go1.8

package push

import "net/http"

func (h Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// noop on go before 1.8
	return h.Next.ServeHTTP(w, r)
}

func http2PushSupported() bool {
	return false
}
