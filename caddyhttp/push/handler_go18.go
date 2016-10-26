// +build go1.8

package push

import (
	"net/http"
	"strings"

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

		code, err := h.Next.ServeHTTP(w, r)
		headers := w.Header()

		if links, exists := headers["Link"]; exists {
			h.pushLinks(pusher, links)
		}

		return code, err
	}

	return h.Next.ServeHTTP(w, r)
}

func (h Middleware) pushLinks(pusher http.Pusher, links []string) {
outer:
	for _, link := range links {
		parts := strings.Split(link, ";")

		if link == "" || strings.HasSuffix(link, "nopush") {
			continue
		}

		target := strings.TrimSuffix(strings.TrimPrefix(parts[0], "<"), ">")

		err := pusher.Push(target, &http.PushOptions{Method: "GET"})
		if err != nil {
			break outer
		}
	}
}

func http2PushSupported() bool {
	return true
}
