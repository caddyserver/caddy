package push

import (
	"net/http"
	"strings"

	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/mholt/caddy/caddyhttp/staticfiles"
)

func (h Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	pusher, hasPusher := w.(http.Pusher)

	// no push possible, carry on
	if !hasPusher {
		return h.Next.ServeHTTP(w, r)
	}

	// check if this is a request for the pushed resource (avoid recursion)
	if _, exists := r.Header[pushHeader]; exists {
		return h.Next.ServeHTTP(w, r)
	}

	headers := h.filterProxiedHeaders(r.Header)

	// push first
outer:
	for _, rule := range h.Rules {
		urlPath := r.URL.Path
		matches := httpserver.Path(urlPath).Matches(rule.Path)
		// Also check IndexPages when requesting a directory
		if !matches {
			_, matches = httpserver.IndexFile(h.Root, urlPath, staticfiles.IndexPages)
		}
		if matches {
			for _, resource := range rule.Resources {
				pushErr := pusher.Push(resource.Path, &http.PushOptions{
					Method: resource.Method,
					Header: h.mergeHeaders(headers, resource.Header),
				})
				if pushErr != nil {
					// if we cannot push (either not supported or concurrent streams are full - break)
					break outer
				}
			}
		}
	}

	// serve later
	code, err := h.Next.ServeHTTP(w, r)

	// push resources returned in Link headers from upstream middlewares or proxied apps
	if links, exists := w.Header()["Link"]; exists {
		h.servePreloadLinks(pusher, headers, links)
	}

	return code, err
}

func (h Middleware) servePreloadLinks(pusher http.Pusher, headers http.Header, links []string) {
	for _, link := range links {
		parts := strings.Split(link, ";")

		if link == "" || strings.HasSuffix(link, "nopush") {
			continue
		}

		target := strings.TrimSuffix(strings.TrimPrefix(parts[0], "<"), ">")

		err := pusher.Push(target, &http.PushOptions{
			Method: http.MethodGet,
			Header: headers,
		})

		if err != nil {
			break
		}
	}
}

func (h Middleware) mergeHeaders(l, r http.Header) http.Header {
	out := http.Header{}

	for k, v := range l {
		out[k] = v
	}

	for k, vv := range r {
		for _, v := range vv {
			out.Add(k, v)
		}
	}

	return out
}

func (h Middleware) filterProxiedHeaders(headers http.Header) http.Header {
	filter := http.Header{}

	for _, header := range proxiedHeaders {
		if val, ok := headers[header]; ok {
			filter[header] = val
		}
	}

	return filter
}

var proxiedHeaders = []string{
	"Accept-Encoding",
	"Accept-Language",
	"Cache-Control",
	"Host",
	"User-Agent",
}
