package caddyhttp

import (
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"

	"github.com/caddyserver/caddy"
)

// TODO: A simple way to format or escape or encode each value would be nice
// ... TODO: Should we just use templates? :-/ yeesh...

func addHTTPVarsToReplacer(repl caddy.Replacer, req *http.Request, w http.ResponseWriter) {
	httpVars := func() map[string]string {
		m := make(map[string]string)
		if req != nil {
			m["http.request.host"] = func() string {
				host, _, err := net.SplitHostPort(req.Host)
				if err != nil {
					return req.Host // OK; there probably was no port
				}
				return host
			}()
			m["http.request.hostport"] = req.Host // may include both host and port
			m["http.request.method"] = req.Method
			m["http.request.port"] = func() string {
				// if there is no port, there will be an error; in
				// that case, port is the empty string anyway
				_, port, _ := net.SplitHostPort(req.Host)
				return port
			}()
			m["http.request.scheme"] = func() string {
				if req.TLS != nil {
					return "https"
				}
				return "http"
			}()
			m["http.request.uri"] = req.URL.RequestURI()
			m["http.request.uri.path"] = req.URL.Path
			m["http.request.uri.path.file"] = func() string {
				_, file := path.Split(req.URL.Path)
				return file
			}()
			m["http.request.uri.path.dir"] = func() string {
				dir, _ := path.Split(req.URL.Path)
				return dir
			}()
			m["http.request.uri.query"] = req.URL.RawQuery

			for param, vals := range req.URL.Query() {
				m["http.request.uri.query."+param] = strings.Join(vals, ",")
			}
			for field, vals := range req.Header {
				m["http.request.header."+strings.ToLower(field)] = strings.Join(vals, ",")
			}
			for _, cookie := range req.Cookies() {
				m["http.request.cookie."+cookie.Name] = cookie.Value
			}

			hostLabels := strings.Split(req.Host, ".")
			for i, label := range hostLabels {
				key := fmt.Sprintf("http.request.host.labels.%d", len(hostLabels)-i-1)
				m[key] = label
			}
		}

		if w != nil {
			for field, vals := range w.Header() {
				m["http.response.header."+strings.ToLower(field)] = strings.Join(vals, ",")
			}
		}

		return m
	}

	repl.Map(httpVars)
}
