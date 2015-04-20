// Package fastcgi has middleware that acts as a FastCGI client. Requests
// that get forwarded to FastCGI stop the middleware execution chain.
// The most common use for this package is to serve PHP websites via php-fpm.
package fastcgi

import (
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// New generates a new FastCGI middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	root := c.Root()

	rules, err := parse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return Handler{Next: next, Rules: rules, Root: root}
	}, nil
}

// Handler is a middleware type that can handle requests as a FastCGI client.
type Handler struct {
	Next  middleware.Handler
	Root  string
	Rules []Rule
}

func (h Handler) DoesFileExist(path string) bool {
	file := h.Root + path
	if _, err := os.Stat(file); err == nil {
		return true
	}
	return false
}

// ServeHTTP satisfies the middleware.Handler interface.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	servedFcgi := false
	indexFile := "index.php"
	ext := ".php"
	splitText := ".php"
	for _, rule := range h.Rules {
		if middleware.Path(r.URL.Path).Matches(rule.Path) && (strings.HasSuffix(r.URL.Path, "/") ||
			strings.HasSuffix(r.URL.Path, ext) || !h.DoesFileExist(r.URL.Path)) {

			// Get absolute file paths
			absPath, err := filepath.Abs(h.Root + r.URL.Path)
			if err != nil {
				return http.StatusInternalServerError, err
			}

			// Get absolute file path to website root
			absRootPath, err := filepath.Abs(h.Root)
			if err != nil {
				return http.StatusInternalServerError, err
			}

			// Separate remote IP and port
			var ip, port string
			if idx := strings.Index(r.RemoteAddr, ":"); idx > -1 {
				ip = r.RemoteAddr[:idx]
				port = r.RemoteAddr[idx:]
			} else {
				ip = r.RemoteAddr
			}

			// TODO: Do we really have to make this map from scratch for each request?
			// TODO: We have quite a few more to map, too.
			env := make(map[string]string)
			env["SERVER_NAME"] = "caddy"
			env["SERVER_SOFTWARE"] = "caddy" // TODO: Obtain version info...
			env["SERVER_PROTOCOL"] = r.Proto
			env["SCRIPT_FILENAME"] = absPath
			env["REMOTE_ADDR"] = ip
			env["REMOTE_PORT"] = port
			env["REQUEST_METHOD"] = r.Method
			env["QUERY_STRING"] = r.URL.RawQuery
			env["SCRIPT_NAME"] = r.URL.Path
			env["HTTP_HOST"] = r.Host

			split := strings.Index(r.URL.Path, splitText)

			if split == -1 {
				//request doesn't have the extension
				//send the request to the index file
				env["DOCUMENT_URI"] = "/" + indexFile
				env["SCRIPT_NAME"] = "/" + indexFile
				env["SCRIPT_FILENAME"] = absRootPath + "/" + indexFile
				env["PATH_INFO"] = r.URL.Path
			} else {
				env["DOCUMENT_URI"] = r.URL.Path[:split+len(splitText)]
				env["PATH_INFO"] = r.URL.Path[split+len(splitText):]
			}

			env["REQUEST_URI"] = r.URL.RequestURI()

			env["DOCUMENT_ROOT"] = absRootPath
			env["HTTP_COOKIE"] = r.Header.Get("Cookie")

			fcgi, err := Dial("tcp", rule.Address)
			if err != nil {
				return http.StatusBadGateway, err
			}

			var resp *http.Response
			if r.Method == "GET" {
				resp, err = fcgi.Get(env)
			} else {
				l, _ := strconv.Atoi(r.Header.Get("Content-Length"))
				resp, err = fcgi.Post(env, r.Header.Get("Content-Type"), r.Body, l)
			}
			if err != nil && err != io.EOF {
				return http.StatusBadGateway, err
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return http.StatusBadGateway, err
			}

			for key, vals := range resp.Header {
				for _, val := range vals {
					w.Header().Add(key, val)
				}
			}

			w.WriteHeader(resp.StatusCode)
			w.Write(body)

			servedFcgi = true

			return resp.StatusCode, nil
		}
	}

	if !servedFcgi {
		return h.Next.ServeHTTP(w, r)
	}

	return 0, nil
}

func parse(c middleware.Controller) ([]Rule, error) {
	var rules []Rule

	for c.Next() {
		var rule Rule
		if !c.Args(&rule.Path, &rule.Address) {
			return rules, c.ArgErr()
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

// Rule represents a FastCGI handling rule.
type Rule struct {
	Path, Address string
}
