// Package fastcgi has middleware that acts as a FastCGI client. Requests
// that get forwarded to FastCGI stop the middleware execution chain.
// The most common use for this package is to serve PHP websites via php-fpm.
package fastcgi

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// New generates a new FastCGI middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	root, err := filepath.Abs(c.Root())
	if err != nil {
		return nil, err
	}

	rules, err := parse(c)
	if err != nil {
		return nil, err
	}

	return func(next middleware.Handler) middleware.Handler {
		return Handler{
			Next:            next,
			Rules:           rules,
			Root:            root,
			SoftwareName:    "Caddy", // TODO: Once generators are not in the same pkg as handler, obtain this from some global const
			SoftwareVersion: "",      // TODO: Get this from some global const too
			// TODO: Set ServerName and ServerPort to correct values... (as user defined in config)
		}
	}, nil
}

// Handler is a middleware type that can handle requests as a FastCGI client.
type Handler struct {
	Next  middleware.Handler
	Root  string // must be absolute path to site root
	Rules []Rule

	// These are sent to CGI scripts in env variables
	SoftwareName    string
	SoftwareVersion string
	ServerName      string
	ServerPort      string
}

// ServeHTTP satisfies the middleware.Handler interface.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range h.Rules {
		// In addition to matching the path, a request must meet some
		// other criteria before being proxied as FastCGI. For example,
		// we probably want to exclude static assets (CSS, JS, images...)
		// but we also want to be flexible for the script we proxy to.

		// These criteria work well in this order for PHP sites
		if middleware.Path(r.URL.Path).Matches(rule.Path) &&
			(r.URL.Path[len(r.URL.Path)-1] == '/' ||
				strings.HasSuffix(r.URL.Path, rule.Ext) ||
				!h.exists(r.URL.Path)) {

			// Create environment for CGI script
			env, err := h.buildEnv(r, rule)
			if err != nil {
				return http.StatusInternalServerError, err
			}

			// Connect to FastCGI gateway
			fcgi, err := Dial("tcp", rule.Address)
			if err != nil {
				return http.StatusBadGateway, err
			}

			// TODO: Allow more methods (requires refactoring fcgiclient first...)
			var resp *http.Response
			switch r.Method {
			case "GET":
				resp, err = fcgi.Get(env)
			case "POST":
				l, _ := strconv.Atoi(r.Header.Get("Content-Length"))
				resp, err = fcgi.Post(env, r.Header.Get("Content-Type"), r.Body, l)
			default:
				return http.StatusMethodNotAllowed, nil
			}
			defer resp.Body.Close()

			if err != nil && err != io.EOF {
				return http.StatusBadGateway, err
			}

			// Write the response header
			for key, vals := range resp.Header {
				for _, val := range vals {
					w.Header().Add(key, val)
				}
			}
			w.WriteHeader(resp.StatusCode)

			// Write the response body
			_, err = io.Copy(w, resp.Body)
			if err != nil {
				return http.StatusBadGateway, err
			}

			return resp.StatusCode, nil
		}
	}

	return h.Next.ServeHTTP(w, r)
}

func (h Handler) exists(path string) bool {
	if _, err := os.Stat(h.Root + path); err == nil {
		return true
	}
	return false
}

func (h Handler) buildEnv(r *http.Request, rule Rule) (map[string]string, error) {
	var env map[string]string

	// Get absolute path of requested resource
	absPath, err := filepath.Abs(h.Root + r.URL.Path)
	if err != nil {
		return env, err
	}

	// Separate remote IP and port; more lenient than net.SplitHostPort
	var ip, port string
	if idx := strings.Index(r.RemoteAddr, ":"); idx > -1 {
		ip = r.RemoteAddr[:idx]
		port = r.RemoteAddr[idx+1:]
	} else {
		ip = r.RemoteAddr
	}

	// Split path in preparation for env variables
	splitPos := strings.Index(r.URL.Path, rule.SplitPath)
	var docURI, scriptName, scriptFilename, pathInfo string
	if splitPos == -1 {
		// Request doesn't have the extension, so assume index file
		docURI = "/" + rule.IndexFile
		scriptName = "/" + rule.IndexFile
		scriptFilename = h.Root + "/" + rule.IndexFile
		pathInfo = r.URL.Path
	} else {
		// Request has the extension; path was split successfully
		docURI = r.URL.Path[:splitPos+len(rule.SplitPath)]
		pathInfo = r.URL.Path[splitPos+len(rule.SplitPath):]
		scriptName = r.URL.Path
		scriptFilename = absPath
	}

	// Some variables are unused but cleared explicitly to prevent
	// the parent environment from interfering.
	env = map[string]string{

		// Variables defined in CGI 1.1 spec
		"AUTH_TYPE":         "", // Not used
		"CONTENT_LENGTH":    r.Header.Get("Content-Length"),
		"CONTENT_TYPE":      r.Header.Get("Content-Type"),
		"GATEWAY_INTERFACE": "CGI/1.1",
		"PATH_INFO":         pathInfo,
		"PATH_TRANSLATED":   h.Root + "/" + pathInfo, // Source for path_translated: http://www.oreilly.com/openbook/cgi/ch02_04.html
		"QUERY_STRING":      r.URL.RawQuery,
		"REMOTE_ADDR":       ip,
		"REMOTE_HOST":       ip, // For speed, remote host lookups disabled
		"REMOTE_PORT":       port,
		"REMOTE_IDENT":      "", // Not used
		"REMOTE_USER":       "", // Not used
		"REQUEST_METHOD":    r.Method,
		"SERVER_NAME":       h.ServerName,
		"SERVER_PORT":       h.ServerPort,
		"SERVER_PROTOCOL":   r.Proto,
		"SERVER_SOFTWARE":   h.SoftwareName + "/" + h.SoftwareVersion,

		// Other variables
		"DOCUMENT_ROOT":   h.Root,
		"DOCUMENT_URI":    docURI,
		"HTTP_HOST":       r.Host, // added here, since not always part of headers
		"REQUEST_URI":     r.URL.RequestURI(),
		"SCRIPT_FILENAME": scriptFilename,
		"SCRIPT_NAME":     scriptName,
	}

	// Add all HTTP headers to env variables
	for field, val := range r.Header {
		header := strings.ToUpper(field)
		header = headerNameReplacer.Replace(header)
		env["HTTP_"+header] = strings.Join(val, ", ")
	}

	return env, nil
}

func parse(c middleware.Controller) ([]Rule, error) {
	var rules []Rule

	for c.Next() {
		var rule Rule

		args := c.RemainingArgs()

		switch len(args) {
		case 0:
			return rules, c.ArgErr()
		case 1:
			rule.Path = "/"
			rule.Address = args[0]
		case 2:
			rule.Path = args[0]
			rule.Address = args[1]
		case 3:
			rule.Path = args[0]
			rule.Address = args[1]
			err := preset(args[2], &rule)
			if err != nil {
				return rules, c.Err("Invalid fastcgi rule preset '" + args[2] + "'")
			}
		}

		for c.NextBlock() {
			switch c.Val() {
			case "ext":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.Ext = c.Val()
			case "split":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.SplitPath = c.Val()
			case "index":
				if !c.NextArg() {
					return rules, c.ArgErr()
				}
				rule.IndexFile = c.Val()
			}
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// preset configures rule according to name. It returns an error if
// name is not a recognized preset name.
func preset(name string, rule *Rule) error {
	switch name {
	case "php":
		rule.Ext = ".php"
		rule.SplitPath = ".php"
		rule.IndexFile = "index.php"
	default:
		return errors.New(name + " is not a valid preset name")
	}
	return nil
}

// Rule represents a FastCGI handling rule.
type Rule struct {
	// The base path to match. Required.
	Path string

	// The address of the FastCGI server. Required.
	Address string

	// Always process files with this extension with fastcgi.
	Ext string

	// The path in the URL will be split into two, with the first piece ending
	// with the value of SplitPath. The first piece will be assumed as the
	// actual resource (CGI script) name, and the second piece will be set to
	// PATH_INFO for the CGI script to use.
	SplitPath string

	// If the URL does not indicate a file, an index file with this name will be assumed.
	IndexFile string
}

var headerNameReplacer = strings.NewReplacer(" ", "_", "-", "_")
