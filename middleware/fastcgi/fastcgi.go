// Package fastcgi has middleware that acts as a FastCGI client. Requests
// that get forwarded to FastCGI stop the middleware execution chain.
// The most common use for this package is to serve PHP websites via php-fpm.
package fastcgi

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Handler is a middleware type that can handle requests as a FastCGI client.
type Handler struct {
	Next    middleware.Handler
	Rules   []Rule
	Root    string
	AbsRoot string // same as root, but absolute path
	FileSys http.FileSystem

	// These are sent to CGI scripts in env variables
	SoftwareName    string
	SoftwareVersion string
	ServerName      string
	ServerPort      string
}

// ServeHTTP satisfies the middleware.Handler interface.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range h.Rules {

		// First requirement: Base path must match
		if !middleware.Path(r.URL.Path).Matches(rule.Path) {
			continue
		}

		// In addition to matching the path, a request must meet some
		// other criteria before being proxied as FastCGI. For example,
		// we probably want to exclude static assets (CSS, JS, images...)
		// but we also want to be flexible for the script we proxy to.

		fpath := r.URL.Path
		if idx, ok := middleware.IndexFile(h.FileSys, fpath, rule.IndexFiles); ok {
			fpath = idx
		}

		// These criteria work well in this order for PHP sites
		if fpath[len(fpath)-1] == '/' || strings.HasSuffix(fpath, rule.Ext) || !h.exists(fpath) {

			// Create environment for CGI script
			env, err := h.buildEnv(r, rule, fpath)
			if err != nil {
				return http.StatusInternalServerError, err
			}

			// Connect to FastCGI gateway
			var fcgi *FCGIClient

			// check if unix socket or tcp
			if strings.HasPrefix(rule.Address, "/") || strings.HasPrefix(rule.Address, "unix:") {
				if strings.HasPrefix(rule.Address, "unix:") {
					rule.Address = rule.Address[len("unix:"):]
				}
				fcgi, err = Dial("unix", rule.Address)
			} else {
				fcgi, err = Dial("tcp", rule.Address)
			}
			if err != nil {
				return http.StatusBadGateway, err
			}

			var resp *http.Response
			contentLength, _ := strconv.Atoi(r.Header.Get("Content-Length"))
			switch r.Method {
			case "HEAD":
				resp, err = fcgi.Head(env)
			case "GET":
				resp, err = fcgi.Get(env)
			case "OPTIONS":
				resp, err = fcgi.Options(env)
			case "POST":
				resp, err = fcgi.Post(env, r.Header.Get("Content-Type"), r.Body, contentLength)
			case "PUT":
				resp, err = fcgi.Put(env, r.Header.Get("Content-Type"), r.Body, contentLength)
			case "PATCH":
				resp, err = fcgi.Patch(env, r.Header.Get("Content-Type"), r.Body, contentLength)
			case "DELETE":
				resp, err = fcgi.Delete(env, r.Header.Get("Content-Type"), r.Body, contentLength)
			default:
				return http.StatusMethodNotAllowed, nil
			}

			if resp.Body != nil {
				defer resp.Body.Close()
			}

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
			// TODO: If this has an error, the response will already be
			// partly written. We should copy out of resp.Body into a buffer
			// first, then write it to the response...
			_, err = io.Copy(w, resp.Body)
			if err != nil {
				return http.StatusBadGateway, err
			}

			return 0, nil
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

// buildEnv returns a set of CGI environment variables for the request.
func (h Handler) buildEnv(r *http.Request, rule Rule, fpath string) (map[string]string, error) {
	var env map[string]string

	// Get absolute path of requested resource
	absPath := filepath.Join(h.AbsRoot, fpath)

	// Separate remote IP and port; more lenient than net.SplitHostPort
	var ip, port string
	if idx := strings.Index(r.RemoteAddr, ":"); idx > -1 {
		ip = r.RemoteAddr[:idx]
		port = r.RemoteAddr[idx+1:]
	} else {
		ip = r.RemoteAddr
	}

	// Split path in preparation for env variables
	splitPos := strings.Index(fpath, rule.SplitPath)
	var docURI, scriptName, scriptFilename, pathInfo string
	if splitPos == -1 {
		// Request doesn't have the extension, so assume index file in root
		docURI = "/" + rule.IndexFiles[0]
		scriptName = "/" + rule.IndexFiles[0]
		scriptFilename = filepath.Join(h.AbsRoot, rule.IndexFiles[0])
		pathInfo = fpath
	} else {
		// Request has the extension; path was split successfully
		docURI = fpath[:splitPos+len(rule.SplitPath)]
		pathInfo = fpath[splitPos+len(rule.SplitPath):]
		scriptName = fpath
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
		"DOCUMENT_ROOT":   h.AbsRoot,
		"DOCUMENT_URI":    docURI,
		"HTTP_HOST":       r.Host, // added here, since not always part of headers
		"REQUEST_URI":     r.URL.RequestURI(),
		"SCRIPT_FILENAME": scriptFilename,
		"SCRIPT_NAME":     scriptName,
	}

	// compliance with the CGI specification that PATH_TRANSLATED
	// should only exist if PATH_INFO is defined.
	// Info: https://www.ietf.org/rfc/rfc3875 Page 14
	if env["PATH_INFO"] != "" {
		env["PATH_TRANSLATED"] = filepath.Join(h.AbsRoot, pathInfo) // Info: http://www.oreilly.com/openbook/cgi/ch02_04.html
	}

	// Some web apps rely on knowing HTTPS or not
	if r.TLS != nil {
		env["HTTPS"] = "on"
	}

	// Add env variables from config
	for _, envVar := range rule.EnvVars {
		env[envVar[0]] = envVar[1]
	}

	// Add all HTTP headers to env variables
	for field, val := range r.Header {
		header := strings.ToUpper(field)
		header = headerNameReplacer.Replace(header)
		env["HTTP_"+header] = strings.Join(val, ", ")
	}

	return env, nil
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

	// If the URL ends with '/' (which indicates a directory), these index
	// files will be tried instead.
	IndexFiles []string

	// Environment Variables
	EnvVars [][2]string
}

var headerNameReplacer = strings.NewReplacer(" ", "_", "-", "_")
