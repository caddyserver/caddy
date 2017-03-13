// Package fastcgi has middleware that acts as a FastCGI client. Requests
// that get forwarded to FastCGI stop the middleware execution chain.
// The most common use for this package is to serve PHP websites via php-fpm.
package fastcgi

import (
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Handler is a middleware type that can handle requests as a FastCGI client.
type Handler struct {
	Next    httpserver.Handler
	Rules   []Rule
	Root    string
	FileSys http.FileSystem

	// These are sent to CGI scripts in env variables
	SoftwareName    string
	SoftwareVersion string
	ServerName      string
	ServerPort      string
}

// ServeHTTP satisfies the httpserver.Handler interface.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range h.Rules {

		// First requirement: Base path must match and the path must be allowed.
		if !httpserver.Path(r.URL.Path).Matches(rule.Path) || !rule.AllowedPath(r.URL.Path) {
			continue
		}

		// In addition to matching the path, a request must meet some
		// other criteria before being proxied as FastCGI. For example,
		// we probably want to exclude static assets (CSS, JS, images...)
		// but we also want to be flexible for the script we proxy to.

		fpath := r.URL.Path

		if idx, ok := httpserver.IndexFile(h.FileSys, fpath, rule.IndexFiles); ok {
			fpath = idx
			// Index file present.
			// If request path cannot be split, return error.
			if !rule.canSplit(fpath) {
				return http.StatusInternalServerError, ErrIndexMissingSplit
			}
		} else {
			// No index file present.
			// If request path cannot be split, ignore request.
			if !rule.canSplit(fpath) {
				continue
			}
		}

		// These criteria work well in this order for PHP sites
		if !h.exists(fpath) || fpath[len(fpath)-1] == '/' || strings.HasSuffix(fpath, rule.Ext) {

			// Create environment for CGI script
			env, err := h.buildEnv(r, rule, fpath)
			if err != nil {
				return http.StatusInternalServerError, err
			}

			// Connect to FastCGI gateway
			fcgiBackend, err := rule.dialer.Dial()
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return http.StatusGatewayTimeout, err
				}
				return http.StatusBadGateway, err
			}
			defer fcgiBackend.Close()
			fcgiBackend.SetReadTimeout(rule.ReadTimeout)
			fcgiBackend.SetSendTimeout(rule.SendTimeout)

			var resp *http.Response

			var contentLength int64
			// if ContentLength is already set
			if r.ContentLength > 0 {
				contentLength = r.ContentLength
			} else {
				contentLength, _ = strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
			}
			switch r.Method {
			case "HEAD":
				resp, err = fcgiBackend.Head(env)
			case "GET":
				resp, err = fcgiBackend.Get(env)
			case "OPTIONS":
				resp, err = fcgiBackend.Options(env)
			default:
				resp, err = fcgiBackend.Post(env, r.Method, r.Header.Get("Content-Type"), r.Body, contentLength)
			}

			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return http.StatusGatewayTimeout, err
				} else if err != io.EOF {
					return http.StatusBadGateway, err
				}
			}

			// Write response header
			writeHeader(w, resp)

			// Write the response body
			_, err = io.Copy(w, resp.Body)
			if err != nil {
				return http.StatusBadGateway, err
			}

			// Log any stderr output from upstream
			if stderr := fcgiBackend.StdErr(); stderr.Len() != 0 {
				// Remove trailing newline, error logger already does this.
				err = LogError(strings.TrimSuffix(stderr.String(), "\n"))
			}

			// Normally we would return the status code if it is an error status (>= 400),
			// however, upstream FastCGI apps don't know about our contract and have
			// probably already written an error page. So we just return 0, indicating
			// that the response body is already written. However, we do return any
			// error value so it can be logged.
			// Note that the proxy middleware works the same way, returning status=0.
			return 0, err
		}
	}

	return h.Next.ServeHTTP(w, r)
}

// parseAddress returns the network and address of fcgiAddress.
// The first string is the network, "tcp" or "unix", implied from the scheme and address.
// The second string is fcgiAddress, with scheme prefixes removed.
// The two returned strings can be used as parameters to the Dial() function.
func parseAddress(fcgiAddress string) (string, string) {
	// check if address has tcp scheme explicitly set
	if strings.HasPrefix(fcgiAddress, "tcp://") {
		return "tcp", fcgiAddress[len("tcp://"):]
	}
	// check if address has fastcgi scheme explicitly set
	if strings.HasPrefix(fcgiAddress, "fastcgi://") {
		return "tcp", fcgiAddress[len("fastcgi://"):]
	}
	// check if unix socket
	if trim := strings.HasPrefix(fcgiAddress, "unix"); strings.HasPrefix(fcgiAddress, "/") || trim {
		if trim {
			return "unix", fcgiAddress[len("unix:"):]
		}
		return "unix", fcgiAddress
	}
	// default case, a plain tcp address with no scheme
	return "tcp", fcgiAddress
}

func writeHeader(w http.ResponseWriter, r *http.Response) {
	for key, vals := range r.Header {
		for _, val := range vals {
			w.Header().Add(key, val)
		}
	}
	w.WriteHeader(r.StatusCode)
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
	absPath := filepath.Join(rule.Root, fpath)

	// Separate remote IP and port; more lenient than net.SplitHostPort
	var ip, port string
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > -1 {
		ip = r.RemoteAddr[:idx]
		port = r.RemoteAddr[idx+1:]
	} else {
		ip = r.RemoteAddr
	}

	// Remove [] from IPv6 addresses
	ip = strings.Replace(ip, "[", "", 1)
	ip = strings.Replace(ip, "]", "", 1)

	// Split path in preparation for env variables.
	// Previous rule.canSplit checks ensure this can never be -1.
	splitPos := rule.splitPos(fpath)

	// Request has the extension; path was split successfully
	docURI := fpath[:splitPos+len(rule.SplitPath)]
	pathInfo := fpath[splitPos+len(rule.SplitPath):]
	scriptName := fpath
	scriptFilename := absPath

	// Strip PATH_INFO from SCRIPT_NAME
	scriptName = strings.TrimSuffix(scriptName, pathInfo)

	// Get the request URI from context. The request URI might be as it came in over the wire,
	// or it might have been rewritten internally by the rewrite middleware (see issue #256).
	// If it was rewritten, there will be a context value with the original URL,
	// which is needed to get the correct RequestURI value for PHP apps.
	reqURI := r.URL.RequestURI()
	if origURI, _ := r.Context().Value(httpserver.URIxRewriteCtxKey).(string); origURI != "" {
		reqURI = origURI
	}

	// Retrieve name of remote user that was set by some downstream middleware,
	// possibly basicauth.
	remoteUser, _ := r.Context().Value(httpserver.RemoteUserCtxKey).(string) // Blank if not set

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
		"REMOTE_USER":       remoteUser,
		"REQUEST_METHOD":    r.Method,
		"SERVER_NAME":       h.ServerName,
		"SERVER_PORT":       h.ServerPort,
		"SERVER_PROTOCOL":   r.Proto,
		"SERVER_SOFTWARE":   h.SoftwareName + "/" + h.SoftwareVersion,

		// Other variables
		"DOCUMENT_ROOT":   rule.Root,
		"DOCUMENT_URI":    docURI,
		"HTTP_HOST":       r.Host, // added here, since not always part of headers
		"REQUEST_URI":     reqURI,
		"SCRIPT_FILENAME": scriptFilename,
		"SCRIPT_NAME":     scriptName,
	}

	// compliance with the CGI specification that PATH_TRANSLATED
	// should only exist if PATH_INFO is defined.
	// Info: https://www.ietf.org/rfc/rfc3875 Page 14
	if env["PATH_INFO"] != "" {
		env["PATH_TRANSLATED"] = filepath.Join(rule.Root, pathInfo) // Info: http://www.oreilly.com/openbook/cgi/ch02_04.html
	}

	// Some web apps rely on knowing HTTPS or not
	if r.TLS != nil {
		env["HTTPS"] = "on"
	}

	replacer := httpserver.NewReplacer(r, nil, "")
	// Add env variables from config
	for _, envVar := range rule.EnvVars {
		// replace request placeholders in environment variables
		env[envVar[0]] = replacer.Replace(envVar[1])
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
// It is parsed from the fastcgi directive in the Caddyfile, see setup.go.
type Rule struct {
	// The base path to match. Required.
	Path string

	// The address of the FastCGI server. Required.
	Address string

	// Always process files with this extension with fastcgi.
	Ext string

	// Use this directory as the fastcgi root directory. Defaults to the root
	// directory of the parent virtual host.
	Root string

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

	// Ignored paths
	IgnoredSubPaths []string

	// The duration used to set a deadline when reading from the FastCGI server.
	ReadTimeout time.Duration

	// The duration used to set a deadline when sending to the FastCGI server.
	SendTimeout time.Duration

	// FCGI dialer
	dialer dialer
}

// canSplit checks if path can split into two based on rule.SplitPath.
func (r Rule) canSplit(path string) bool {
	return r.splitPos(path) >= 0
}

// splitPos returns the index where path should be split
// based on rule.SplitPath.
func (r Rule) splitPos(path string) int {
	if httpserver.CaseSensitivePath {
		return strings.Index(path, r.SplitPath)
	}
	return strings.Index(strings.ToLower(path), strings.ToLower(r.SplitPath))
}

// AllowedPath checks if requestPath is not an ignored path.
func (r Rule) AllowedPath(requestPath string) bool {
	for _, ignoredSubPath := range r.IgnoredSubPaths {
		if httpserver.Path(path.Clean(requestPath)).Matches(path.Join(r.Path, ignoredSubPath)) {
			return false
		}
	}
	return true
}

var (
	headerNameReplacer = strings.NewReplacer(" ", "_", "-", "_")
	// ErrIndexMissingSplit describes an index configuration error.
	ErrIndexMissingSplit = errors.New("configured index file(s) must include split value")
)

// LogError is a non fatal error that allows requests to go through.
type LogError string

// Error satisfies error interface.
func (l LogError) Error() string {
	return string(l)
}
