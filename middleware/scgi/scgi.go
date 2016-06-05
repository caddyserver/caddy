// Package scgi has middleware that acts as a SCGI client. Requests
// that get forwarded to SCGI stop the middleware execution chain.
package scgi

import (
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/mholt/caddy/middleware"
)

// Handler is a middleware type that can handle requests as a SCGI client.
type Handler struct {
	Next    middleware.Handler
	Rules   []Rule
	Root    string
	AbsRoot string // same as root, but absolute path

	// These are sent to SCGI scripts in env variables
	SoftwareName    string
	SoftwareVersion string
	ServerName      string
	ServerPort      string
}

// ServeHTTP satisfies the middleware.Handler interface.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, rule := range h.Rules {

		// First requirement: Base path must match and the path must be allowed.
		if !middleware.Path(r.URL.Path).Matches(rule.Path) || !rule.AllowedPath(r.URL.Path) {
			continue
		}

		// In addition to matching the path, a request must meet some
		// other criteria before being proxied as SCGI. For example,
		// we probably want to exclude static assets (CSS, JS, images...)
		// but we also want to be flexible for the script we proxy to.

		fpath := r.URL.Path

		if !h.exists(fpath) || fpath[len(fpath)-1] == '/' {

			// Create environment for SCGI script
			env, err := h.buildEnv(r, rule, fpath)
			if err != nil {
				return http.StatusInternalServerError, err
			}

			// Connect to SCGI gateway
			network, address := rule.parseAddress()
			scgiBackend, err := Dial(network, address)
			if err != nil {
				return http.StatusBadGateway, err
			}

			var resp *http.Response
			contentLength, _ := strconv.Atoi(r.Header.Get("Content-Length"))
			switch r.Method {
			case "HEAD":
				resp, err = scgiBackend.Head(env)
			case "GET":
				resp, err = scgiBackend.Get(env)
			case "OPTIONS":
				resp, err = scgiBackend.Options(env)
			default:
				resp, err = scgiBackend.Post(env, r.Method, r.Header.Get("Content-Type"), r.Body, contentLength)
			}

			if resp.Body != nil {
				defer resp.Body.Close()
			}

			if err != nil && err != io.EOF {
				return http.StatusBadGateway, err
			}

			// Write response header
			writeHeader(w, resp)

			// Write the response body
			_, err = io.Copy(w, resp.Body)
			if err != nil {
				return http.StatusBadGateway, err
			}

			// Log any stderr output from upstream
			if scgiBackend.stderr.Len() != 0 {
				// Remove trailing newline, error logger already does this.
				err = LogError(strings.TrimSuffix(scgiBackend.stderr.String(), "\n"))
			}

			// Normally we would return the status code if it is an error status (>= 400),
			// however, upstream SCGI apps don't know about our contract and have
			// probably already written an error page. So we just return 0, indicating
			// that the response body is already written. However, we do return any
			// error value so it can be logged.
			// Note that the proxy middleware works the same way, returning status=0.
			return 0, err
		}
	}

	return h.Next.ServeHTTP(w, r)
}

// parseAddress returns the network and address of r.
// The first string is the network, "tcp" or "unix", implied from the scheme and address.
// The second string is r.Address, with scheme prefixes removed.
// The two returned strings can be used as parameters to the Dial() function.
func (r Rule) parseAddress() (string, string) {
	// check if address has tcp scheme explicitly set
	if strings.HasPrefix(r.Address, "tcp://") {
		return "tcp", r.Address[len("tcp://"):]
	}
	// check if address has scgi scheme explicitly set
	if strings.HasPrefix(r.Address, "scgi://") {
		return "tcp", r.Address[len("scgi://"):]
	}
	// check if unix socket
	if trim := strings.HasPrefix(r.Address, "unix"); strings.HasPrefix(r.Address, "/") || trim {
		if trim {
			return "unix", r.Address[len("unix:"):]
		}
		return "unix", r.Address
	}
	// default case, a plain tcp address with no scheme
	return "tcp", r.Address
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

	// Separate remote IP and port; more lenient than net.SplitHostPort
	var ip, port string
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > -1 {
		ip = r.RemoteAddr[:idx]
		port = r.RemoteAddr[idx+1:]
	} else {
		ip = r.RemoteAddr
	}

	// Get the request URI. The request URI might be as it came in over the wire,
	// or it might have been rewritten internally by the rewrite middleware (see issue #256).
	// If it was rewritten, there will be a header indicating the original URL,
	// which is needed to get the correct RequestURI value.
	const internalRewriteFieldName = "Caddy-Rewrite-Original-URI"
	reqURI := r.URL.RequestURI()
	if origURI := r.Header.Get(internalRewriteFieldName); origURI != "" {
		reqURI = origURI
		r.Header.Del(internalRewriteFieldName)
	}

	// Some variables are unused but cleared explicitly to prevent
	// the parent environment from interfering.
	env = map[string]string{

		// CONTENT_LENGTH must send at first
		"CONTENT_LENGTH":  r.Header.Get("Content-Length"),
		"CONTENT_TYPE":    r.Header.Get("Content-Type"),
		"SCGI":            "1",
		"QUERY_STRING":    r.URL.RawQuery,
		"REMOTE_ADDR":     ip,
		"REMOTE_HOST":     ip, // For speed, remote host lookups disabled
		"REMOTE_PORT":     port,
		"REQUEST_METHOD":  r.Method,
		"SERVER_NAME":     h.ServerName,
		"SERVER_PORT":     h.ServerPort,
		"SERVER_PROTOCOL": r.Proto,
		"SERVER_SOFTWARE": h.SoftwareName + "/" + h.SoftwareVersion,

		// Other variables
		"DOCUMENT_ROOT": h.AbsRoot,
		"DOCUMENT_URI":  fpath,
		"HTTP_HOST":     r.Host, // added here, since not always part of headers
		"REQUEST_URI":   reqURI,
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

// Rule represents a SCGI handling rule.
type Rule struct {
	// The base path to match. Required.
	Path string

	// The address of the SCGI server. Required.
	Address string

	// Environment Variables
	EnvVars [][2]string

	// Ignored paths
	IgnoredSubPaths []string
}

// AllowedPath checks if requestPath is not an ignored path.
func (r Rule) AllowedPath(requestPath string) bool {
	for _, ignoredSubPath := range r.IgnoredSubPaths {
		if middleware.Path(path.Clean(requestPath)).Matches(path.Join(r.Path, ignoredSubPath)) {
			return false
		}
	}
	return true
}

var (
	headerNameReplacer = strings.NewReplacer(" ", "_", "-", "_")
)

// LogError is a non fatal error that allows requests to go through.
type LogError string

// Error satisfies error interface.
func (l LogError) Error() string {
	return string(l)
}
