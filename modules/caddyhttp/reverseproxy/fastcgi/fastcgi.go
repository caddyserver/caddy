// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fastcgi

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddytls"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Transport{})
}

type Transport struct {
	//////////////////////////////
	// TODO: taken from v1 Handler type

	SoftwareName    string
	SoftwareVersion string
	ServerName      string
	ServerPort      string

	//////////////////////////
	// TODO: taken from v1 Rule type

	// The base path to match. Required.
	// Path string

	// upstream load balancer
	// balancer

	// Always process files with this extension with fastcgi.
	// Ext string

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

	// The duration used to set a deadline when connecting to an upstream.
	DialTimeout time.Duration

	// The duration used to set a deadline when reading from the FastCGI server.
	ReadTimeout time.Duration

	// The duration used to set a deadline when sending to the FastCGI server.
	WriteTimeout time.Duration
}

// CaddyModule returns the Caddy module information.
func (Transport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		Name: "http.handlers.reverse_proxy.transport.fastcgi",
		New:  func() caddy.Module { return new(Transport) },
	}
}

func (t Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Create environment for CGI script
	env, err := t.buildEnv(r)
	if err != nil {
		return nil, fmt.Errorf("building environment: %v", err)
	}

	// TODO:
	// Connect to FastCGI gateway
	// address, err := f.Address()
	// if err != nil {
	// 	return http.StatusBadGateway, err
	// }
	// network, address := parseAddress(address)
	network, address := "tcp", r.URL.Host // TODO:

	ctx := context.Background()
	if t.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.DialTimeout)
		defer cancel()
	}

	fcgiBackend, err := DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dialing backend: %v", err)
	}
	// fcgiBackend is closed when response body is closed (see clientCloser)

	// read/write timeouts
	if err := fcgiBackend.SetReadTimeout(t.ReadTimeout); err != nil {
		return nil, fmt.Errorf("setting read timeout: %v", err)
	}
	if err := fcgiBackend.SetWriteTimeout(t.WriteTimeout); err != nil {
		return nil, fmt.Errorf("setting write timeout: %v", err)
	}

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
		resp, err = fcgiBackend.Get(env, r.Body, contentLength)
	case "OPTIONS":
		resp, err = fcgiBackend.Options(env)
	default:
		resp, err = fcgiBackend.Post(env, r.Method, r.Header.Get("Content-Type"), r.Body, contentLength)
	}

	// TODO:
	return resp, err

	// Stuff brought over from v1 that might not be necessary here:

	// if resp != nil && resp.Body != nil {
	// 	defer resp.Body.Close()
	// }

	// if err != nil {
	// 	if err, ok := err.(net.Error); ok && err.Timeout() {
	// 		return http.StatusGatewayTimeout, err
	// 	} else if err != io.EOF {
	// 		return http.StatusBadGateway, err
	// 	}
	// }

	// // Write response header
	// writeHeader(w, resp)

	// // Write the response body
	// _, err = io.Copy(w, resp.Body)
	// if err != nil {
	// 	return http.StatusBadGateway, err
	// }

	// // Log any stderr output from upstream
	// if fcgiBackend.stderr.Len() != 0 {
	// 	// Remove trailing newline, error logger already does this.
	// 	err = LogError(strings.TrimSuffix(fcgiBackend.stderr.String(), "\n"))
	// }

	// // Normally we would return the status code if it is an error status (>= 400),
	// // however, upstream FastCGI apps don't know about our contract and have
	// // probably already written an error page. So we just return 0, indicating
	// // that the response body is already written. However, we do return any
	// // error value so it can be logged.
	// // Note that the proxy middleware works the same way, returning status=0.
	// return 0, err
}

// buildEnv returns a set of CGI environment variables for the request.
func (t Transport) buildEnv(r *http.Request) (map[string]string, error) {
	var env map[string]string

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

	// TODO: respect index files? or leave that to matcher/rewrite (I prefer that)?
	fpath := r.URL.Path

	// Split path in preparation for env variables.
	// Previous canSplit checks ensure this can never be -1.
	// TODO: I haven't brought over canSplit; make sure this doesn't break
	splitPos := t.splitPos(fpath)

	// Request has the extension; path was split successfully
	docURI := fpath[:splitPos+len(t.SplitPath)]
	pathInfo := fpath[splitPos+len(t.SplitPath):]
	scriptName := fpath

	// Strip PATH_INFO from SCRIPT_NAME
	scriptName = strings.TrimSuffix(scriptName, pathInfo)

	// SCRIPT_FILENAME is the absolute path of SCRIPT_NAME
	scriptFilename := filepath.Join(t.Root, scriptName)

	// Add vhost path prefix to scriptName. Otherwise, some PHP software will
	// have difficulty discovering its URL.
	pathPrefix, _ := r.Context().Value(caddy.CtxKey("path_prefix")).(string)
	scriptName = path.Join(pathPrefix, scriptName)

	// TODO: Disabled for now
	// // Get the request URI from context. The context stores the original URI in case
	// // it was changed by a middleware such as rewrite. By default, we pass the
	// // original URI in as the value of REQUEST_URI (the user can overwrite this
	// // if desired). Most PHP apps seem to want the original URI. Besides, this is
	// // how nginx defaults: http://stackoverflow.com/a/12485156/1048862
	// reqURL, _ := r.Context().Value(httpserver.OriginalURLCtxKey).(url.URL)

	// // Retrieve name of remote user that was set by some downstream middleware such as basicauth.
	// remoteUser, _ := r.Context().Value(httpserver.RemoteUserCtxKey).(string)

	requestScheme := "http"
	if r.TLS != nil {
		requestScheme = "https"
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
		// "REMOTE_USER":       remoteUser, // TODO:
		"REQUEST_METHOD":  r.Method,
		"REQUEST_SCHEME":  requestScheme,
		"SERVER_NAME":     t.ServerName,
		"SERVER_PORT":     t.ServerPort,
		"SERVER_PROTOCOL": r.Proto,
		"SERVER_SOFTWARE": t.SoftwareName + "/" + t.SoftwareVersion,

		// Other variables
		// "DOCUMENT_ROOT":   rule.Root,
		"DOCUMENT_URI": docURI,
		"HTTP_HOST":    r.Host, // added here, since not always part of headers
		// "REQUEST_URI":     reqURL.RequestURI(), // TODO:
		"SCRIPT_FILENAME": scriptFilename,
		"SCRIPT_NAME":     scriptName,
	}

	// compliance with the CGI specification requires that
	// PATH_TRANSLATED should only exist if PATH_INFO is defined.
	// Info: https://www.ietf.org/rfc/rfc3875 Page 14
	if env["PATH_INFO"] != "" {
		env["PATH_TRANSLATED"] = filepath.Join(t.Root, pathInfo) // Info: http://www.oreilly.com/openbook/cgi/ch02_04.html
	}

	// Some web apps rely on knowing HTTPS or not
	if r.TLS != nil {
		env["HTTPS"] = "on"
		// and pass the protocol details in a manner compatible with apache's mod_ssl
		// (which is why these have a SSL_ prefix and not TLS_).
		v, ok := tlsProtocolStrings[r.TLS.Version]
		if ok {
			env["SSL_PROTOCOL"] = v
		}
		// and pass the cipher suite in a manner compatible with apache's mod_ssl
		for k, v := range caddytls.SupportedCipherSuites {
			if v == r.TLS.CipherSuite {
				env["SSL_CIPHER"] = k
				break
			}
		}
	}

	// Add env variables from config (with support for placeholders in values)
	repl := r.Context().Value(caddy.ReplacerCtxKey).(caddy.Replacer)
	for _, envVar := range t.EnvVars {
		env[envVar[0]] = repl.ReplaceAll(envVar[1], "")
	}

	// Add all HTTP headers to env variables
	for field, val := range r.Header {
		header := strings.ToUpper(field)
		header = headerNameReplacer.Replace(header)
		env["HTTP_"+header] = strings.Join(val, ", ")
	}
	return env, nil
}

// splitPos returns the index where path should
// be split based on t.SplitPath.
func (t Transport) splitPos(path string) int {
	// TODO:
	// if httpserver.CaseSensitivePath {
	// 	return strings.Index(path, r.SplitPath)
	// }
	return strings.Index(strings.ToLower(path), strings.ToLower(t.SplitPath))
}

// TODO:
// Map of supported protocols to Apache ssl_mod format
// Note that these are slightly different from SupportedProtocols in caddytls/config.go
var tlsProtocolStrings = map[uint16]string{
	tls.VersionTLS10: "TLSv1",
	tls.VersionTLS11: "TLSv1.1",
	tls.VersionTLS12: "TLSv1.2",
	tls.VersionTLS13: "TLSv1.3",
}

var headerNameReplacer = strings.NewReplacer(" ", "_", "-", "_")
