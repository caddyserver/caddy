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
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(Transport{})
}

// Transport facilitates FastCGI communication.
type Transport struct {
	// Use this directory as the fastcgi root directory. Defaults to the root
	// directory of the parent virtual host.
	Root string `json:"root,omitempty"`

	// The path in the URL will be split into two, with the first piece ending
	// with the value of SplitPath. The first piece will be assumed as the
	// actual resource (CGI script) name, and the second piece will be set to
	// PATH_INFO for the CGI script to use.
	//
	// Future enhancements should be careful to avoid CVE-2019-11043,
	// which can be mitigated with use of a try_files-like behavior
	// that 404s if the fastcgi path info is not found.
	SplitPath []string `json:"split_path,omitempty"`

	// Path declared as root directory will be resolved to its absolute value
	// after the evaluation of any symbolic links.
	// Due to the nature of PHP opcache, root directory path is cached: when
	// using a symlinked directory as root this could generate errors when
	// symlink is changed without php-fpm being restarted; enabling this
	// directive will set $_SERVER['DOCUMENT_ROOT'] to the real directory path.
	ResolveRootSymlink bool `json:"resolve_root_symlink,omitempty"`

	// Extra environment variables.
	EnvVars map[string]string `json:"env,omitempty"`

	// The duration used to set a deadline when connecting to an upstream.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// The duration used to set a deadline when reading from the FastCGI server.
	ReadTimeout caddy.Duration `json:"read_timeout,omitempty"`

	// The duration used to set a deadline when sending to the FastCGI server.
	WriteTimeout caddy.Duration `json:"write_timeout,omitempty"`

	serverSoftware string
	logger         *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Transport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.fastcgi",
		New: func() caddy.Module { return new(Transport) },
	}
}

// Provision sets up t.
func (t *Transport) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger(t)
	if t.Root == "" {
		t.Root = "{http.vars.root}"
	}
	t.serverSoftware = "Caddy"
	if mod := caddy.GoModule(); mod.Version != "" {
		t.serverSoftware += "/" + mod.Version
	}
	return nil
}

// RoundTrip implements http.RoundTripper.
func (t Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	env, err := t.buildEnv(r)
	if err != nil {
		return nil, fmt.Errorf("building environment: %v", err)
	}

	// TODO: doesn't dialer have a Timeout field?
	ctx := r.Context()
	if t.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(t.DialTimeout))
		defer cancel()
	}

	// extract dial information from request (should have been embedded by the reverse proxy)
	network, address := "tcp", r.URL.Host
	if dialInfo, ok := reverseproxy.GetDialInfo(ctx); ok {
		network = dialInfo.Network
		address = dialInfo.Address
	}

	t.logger.Debug("roundtrip",
		zap.Object("request", caddyhttp.LoggableHTTPRequest{Request: r}),
		zap.String("dial", address),
		zap.Any("env", env), // TODO: this uses reflection I think
	)

	fcgiBackend, err := DialContext(ctx, network, address)
	if err != nil {
		// TODO: wrap in a special error type if the dial failed, so retries can happen if enabled
		return nil, fmt.Errorf("dialing backend: %v", err)
	}
	// fcgiBackend gets closed when response body is closed (see clientCloser)

	// read/write timeouts
	if err := fcgiBackend.SetReadTimeout(time.Duration(t.ReadTimeout)); err != nil {
		return nil, fmt.Errorf("setting read timeout: %v", err)
	}
	if err := fcgiBackend.SetWriteTimeout(time.Duration(t.WriteTimeout)); err != nil {
		return nil, fmt.Errorf("setting write timeout: %v", err)
	}

	contentLength := r.ContentLength
	if contentLength == 0 {
		contentLength, _ = strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	}

	var resp *http.Response
	switch r.Method {
	case http.MethodHead:
		resp, err = fcgiBackend.Head(env)
	case http.MethodGet:
		resp, err = fcgiBackend.Get(env, r.Body, contentLength)
	case http.MethodOptions:
		resp, err = fcgiBackend.Options(env)
	default:
		resp, err = fcgiBackend.Post(env, r.Method, r.Header.Get("Content-Type"), r.Body, contentLength)
	}

	return resp, err
}

// buildEnv returns a set of CGI environment variables for the request.
func (t Transport) buildEnv(r *http.Request) (map[string]string, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

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

	// make sure file root is absolute
	root, err := filepath.Abs(repl.ReplaceAll(t.Root, "."))
	if err != nil {
		return nil, err
	}

	if t.ResolveRootSymlink {
		root, err = filepath.EvalSymlinks(root)
		if err != nil {
			return nil, err
		}
	}

	fpath := r.URL.Path
	scriptName := fpath

	docURI := fpath
	// split "actual path" from "path info" if configured
	var pathInfo string
	if splitPos := t.splitPos(fpath); splitPos > -1 {
		docURI = fpath[:splitPos]
		pathInfo = fpath[splitPos:]

		// Strip PATH_INFO from SCRIPT_NAME
		scriptName = strings.TrimSuffix(scriptName, pathInfo)
	}

	// Try to grab the path remainder from a file matcher
	// if we didn't get a split result here.
	// See https://github.com/caddyserver/caddy/issues/3718
	if pathInfo == "" {
		if remainder, ok := repl.GetString("http.matchers.file.remainder"); ok {
			pathInfo = remainder
		}
	}

	// SCRIPT_FILENAME is the absolute path of SCRIPT_NAME
	scriptFilename := caddyhttp.SanitizedPathJoin(root, scriptName)

	// Ensure the SCRIPT_NAME has a leading slash for compliance with RFC3875
	// Info: https://tools.ietf.org/html/rfc3875#section-4.1.13
	if scriptName != "" && !strings.HasPrefix(scriptName, "/") {
		scriptName = "/" + scriptName
	}

	// Get the request URL from context. The context stores the original URL in case
	// it was changed by a middleware such as rewrite. By default, we pass the
	// original URI in as the value of REQUEST_URI (the user can overwrite this
	// if desired). Most PHP apps seem to want the original URI. Besides, this is
	// how nginx defaults: http://stackoverflow.com/a/12485156/1048862
	origReq := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request)

	requestScheme := "http"
	if r.TLS != nil {
		requestScheme = "https"
	}

	reqHost, reqPort, err := net.SplitHostPort(r.Host)
	if err != nil {
		// whatever, just assume there was no port
		reqHost = r.Host
	}

	authUser := ""
	if val, ok := repl.Get("http.auth.user.id"); ok {
		authUser = val.(string)
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
		"REMOTE_USER":       authUser,
		"REQUEST_METHOD":    r.Method,
		"REQUEST_SCHEME":    requestScheme,
		"SERVER_NAME":       reqHost,
		"SERVER_PROTOCOL":   r.Proto,
		"SERVER_SOFTWARE":   t.serverSoftware,

		// Other variables
		"DOCUMENT_ROOT":   root,
		"DOCUMENT_URI":    docURI,
		"HTTP_HOST":       r.Host, // added here, since not always part of headers
		"REQUEST_URI":     origReq.URL.RequestURI(),
		"SCRIPT_FILENAME": scriptFilename,
		"SCRIPT_NAME":     scriptName,
	}

	// compliance with the CGI specification requires that
	// PATH_TRANSLATED should only exist if PATH_INFO is defined.
	// Info: https://www.ietf.org/rfc/rfc3875 Page 14
	if env["PATH_INFO"] != "" {
		env["PATH_TRANSLATED"] = caddyhttp.SanitizedPathJoin(root, pathInfo) // Info: http://www.oreilly.com/openbook/cgi/ch02_04.html
	}

	// compliance with the CGI specification requires that
	// SERVER_PORT should only exist if it's a valid numeric value.
	// Info: https://www.ietf.org/rfc/rfc3875 Page 18
	if reqPort != "" {
		env["SERVER_PORT"] = reqPort
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
		for _, cs := range caddytls.SupportedCipherSuites() {
			if cs.ID == r.TLS.CipherSuite {
				env["SSL_CIPHER"] = cs.Name
				break
			}
		}
	}

	// Add env variables from config (with support for placeholders in values)
	for key, value := range t.EnvVars {
		env[key] = repl.ReplaceAll(value, "")
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
	// TODO: from v1...
	// if httpserver.CaseSensitivePath {
	// 	return strings.Index(path, r.SplitPath)
	// }
	if len(t.SplitPath) == 0 {
		return 0
	}

	lowerPath := strings.ToLower(path)
	for _, split := range t.SplitPath {
		if idx := strings.Index(lowerPath, strings.ToLower(split)); idx > -1 {
			return idx + len(split)
		}
	}
	return -1
}

// Map of supported protocols to Apache ssl_mod format
// Note that these are slightly different from SupportedProtocols in caddytls/config.go
var tlsProtocolStrings = map[uint16]string{
	tls.VersionTLS10: "TLSv1",
	tls.VersionTLS11: "TLSv1.1",
	tls.VersionTLS12: "TLSv1.2",
	tls.VersionTLS13: "TLSv1.3",
}

var headerNameReplacer = strings.NewReplacer(" ", "_", "-", "_")

// Interface guards
var (
	_ caddy.Provisioner = (*Transport)(nil)
	_ http.RoundTripper = (*Transport)(nil)
)
