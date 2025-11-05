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
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

var noopLogger = zap.NewNop()

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

	// The duration used to set a deadline when connecting to an upstream. Default: `3s`.
	DialTimeout caddy.Duration `json:"dial_timeout,omitempty"`

	// The duration used to set a deadline when reading from the FastCGI server.
	ReadTimeout caddy.Duration `json:"read_timeout,omitempty"`

	// The duration used to set a deadline when sending to the FastCGI server.
	WriteTimeout caddy.Duration `json:"write_timeout,omitempty"`

	// Capture and log any messages sent by the upstream on stderr. Logs at WARN
	// level by default. If the response has a 4xx or 5xx status ERROR level will
	// be used instead.
	CaptureStderr bool `json:"capture_stderr,omitempty"`

	// disable buffering of the request body that doesn't have a content length
	BodyBufferDisabled bool `json:"body_buffer_disabled,omitempty"`
	// memory limit for buffering the request body, the rest will be buffered by temporary files
	BodyBufferMemoryLimit int64 `json:"body_buffer_memory_limit,omitempty"`
	// total disk storage allowed by the request body buffer
	FileBufferSizeLimit int64 `json:"file_buffer_size_limit,omitempty"`
	// the path to store the temporary files for the request body buffer
	FileBufferFilepath string `json:"file_buffer_filepath,omitempty"`

	serverSoftware  string
	logger          *zap.Logger
	tempFileLimiter *fileQuotaLimiter
}

// CaddyModule returns the Caddy module information.
func (Transport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.fastcgi",
		New: func() caddy.Module { return new(Transport) },
	}
}

const (
	defaultDialTimeout = 3 * time.Second
	// nginx default for 64bit platforms
	// https://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_buffer_size
	defaultMemBufferSize = 1 << 14 // 16KB
	// nginx doesn't have an option to limit the total file buffer size
	defaultFileBufferSize = 100 << 20 // 100MB
)

// Provision sets up t.
func (t *Transport) Provision(ctx caddy.Context) error {
	t.logger = ctx.Logger()

	if t.Root == "" {
		t.Root = "{http.vars.root}"
	}

	version, _ := caddy.Version()
	t.serverSoftware = "Caddy/" + version

	// Set a relatively short default dial timeout.
	// This is helpful to make load-balancer retries more speedy.
	if t.DialTimeout == 0 {
		t.DialTimeout = caddy.Duration(defaultDialTimeout)
	}

	if !t.BodyBufferDisabled {
		if t.FileBufferFilepath == "" {
			t.FileBufferFilepath = os.TempDir()
		}
		// test if temporary file can be created
		file, err := os.CreateTemp(t.FileBufferFilepath, "caddy-fastcgi-buffer-")
		if err != nil {
			return fmt.Errorf("failed to create temporary file: %v", err)
		}
		file.Close()
		os.Remove(file.Name())

		if t.BodyBufferMemoryLimit == 0 {
			t.BodyBufferMemoryLimit = defaultMemBufferSize
		}
		if t.FileBufferSizeLimit == 0 {
			t.FileBufferSizeLimit = defaultFileBufferSize
		}
		t.tempFileLimiter = newFileQuotaLimiter(t.FileBufferSizeLimit)
	}

	return nil
}

type bufferedBody struct {
	memBuf          *bytes.Buffer
	fileBuf         *os.File
	filesize        int64
	tempFileLimiter *fileQuotaLimiter
}

func (b *bufferedBody) Read(p []byte) (int, error) {
	if b.memBuf != nil {
		if b.memBuf.Len() != 0 {
			return b.memBuf.Read(p)
		}
		bufPool.Put(b.memBuf)
		b.memBuf = nil
	}
	if b.fileBuf != nil {
		n, err := b.fileBuf.Read(p)
		if err != nil {
			// close the file and remove it
			b.fileBuf.Close()
			os.Remove(b.fileBuf.Name())
			b.tempFileLimiter.release(b.filesize)
			b.fileBuf = nil
			return n, err
		}
	}
	return 0, io.EOF
}

func (b *bufferedBody) Close() error {
	if b.memBuf != nil {
		bufPool.Put(b.memBuf)
		b.memBuf = nil
	}
	if b.fileBuf != nil {
		b.fileBuf.Close()
		os.Remove(b.fileBuf.Name())
		b.tempFileLimiter.release(b.filesize)
		b.fileBuf = nil
	}
	return nil
}

var errFileBufferExceeded = errors.New("temporary file buffer limit exceeded")

func (t Transport) bufferBodyToFile(file *os.File, req io.Reader) (int64, error) {
	buf := streamingBufPool.Get().(*[]byte)
	defer streamingBufPool.Put(buf)

	var size int64
	for {
		reserved := t.tempFileLimiter.acquire(readBufSize)
		if !reserved {
			return size, errFileBufferExceeded
		}
		n, er := req.Read(*buf)
		if n > 0 {
			nw, ew := file.Write((*buf)[:n])
			size += int64(nw)
			t.tempFileLimiter.release(int64(readBufSize - nw))
			if ew != nil {
				return size, ew
			}
		}
		if er != nil {
			if er == io.EOF {
				return size, nil
			}
			return size, er
		}
	}
}

func (t Transport) bufferBody(req io.Reader) (int64, io.ReadCloser, error) {
	if closer, ok := req.(io.Closer); ok {
		defer closer.Close()
	}

	memBuf := bufPool.Get().(*bytes.Buffer)
	memBuf.Reset()
	size, err := io.CopyN(memBuf, req, t.BodyBufferMemoryLimit)
	var body bufferedBody // should be closed in case buffering fails
	body.memBuf = memBuf
	body.tempFileLimiter = t.tempFileLimiter
	// error while reading the body
	if err != nil {
		// fully buffered in memory
		if err == io.EOF {
			return size, &body, nil
		}
		body.Close()
		return 0, nil, err
	}

	// temporary file is needed here.
	fileBuf, err := os.CreateTemp(t.FileBufferFilepath, "caddy-fastcgi-buffer-")
	if err != nil {
		body.Close()
		return 0, nil, err
	}
	body.fileBuf = fileBuf
	// buffer the rest of the body to the file
	fSize, err := t.bufferBodyToFile(fileBuf, req)
	body.filesize = fSize
	if err != nil {
		body.Close()
		return 0, nil, err
	}
	return size + fSize, &body, nil
}

// RoundTrip implements http.RoundTripper.
func (t Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	server := r.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)

	// Disallow null bytes in the request path, because
	// PHP upstreams may do bad things, like execute a
	// non-PHP file as PHP code. See #4574
	if strings.Contains(r.URL.Path, "\x00") {
		return nil, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid request path"))
	}

	env, err := t.buildEnv(r)
	if err != nil {
		return nil, fmt.Errorf("building environment: %v", err)
	}

	ctx := r.Context()

	// extract dial information from request (should have been embedded by the reverse proxy)
	network, address := "tcp", r.URL.Host
	if dialInfo, ok := reverseproxy.GetDialInfo(ctx); ok {
		network = dialInfo.Network
		address = dialInfo.Address
	}

	logCreds := server.Logs != nil && server.Logs.ShouldLogCredentials
	loggableReq := caddyhttp.LoggableHTTPRequest{
		Request:              r,
		ShouldLogCredentials: logCreds,
	}
	loggableEnv := loggableEnv{vars: env, logCredentials: logCreds}

	logger := t.logger.With(
		zap.Object("request", loggableReq),
		zap.Object("env", loggableEnv),
	)
	if c := t.logger.Check(zapcore.DebugLevel, "roundtrip"); c != nil {
		c.Write(
			zap.String("dial", address),
			zap.Object("env", loggableEnv),
			zap.Object("request", loggableReq),
		)
	}

	// connect to the backend
	dialer := net.Dialer{Timeout: time.Duration(t.DialTimeout)}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dialing backend: %v", err)
	}
	defer func() {
		// conn will be closed with the response body unless there's an error
		if err != nil {
			conn.Close()
		}
	}()

	// create the client that will facilitate the protocol
	client := client{
		rwc:        conn,
		reqID:      1,
		logger:     logger,
		stderr:     t.CaptureStderr,
		buffer:     !t.BodyBufferDisabled,
		bufferFunc: t.bufferBody,
	}

	// read/write timeouts
	if err = client.SetReadTimeout(time.Duration(t.ReadTimeout)); err != nil {
		return nil, fmt.Errorf("setting read timeout: %v", err)
	}
	if err = client.SetWriteTimeout(time.Duration(t.WriteTimeout)); err != nil {
		return nil, fmt.Errorf("setting write timeout: %v", err)
	}

	contentLength := r.ContentLength
	if contentLength == 0 {
		contentLength, _ = strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	}

	var resp *http.Response
	switch r.Method {
	case http.MethodHead:
		resp, err = client.Head(env)
	case http.MethodGet:
		resp, err = client.Get(env, r.Body, contentLength)
	case http.MethodOptions:
		resp, err = client.Options(env)
	default:
		resp, err = client.Post(env, r.Method, r.Header.Get("Content-Type"), r.Body, contentLength)
	}
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// buildEnv returns a set of CGI environment variables for the request.
func (t Transport) buildEnv(r *http.Request) (envVars, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	var env envVars

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
	root, err := caddy.FastAbs(repl.ReplaceAll(t.Root, "."))
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
		pathInfo, _ = repl.GetString("http.matchers.file.remainder")
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

	authUser, _ := repl.GetString("http.auth.user.id")

	// Some variables are unused but cleared explicitly to prevent
	// the parent environment from interfering.
	env = envVars{
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
	// the SERVER_PORT variable MUST be set to the TCP/IP port number on which this request is received from the client
	// even if the port is the default port for the scheme and could otherwise be omitted from a URI.
	// https://tools.ietf.org/html/rfc3875#section-4.1.15
	if reqPort != "" {
		env["SERVER_PORT"] = reqPort
	} else if requestScheme == "http" {
		env["SERVER_PORT"] = "80"
	} else if requestScheme == "https" {
		env["SERVER_PORT"] = "443"
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

type envVars map[string]string

// loggableEnv is a simple type to allow for speeding up zap log encoding.
type loggableEnv struct {
	vars           envVars
	logCredentials bool
}

func (env loggableEnv) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, v := range env.vars {
		if !env.logCredentials {
			switch strings.ToLower(k) {
			case "http_cookie", "http_set_cookie", "http_authorization", "http_proxy_authorization":
				v = ""
			}
		}
		enc.AddString(k, v)
	}
	return nil
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
	_ zapcore.ObjectMarshaler = (*loggableEnv)(nil)

	_ caddy.Provisioner = (*Transport)(nil)
	_ http.RoundTripper = (*Transport)(nil)
)
