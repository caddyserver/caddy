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

package caddyhttp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func init() {
	caddy.RegisterModule(HTTPRedirectListenerWrapper{})
}

// HTTPRedirectListenerWrapper provides HTTP->HTTPS redirects for
// connections that come on the TLS port as an HTTP request,
// by detecting using the first few bytes that it's not a TLS
// handshake, but instead an HTTP request.
//
// This is especially useful when using a non-standard HTTPS port.
// A user may simply type the address in their browser without the
// https:// scheme, which would cause the browser to attempt the
// connection over HTTP, but this would cause a "Client sent an
// HTTP request to an HTTPS server" error response.
//
// This listener wrapper must be placed BEFORE the "tls" listener
// wrapper, for it to work properly.
type HTTPRedirectListenerWrapper struct {
	// MaxHeaderBytes is the maximum size to parse from a client's
	// HTTP request headers. Default: 1 MB
	MaxHeaderBytes int64 `json:"max_header_bytes,omitempty"`
}

func (HTTPRedirectListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.http_redirect",
		New: func() caddy.Module { return new(HTTPRedirectListenerWrapper) },
	}
}

func (h *HTTPRedirectListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

func (h *HTTPRedirectListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return &httpRedirectListener{l, h.MaxHeaderBytes}
}

// httpRedirectListener is listener that checks the first few bytes
// of the request when the server is intended to accept HTTPS requests,
// to respond to an HTTP request with a redirect.
type httpRedirectListener struct {
	net.Listener
	maxHeaderBytes int64
}

// Accept waits for and returns the next connection to the listener,
// wrapping it with a httpRedirectConn.
func (l *httpRedirectListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	maxHeaderBytes := l.maxHeaderBytes
	if maxHeaderBytes == 0 {
		maxHeaderBytes = 1024 * 1024
	}

	return &httpRedirectConn{
		Conn:  c,
		limit: maxHeaderBytes,
		r:     bufio.NewReader(c),
	}, nil
}

type httpRedirectConn struct {
	net.Conn
	once  bool
	limit int64
	r     *bufio.Reader
}

// Read tries to peek at the first few bytes of the request, and if we get
// an error reading the headers, and that error was due to the bytes looking
// like an HTTP request, then we perform a HTTP->HTTPS redirect on the same
// port as the original connection.
func (c *httpRedirectConn) Read(p []byte) (int, error) {
	if c.once {
		return c.r.Read(p)
	}
	// no need to use sync.Once - net.Conn is not read from concurrently.
	c.once = true

	firstBytes, err := c.r.Peek(5)
	if err != nil {
		return 0, err
	}

	// If the request doesn't look like HTTP, then it's probably
	// TLS bytes, and we don't need to do anything.
	if !firstBytesLookLikeHTTP(firstBytes) {
		return c.r.Read(p)
	}

	// From now on, we can be almost certain the request is HTTP.
	// The returned error will be non nil and caller are expected to
	// close the connection.

	// Set the read limit, io.MultiReader is needed because
	// when resetting, *bufio.Reader discards buffered data.
	buffered, _ := c.r.Peek(c.r.Buffered())
	mr := io.MultiReader(bytes.NewReader(buffered), c.Conn)
	c.r.Reset(io.LimitReader(mr, c.limit))

	// Parse the HTTP request, so we can get the Host and URL to redirect to.
	req, err := http.ReadRequest(c.r)
	if err != nil {
		return 0, fmt.Errorf("couldn't read HTTP request")
	}

	// Build the redirect response, using the same Host and URL,
	// but replacing the scheme with https.
	headers := make(http.Header)
	headers.Add("Location", "https://"+req.Host+req.URL.String())
	resp := &http.Response{
		Proto:      "HTTP/1.0",
		Status:     "308 Permanent Redirect",
		StatusCode: 308,
		ProtoMajor: 1,
		ProtoMinor: 0,
		Header:     headers,
	}

	err = resp.Write(c.Conn)
	if err != nil {
		return 0, fmt.Errorf("couldn't write HTTP->HTTPS redirect")
	}

	return 0, fmt.Errorf("redirected HTTP request on HTTPS port")
}

// firstBytesLookLikeHTTP reports whether a TLS record header
// looks like it might've been a misdirected plaintext HTTP request.
func firstBytesLookLikeHTTP(hdr []byte) bool {
	switch string(hdr[:5]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO":
		return true
	}
	return false
}

var (
	_ caddy.ListenerWrapper = (*HTTPRedirectListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*HTTPRedirectListenerWrapper)(nil)
)
