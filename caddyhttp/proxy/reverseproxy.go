// This file is adapted from code in the net/http/httputil
// package of the Go standard library, which is by the
// Go Authors, and bears this copyright and license info:
//
//   Copyright 2011 The Go Authors. All rights reserved.
//   Use of this source code is governed by a BSD-style
//   license that can be found in the LICENSE file.
//
// This file has been modified from the standard lib to
// meet the needs of the application.

package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

var bufferPool = sync.Pool{New: createBuffer}

func createBuffer() interface{} {
	return make([]byte, 32*1024)
}

// onExitFlushLoop is a callback set by tests to detect the state of the
// flushLoop() goroutine.
var onExitFlushLoop func()

// ReverseProxy is an HTTP Handler that takes an incoming request and
// sends it to another server, proxying the response back to the
// client.
type ReverseProxy struct {
	// Director must be a function which modifies
	// the request into a new request to be sent
	// using Transport. Its response is then copied
	// back to the original client unmodified.
	Director func(*http.Request)

	// The transport used to perform proxy requests.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper

	// FlushInterval specifies the flush interval
	// to flush to the client while copying the
	// response body.
	// If zero, no periodic flushing is done.
	FlushInterval time.Duration
}

// Though the relevant directive prefix is just "unix:", url.Parse
// will - assuming the regular URL scheme - add additional slashes
// as if "unix" was a request protocol.
// What we need is just the path, so if "unix:/var/run/www.socket"
// was the proxy directive, the parsed hostName would be
// "unix:///var/run/www.socket", hence the ambiguous trimming.
func socketDial(hostName string) func(network, addr string) (conn net.Conn, err error) {
	return func(network, addr string) (conn net.Conn, err error) {
		return net.Dial("unix", hostName[len("unix://"):])
	}
}

// NewSingleHostReverseProxy returns a new ReverseProxy that rewrites
// URLs to the scheme, host, and base path provided in target. If the
// target's path is "/base" and the incoming request was for "/dir",
// the target request will be for /base/dir.
// Without logic: target's path is "/", incoming is "/api/messages",
// without is "/api", then the target request will be for /messages.
func NewSingleHostReverseProxy(target *url.URL, without string, keepalive int) *ReverseProxy {
	targetQuery := target.RawQuery
	director := func(req *http.Request) {
		if target.Scheme == "unix" {
			// to make Dial work with unix URL,
			// scheme and host have to be faked
			req.URL.Scheme = "http"
			req.URL.Host = "socket"
		} else {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
		}

		// We should remove the `without` prefix at first.
		if without != "" {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, without)
			if req.URL.Opaque != "" {
				req.URL.Opaque = strings.TrimPrefix(req.URL.Opaque, without)
			}
			if req.URL.RawPath != "" {
				req.URL.RawPath = strings.TrimPrefix(req.URL.RawPath, without)
			}
		}

		hadTrailingSlash := strings.HasSuffix(req.URL.Path, "/")
		req.URL.Path = path.Join(target.Path, req.URL.Path)
		// path.Join will strip off the last /, so put it back if it was there.
		if hadTrailingSlash && !strings.HasSuffix(req.URL.Path, "/") {
			req.URL.Path = req.URL.Path + "/"
		}

		// Trims the path of the socket from the URL path.
		// This is done because req.URL passed to your proxied service
		// will have the full path of the socket file prefixed to it.
		// Calling /test on a server that proxies requests to
		// unix:/var/run/www.socket will thus set the requested path
		// to /var/run/www.socket/test, rendering paths useless.
		if target.Scheme == "unix" {
			// See comment on socketDial for the trim
			socketPrefix := target.String()[len("unix://"):]
			req.URL.Path = strings.TrimPrefix(req.URL.Path, socketPrefix)
		}

		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}
	rp := &ReverseProxy{Director: director, FlushInterval: 250 * time.Millisecond} // flushing good for streaming & server-sent events
	if target.Scheme == "unix" {
		rp.Transport = &http.Transport{
			Dial: socketDial(target.String()),
		}
	} else if keepalive != http.DefaultMaxIdleConnsPerHost {
		// if keepalive is equal to the default,
		// just use default transport, to avoid creating
		// a brand new transport
		rp.Transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		if keepalive == 0 {
			rp.Transport.(*http.Transport).DisableKeepAlives = true
		} else {
			rp.Transport.(*http.Transport).MaxIdleConnsPerHost = keepalive
		}
	}
	return rp
}

// UseInsecureTransport is used to facilitate HTTPS proxying
// when it is OK for upstream to be using a bad certificate,
// since this transport skips verification.
func (rp *ReverseProxy) UseInsecureTransport() {
	if rp.Transport == nil {
		rp.Transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		}
	} else if transport, ok := rp.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
}

// ServeHTTP serves the proxied request to the upstream by performing a roundtrip.
// It is designed to handle websocket connection upgrades as well.
func (rp *ReverseProxy) ServeHTTP(rw http.ResponseWriter, outreq *http.Request, respUpdateFn respUpdateFn) error {
	transport := rp.Transport
	if requestIsWebsocket(outreq) {
		transport = newConnHijackerTransport(transport)
	} else if transport == nil {
		transport = http.DefaultTransport
	}

	rp.Director(outreq)
	outreq.Proto = "HTTP/1.1"
	outreq.ProtoMajor = 1
	outreq.ProtoMinor = 1
	outreq.Close = false

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		return err
	}

	if respUpdateFn != nil {
		respUpdateFn(res)
	}
	if res.StatusCode == http.StatusSwitchingProtocols && strings.ToLower(res.Header.Get("Upgrade")) == "websocket" {
		res.Body.Close()
		hj, ok := rw.(http.Hijacker)
		if !ok {
			panic(httpserver.NonHijackerError{Underlying: rw})
		}

		conn, _, err := hj.Hijack()
		if err != nil {
			return err
		}
		defer conn.Close()

		var backendConn net.Conn
		if hj, ok := transport.(*connHijackerTransport); ok {
			backendConn = hj.Conn
			if _, err := conn.Write(hj.Replay); err != nil {
				return err
			}
			bufferPool.Put(hj.Replay)
		} else {
			backendConn, err = net.Dial("tcp", outreq.URL.Host)
			if err != nil {
				return err
			}
			outreq.Write(backendConn)
		}
		defer backendConn.Close()

		go func() {
			io.Copy(backendConn, conn) // write tcp stream to backend.
		}()
		io.Copy(conn, backendConn) // read tcp stream from backend.
	} else {
		defer res.Body.Close()
		for _, h := range hopHeaders {
			res.Header.Del(h)
		}
		copyHeader(rw.Header(), res.Header)
		rw.WriteHeader(res.StatusCode)
		rp.copyResponse(rw, res.Body)
	}

	return nil
}

func (rp *ReverseProxy) copyResponse(dst io.Writer, src io.Reader) {
	buf := bufferPool.Get()
	defer bufferPool.Put(buf)

	if rp.FlushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: rp.FlushInterval,
				done:    make(chan bool),
			}
			go mlw.flushLoop()
			defer mlw.stop()
			dst = mlw
		}
	}
	io.CopyBuffer(dst, src, buf.([]byte))
}

// skip these headers if they already exist.
// see https://github.com/mholt/caddy/pull/1112#discussion_r80092582
var skipHeaders = map[string]struct{}{
	"Content-Type":        {},
	"Content-Disposition": {},
	"Accept-Ranges":       {},
	"Set-Cookie":          {},
	"Cache-Control":       {},
	"Expires":             {},
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		if _, ok := dst[k]; ok {
			// skip some predefined headers
			// see https://github.com/mholt/caddy/issues/1086
			if _, shouldSkip := skipHeaders[k]; shouldSkip {
				continue
			}
			// otherwise, overwrite
			dst.Del(k)
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
	"Alternate-Protocol",
	"Alt-Svc",
}

type respUpdateFn func(resp *http.Response)

type hijackedConn struct {
	net.Conn
	hj *connHijackerTransport
}

func (c *hijackedConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	c.hj.Replay = append(c.hj.Replay, b[:n]...)
	return
}

func (c *hijackedConn) Close() error {
	return nil
}

type connHijackerTransport struct {
	*http.Transport
	Conn   net.Conn
	Replay []byte
}

func newConnHijackerTransport(base http.RoundTripper) *connHijackerTransport {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: -1,
	}
	if base != nil {
		if baseTransport, ok := base.(*http.Transport); ok {
			transport.Proxy = baseTransport.Proxy
			transport.TLSClientConfig = baseTransport.TLSClientConfig
			transport.TLSHandshakeTimeout = baseTransport.TLSHandshakeTimeout
			transport.Dial = baseTransport.Dial
			transport.DialTLS = baseTransport.DialTLS
			transport.MaxIdleConnsPerHost = -1
		}
	}
	hjTransport := &connHijackerTransport{transport, nil, bufferPool.Get().([]byte)[:0]}
	oldDial := transport.Dial
	oldDialTLS := transport.DialTLS
	if oldDial == nil {
		oldDial = (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial
	}
	hjTransport.Dial = func(network, addr string) (net.Conn, error) {
		c, err := oldDial(network, addr)
		hjTransport.Conn = c
		return &hijackedConn{c, hjTransport}, err
	}
	if oldDialTLS != nil {
		hjTransport.DialTLS = func(network, addr string) (net.Conn, error) {
			c, err := oldDialTLS(network, addr)
			hjTransport.Conn = c
			return &hijackedConn{c, hjTransport}, err
		}
	}
	return hjTransport
}

func requestIsWebsocket(req *http.Request) bool {
	return !(strings.ToLower(req.Header.Get("Upgrade")) != "websocket" || !strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade"))
}

type writeFlusher interface {
	io.Writer
	http.Flusher
}

type maxLatencyWriter struct {
	dst     writeFlusher
	latency time.Duration

	lk   sync.Mutex // protects Write + Flush
	done chan bool
}

func (m *maxLatencyWriter) Write(p []byte) (int, error) {
	m.lk.Lock()
	defer m.lk.Unlock()
	return m.dst.Write(p)
}

func (m *maxLatencyWriter) flushLoop() {
	t := time.NewTicker(m.latency)
	defer t.Stop()
	for {
		select {
		case <-m.done:
			if onExitFlushLoop != nil {
				onExitFlushLoop()
			}
			return
		case <-t.C:
			m.lk.Lock()
			m.dst.Flush()
			m.lk.Unlock()
		}
	}
}

func (m *maxLatencyWriter) stop() { m.done <- true }
