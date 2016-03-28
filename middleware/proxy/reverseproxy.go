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
	"strings"
	"sync"
	"time"
)

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

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
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
func NewSingleHostReverseProxy(target *url.URL, without string) *ReverseProxy {
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
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
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
		// We are then safe to remove the `without` prefix.
		if without != "" {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, without)
		}
	}
	rp := &ReverseProxy{Director: director}
	if target.Scheme == "unix" {
		rp.Transport = &http.Transport{
			Dial: socketDial(target.String()),
		}
	}
	return rp
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
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
}

// InsecureTransport is used to facilitate HTTPS proxying
// when it is OK for upstream to be using a bad certificate,
// since this transport skips verification.
var InsecureTransport http.RoundTripper = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	Dial: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial,
	TLSHandshakeTimeout: 10 * time.Second,
	TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
}

func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request, extraHeaders http.Header) error {
	transport := p.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	outreq := new(http.Request)
	*outreq = *req // includes shallow copies of maps, but okay

	p.Director(outreq)
	outreq.Proto = "HTTP/1.1"
	outreq.ProtoMajor = 1
	outreq.ProtoMinor = 1
	outreq.Close = false

	// Remove hop-by-hop headers to the backend.  Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.  This
	// is modifying the same underlying map from req (shallow
	// copied above) so we only copy it if necessary.
	copiedHeaders := false
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			if !copiedHeaders {
				outreq.Header = make(http.Header)
				copyHeader(outreq.Header, req.Header)
				copiedHeaders = true
			}
			outreq.Header.Del(h)
		}
	}

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}

	if extraHeaders != nil {
		for k, v := range extraHeaders {
			outreq.Header[k] = v
		}
	}

	res, err := transport.RoundTrip(outreq)
	if err != nil {
		return err
	}

	if res.StatusCode == http.StatusSwitchingProtocols && res.Header.Get("Upgrade") == "websocket" {
		res.Body.Close()
		hj, ok := rw.(http.Hijacker)
		if !ok {
			return nil
		}

		conn, _, err := hj.Hijack()
		if err != nil {
			return err
		}
		defer conn.Close()

		backendConn, err := net.Dial("tcp", outreq.URL.Host)
		if err != nil {
			return err
		}
		defer backendConn.Close()

		outreq.Write(backendConn)

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
		p.copyResponse(rw, res.Body)
	}

	return nil
}

func (p *ReverseProxy) copyResponse(dst io.Writer, src io.Reader) {
	if p.FlushInterval != 0 {
		if wf, ok := dst.(writeFlusher); ok {
			mlw := &maxLatencyWriter{
				dst:     wf,
				latency: p.FlushInterval,
				done:    make(chan bool),
			}
			go mlw.flushLoop()
			defer mlw.stop()
			dst = mlw
		}
	}

	io.Copy(dst, src)
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
