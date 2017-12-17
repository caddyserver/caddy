// Copyright 2015 Light Code Labs, LLC
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

// Package proxy is middleware that proxies HTTP requests.
package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

// Proxy represents a middleware instance that can proxy requests.
type Proxy struct {
	Next      httpserver.Handler
	Upstreams []Upstream
}

// Upstream manages a pool of proxy upstream hosts.
type Upstream interface {
	// The path this upstream host should be routed on
	From() string

	// Selects an upstream host to be routed to. It
	// should return a suitable upstream host, or nil
	// if no such hosts are available.
	Select(*http.Request) *UpstreamHost

	// Checks if subpath is not an ignored path
	AllowedPath(string) bool

	// Gets how long to try selecting upstream hosts
	// in the case of cascading failures.
	GetTryDuration() time.Duration

	// Gets how long to wait between selecting upstream
	// hosts in the case of cascading failures.
	GetTryInterval() time.Duration

	// Gets the number of upstream hosts.
	GetHostCount() int

	// Stops the upstream from proxying requests to shutdown goroutines cleanly.
	Stop() error
}

// UpstreamHostDownFunc can be used to customize how Down behaves.
type UpstreamHostDownFunc func(*UpstreamHost) bool

// UpstreamHost represents a single proxy upstream
type UpstreamHost struct {
	// This field is read & written to concurrently, so all access must use
	// atomic operations.
	Conns             int64 // must be first field to be 64-bit aligned on 32-bit systems
	MaxConns          int64
	Name              string // hostname of this upstream host
	UpstreamHeaders   http.Header
	DownstreamHeaders http.Header
	FailTimeout       time.Duration
	CheckDown         UpstreamHostDownFunc
	WithoutPathPrefix string
	ReverseProxy      *ReverseProxy
	Fails             int32
	// This is an int32 so that we can use atomic operations to do concurrent
	// reads & writes to this value.  The default value of 0 indicates that it
	// is healthy and any non-zero value indicates unhealthy.
	Unhealthy         int32
	HealthCheckResult atomic.Value
}

// Down checks whether the upstream host is down or not.
// Down will try to use uh.CheckDown first, and will fall
// back to some default criteria if necessary.
func (uh *UpstreamHost) Down() bool {
	if uh.CheckDown == nil {
		// Default settings
		return atomic.LoadInt32(&uh.Unhealthy) != 0 || atomic.LoadInt32(&uh.Fails) > 0
	}
	return uh.CheckDown(uh)
}

// Full checks whether the upstream host has reached its maximum connections
func (uh *UpstreamHost) Full() bool {
	return uh.MaxConns > 0 && atomic.LoadInt64(&uh.Conns) >= uh.MaxConns
}

// Available checks whether the upstream host is available for proxying to
func (uh *UpstreamHost) Available() bool {
	return !uh.Down() && !uh.Full()
}

// ServeHTTP satisfies the httpserver.Handler interface.
func (p Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	// start by selecting most specific matching upstream config
	upstream := p.match(r)
	if upstream == nil {
		return p.Next.ServeHTTP(w, r)
	}

	// this replacer is used to fill in header field values
	replacer := httpserver.NewReplacer(r, nil, "")

	// outreq is the request that makes a roundtrip to the backend
	outreq, cancel := createUpstreamRequest(w, r)
	defer cancel()

	// If we have more than one upstream host defined and if retrying is enabled
	// by setting try_duration to a non-zero value, caddy will try to
	// retry the request at a different host if the first one failed.
	//
	// This requires us to possibly rewind and replay the request body though,
	// which in turn requires us to buffer the request body first.
	//
	// An unbuffered request is usually preferrable, because it reduces latency
	// as well as memory usage. Furthermore it enables different kinds of
	// HTTP streaming applications like gRPC for instance.
	requiresBuffering := upstream.GetHostCount() > 1 && upstream.GetTryDuration() != 0

	if requiresBuffering {
		body, err := newBufferedBody(outreq.Body)
		if err != nil {
			return http.StatusBadRequest, errors.New("failed to read downstream request body")
		}
		if body != nil {
			outreq.Body = body
		}
	}

	// The keepRetrying function will return true if we should
	// loop and try to select another host, or false if we
	// should break and stop retrying.
	start := time.Now()
	keepRetrying := func(backendErr error) bool {
		// if downstream has canceled the request, break
		if backendErr == context.Canceled {
			return false
		}
		// if we've tried long enough, break
		if time.Since(start) >= upstream.GetTryDuration() {
			return false
		}
		// otherwise, wait and try the next available host
		time.Sleep(upstream.GetTryInterval())
		return true
	}

	var backendErr error
	for {
		// since Select() should give us "up" hosts, keep retrying
		// hosts until timeout (or until we get a nil host).
		host := upstream.Select(r)
		if host == nil {
			if backendErr == nil {
				backendErr = errors.New("no hosts available upstream")
			}
			if !keepRetrying(backendErr) {
				break
			}
			continue
		}
		if rr, ok := w.(*httpserver.ResponseRecorder); ok && rr.Replacer != nil {
			rr.Replacer.Set("upstream", host.Name)
		}

		proxy := host.ReverseProxy

		// a backend's name may contain more than just the host,
		// so we parse it as a URL to try to isolate the host.
		if nameURL, err := url.Parse(host.Name); err == nil {
			outreq.Host = nameURL.Host
			if proxy == nil {
				proxy = NewSingleHostReverseProxy(nameURL, host.WithoutPathPrefix, http.DefaultMaxIdleConnsPerHost)
			}

			// use upstream credentials by default
			if outreq.Header.Get("Authorization") == "" && nameURL.User != nil {
				pwd, _ := nameURL.User.Password()
				outreq.SetBasicAuth(nameURL.User.Username(), pwd)
			}
		} else {
			outreq.Host = host.Name
		}
		if proxy == nil {
			return http.StatusInternalServerError, errors.New("proxy for host '" + host.Name + "' is nil")
		}

		// set headers for request going upstream
		if host.UpstreamHeaders != nil {
			// modify headers for request that will be sent to the upstream host
			mutateHeadersByRules(outreq.Header, host.UpstreamHeaders, replacer)
			if hostHeaders, ok := outreq.Header["Host"]; ok && len(hostHeaders) > 0 {
				outreq.Host = hostHeaders[len(hostHeaders)-1]
			}
		}

		// prepare a function that will update response
		// headers coming back downstream
		var downHeaderUpdateFn respUpdateFn
		if host.DownstreamHeaders != nil {
			downHeaderUpdateFn = createRespHeaderUpdateFn(host.DownstreamHeaders, replacer)
		}

		// Before we retry the request we have to make sure
		// that the body is rewound to it's beginning.
		if bb, ok := outreq.Body.(*bufferedBody); ok {
			if err := bb.rewind(); err != nil {
				return http.StatusInternalServerError, errors.New("unable to rewind downstream request body")
			}
		}

		// tell the proxy to serve the request
		//
		// NOTE:
		//   The call to proxy.ServeHTTP can theoretically panic.
		//   To prevent host.Conns from getting out-of-sync we thus have to
		//   make sure that it's _always_ correctly decremented afterwards.
		func() {
			atomic.AddInt64(&host.Conns, 1)
			defer atomic.AddInt64(&host.Conns, -1)
			backendErr = proxy.ServeHTTP(w, outreq, downHeaderUpdateFn)
		}()

		// if no errors, we're done here
		if backendErr == nil {
			return 0, nil
		}

		if backendErr == httpserver.ErrMaxBytesExceeded {
			return http.StatusRequestEntityTooLarge, backendErr
		}

		// failover; remember this failure for some time if
		// request failure counting is enabled
		timeout := host.FailTimeout
		if timeout > 0 {
			atomic.AddInt32(&host.Fails, 1)
			go func(host *UpstreamHost, timeout time.Duration) {
				time.Sleep(timeout)
				atomic.AddInt32(&host.Fails, -1)
			}(host, timeout)
		}

		// if we've tried long enough, break
		if !keepRetrying(backendErr) {
			break
		}
	}

	return http.StatusBadGateway, backendErr
}

// match finds the best match for a proxy config based on r.
func (p Proxy) match(r *http.Request) Upstream {
	var u Upstream
	var longestMatch int
	for _, upstream := range p.Upstreams {
		basePath := upstream.From()
		if !httpserver.Path(r.URL.Path).Matches(basePath) || !upstream.AllowedPath(r.URL.Path) {
			continue
		}
		if len(basePath) > longestMatch {
			longestMatch = len(basePath)
			u = upstream
		}
	}
	return u
}

// createUpstremRequest shallow-copies r into a new request
// that can be sent upstream.
//
// Derived from reverseproxy.go in the standard Go httputil package.
func createUpstreamRequest(rw http.ResponseWriter, r *http.Request) (*http.Request, context.CancelFunc) {
	// Original incoming server request may be canceled by the
	// user or by std lib(e.g. too many idle connections).
	ctx, cancel := context.WithCancel(r.Context())
	if cn, ok := rw.(http.CloseNotifier); ok {
		notifyChan := cn.CloseNotify()
		go func() {
			select {
			case <-notifyChan:
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	outreq := r.WithContext(ctx) // includes shallow copies of maps, but okay

	// We should set body to nil explicitly if request body is empty.
	// For server requests the Request Body is always non-nil.
	if r.ContentLength == 0 {
		outreq.Body = nil
	}

	// We are modifying the same underlying map from req (shallow
	// copied above) so we only copy it if necessary.
	copiedHeaders := false

	// Remove hop-by-hop headers listed in the "Connection" header.
	// See RFC 2616, section 14.10.
	if c := outreq.Header.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				if !copiedHeaders {
					outreq.Header = make(http.Header)
					copyHeader(outreq.Header, r.Header)
					copiedHeaders = true
				}
				outreq.Header.Del(f)
			}
		}
	}

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			if !copiedHeaders {
				outreq.Header = make(http.Header)
				copyHeader(outreq.Header, r.Header)
				copiedHeaders = true
			}
			outreq.Header.Del(h)
		}
	}

	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		// If we aren't the first proxy, retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := outreq.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		outreq.Header.Set("X-Forwarded-For", clientIP)
	}

	return outreq, cancel
}

func createRespHeaderUpdateFn(rules http.Header, replacer httpserver.Replacer) respUpdateFn {
	return func(resp *http.Response) {
		mutateHeadersByRules(resp.Header, rules, replacer)
	}
}

func mutateHeadersByRules(headers, rules http.Header, repl httpserver.Replacer) {
	for ruleField, ruleValues := range rules {
		if strings.HasPrefix(ruleField, "+") {
			for _, ruleValue := range ruleValues {
				replacement := repl.Replace(ruleValue)
				if len(replacement) > 0 {
					headers.Add(strings.TrimPrefix(ruleField, "+"), replacement)
				}
			}
		} else if strings.HasPrefix(ruleField, "-") {
			headers.Del(strings.TrimPrefix(ruleField, "-"))
		} else if len(ruleValues) > 0 {
			replacement := repl.Replace(ruleValues[len(ruleValues)-1])
			if len(replacement) > 0 {
				headers.Set(ruleField, replacement)
			}
		}
	}
}
