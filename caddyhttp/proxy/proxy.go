// Package proxy is middleware that proxies HTTP requests.
package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mholt/caddy/caddyhttp/httpserver"
)

var errUnreachable = errors.New("unreachable backend")

// Proxy represents a middleware instance that can proxy requests.
type Proxy struct {
	Next      httpserver.Handler
	Upstreams []Upstream
}

// Upstream manages a pool of proxy upstream hosts. Select should return a
// suitable upstream host, or nil if no such hosts are available.
type Upstream interface {
	// The path this upstream host should be routed on
	From() string
	// Selects an upstream host to be routed to.
	Select(*http.Request) *UpstreamHost
	// Checks if subpath is not an ignored path
	AllowedPath(string) bool
}

// UpstreamHostDownFunc can be used to customize how Down behaves.
type UpstreamHostDownFunc func(*UpstreamHost) bool

// UpstreamHost represents a single proxy upstream
type UpstreamHost struct {
	Conns             int64  // must be first field to be 64-bit aligned on 32-bit systems
	Name              string // hostname of this upstream host
	ReverseProxy      *ReverseProxy
	Fails             int32
	FailTimeout       time.Duration
	Unhealthy         bool
	UpstreamHeaders   http.Header
	DownstreamHeaders http.Header
	CheckDown         UpstreamHostDownFunc
	WithoutPathPrefix string
	MaxConns          int64
}

// Down checks whether the upstream host is down or not.
// Down will try to use uh.CheckDown first, and will fall
// back to some default criteria if necessary.
func (uh *UpstreamHost) Down() bool {
	if uh.CheckDown == nil {
		// Default settings
		return uh.Unhealthy || uh.Fails > 0
	}
	return uh.CheckDown(uh)
}

// Full checks whether the upstream host has reached its maximum connections
func (uh *UpstreamHost) Full() bool {
	return uh.MaxConns > 0 && uh.Conns >= uh.MaxConns
}

// Available checks whether the upstream host is available for proxying to
func (uh *UpstreamHost) Available() bool {
	return !uh.Down() && !uh.Full()
}

// tryDuration is how long to try upstream hosts; failures result in
// immediate retries until this duration ends or we get a nil host.
var tryDuration = 60 * time.Second

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
	outreq := createUpstreamRequest(r)

	// since Select() should give us "up" hosts, keep retrying
	// hosts until timeout (or until we get a nil host).
	start := time.Now()
	for time.Now().Sub(start) < tryDuration {
		host := upstream.Select(r)
		if host == nil {
			return http.StatusBadGateway, errUnreachable
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

		// tell the proxy to serve the request
		atomic.AddInt64(&host.Conns, 1)
		backendErr := proxy.ServeHTTP(w, outreq, downHeaderUpdateFn)
		atomic.AddInt64(&host.Conns, -1)

		// if no errors, we're done here; otherwise failover
		if backendErr == nil {
			return 0, nil
		}
		timeout := host.FailTimeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		atomic.AddInt32(&host.Fails, 1)
		go func(host *UpstreamHost, timeout time.Duration) {
			time.Sleep(timeout)
			atomic.AddInt32(&host.Fails, -1)
		}(host, timeout)
	}

	return http.StatusBadGateway, errUnreachable
}

// match finds the best match for a proxy config based
// on r.
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
func createUpstreamRequest(r *http.Request) *http.Request {
	outreq := new(http.Request)
	*outreq = *r // includes shallow copies of maps, but okay

	// Restore URL Path if it has been modified
	if outreq.URL.RawPath != "" {
		outreq.URL.Opaque = outreq.URL.RawPath
	}

	// Remove hop-by-hop headers to the backend. Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us. This
	// is modifying the same underlying map from r (shallow
	// copied above) so we only copy it if necessary.
	var copiedHeaders bool
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

	return outreq
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
				headers.Add(strings.TrimPrefix(ruleField, "+"), repl.Replace(ruleValue))
			}
		} else if strings.HasPrefix(ruleField, "-") {
			headers.Del(strings.TrimPrefix(ruleField, "-"))
		} else if len(ruleValues) > 0 {
			headers.Set(ruleField, repl.Replace(ruleValues[len(ruleValues)-1]))
		}
	}
}
