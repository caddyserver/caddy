// Package proxy is middleware that proxies requests.
package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mholt/caddy/middleware"
)

var errUnreachable = errors.New("unreachable backend")

// Proxy represents a middleware instance that can proxy requests.
type Proxy struct {
	Next      middleware.Handler
	Upstreams []Upstream
}

// Upstream manages a pool of proxy upstream hosts. Select should return a
// suitable upstream host, or nil if no such hosts are available.
type Upstream interface {
	// The path this upstream host should be routed on
	From() string
	// Selects an upstream host to be routed to.
	Select() *UpstreamHost
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
	ExtraHeaders      http.Header
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

// ServeHTTP satisfies the middleware.Handler interface.
func (p Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, upstream := range p.Upstreams {
		if !middleware.Path(r.URL.Path).Matches(upstream.From()) ||
			!upstream.AllowedPath(r.URL.Path) {
			continue
		}

		var replacer middleware.Replacer
		start := time.Now()

		outreq := createUpstreamRequest(r)

		// Since Select() should give us "up" hosts, keep retrying
		// hosts until timeout (or until we get a nil host).
		for time.Now().Sub(start) < tryDuration {
			host := upstream.Select()
			if host == nil {
				return http.StatusBadGateway, errUnreachable
			}
			if rr, ok := w.(*middleware.ResponseRecorder); ok && rr.Replacer != nil {
				rr.Replacer.Set("upstream", host.Name)
			}

			outreq.Host = host.Name
			if host.ExtraHeaders != nil {
				extraHeaders := make(http.Header)
				if replacer == nil {
					rHost := r.Host
					replacer = middleware.NewReplacer(r, nil, "")
					outreq.Host = rHost
				}
				for header, values := range host.ExtraHeaders {
					for _, value := range values {
						extraHeaders.Add(header, replacer.Replace(value))
						if header == "Host" {
							outreq.Host = replacer.Replace(value)
						}
					}
				}
				for k, v := range extraHeaders {
					outreq.Header[k] = v
				}
			}

			proxy := host.ReverseProxy
			if baseURL, err := url.Parse(host.Name); err == nil {
				r.Host = baseURL.Host
				if proxy == nil {
					proxy = NewSingleHostReverseProxy(baseURL, host.WithoutPathPrefix)
				}
			} else if proxy == nil {
				return http.StatusInternalServerError, err
			}

			atomic.AddInt64(&host.Conns, 1)
			backendErr := proxy.ServeHTTP(w, outreq)
			atomic.AddInt64(&host.Conns, -1)
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

	return p.Next.ServeHTTP(w, r)
}

// createUpstremRequest shallow-copies r into a new request
// that can be sent upstream.
func createUpstreamRequest(r *http.Request) *http.Request {
	outreq := new(http.Request)
	*outreq = *r // includes shallow copies of maps, but okay

	// Remove hop-by-hop headers to the backend.  Especially
	// important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.  This
	// is modifying the same underlying map from r (shallow
	// copied above) so we only copy it if necessary.
	for _, h := range hopHeaders {
		if outreq.Header.Get(h) != "" {
			outreq.Header = make(http.Header)
			copyHeader(outreq.Header, r.Header)
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
