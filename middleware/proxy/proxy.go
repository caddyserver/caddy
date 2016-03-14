// Package proxy is middleware that proxies requests.
package proxy

import (
	"errors"
	"net/http"
	"net/url"
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
	IsAllowedPath(string) bool
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
	HiddenHeaders     http.Header
	CheckDown         UpstreamHostDownFunc
	WithoutPathPrefix string
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

// tryDuration is how long to try upstream hosts; failures result in
// immediate retries until this duration ends or we get a nil host.
var tryDuration = 60 * time.Second

// ServeHTTP satisfies the middleware.Handler interface.
func (p Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {
	for _, upstream := range p.Upstreams {
		if middleware.Path(r.URL.Path).Matches(upstream.From()) && upstream.IsAllowedPath(r.URL.Path) {
			var replacer middleware.Replacer
			start := time.Now()
			requestHost := r.Host

			// Since Select() should give us "up" hosts, keep retrying
			// hosts until timeout (or until we get a nil host).
			for time.Now().Sub(start) < tryDuration {
				host := upstream.Select()
				if host == nil {
					return http.StatusBadGateway, errUnreachable
				}
				proxy := host.ReverseProxy
				r.Host = host.Name

				if baseURL, err := url.Parse(host.Name); err == nil {
					r.Host = baseURL.Host
					if proxy == nil {
						proxy = NewSingleHostReverseProxy(baseURL, host.WithoutPathPrefix)
					}
				} else if proxy == nil {
					return http.StatusInternalServerError, err
				}

				var extraHeaders http.Header
				if host.ExtraHeaders != nil {
					extraHeaders = make(http.Header)
					if replacer == nil {
						rHost := r.Host
						r.Host = requestHost
						replacer = middleware.NewReplacer(r, nil, "")
						r.Host = rHost
					}
					for header, values := range host.ExtraHeaders {
						for _, value := range values {
							extraHeaders.Add(header,
								replacer.Replace(value))
							if header == "Host" {
								r.Host = replacer.Replace(value)
							}
						}
					}
				}

				var hiddenHeaders http.Header
				if host.HiddenHeaders != nil {
					hiddenHeaders = make(http.Header)
					for header, _ := range host.HiddenHeaders {
						hiddenHeaders.Add(header,"")
					}
				}

				atomic.AddInt64(&host.Conns, 1)
				backendErr := proxy.ServeHTTP(w, r, extraHeaders, hiddenHeaders)
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
	}

	return p.Next.ServeHTTP(w, r)
}
