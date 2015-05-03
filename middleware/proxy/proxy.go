// Package proxy is middleware that proxies requests.
package proxy

import (
	"errors"
	"github.com/mholt/caddy/middleware"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

var errUnreachable = errors.New("Unreachable backend")

// Proxy represents a middleware instance that can proxy requests.
type Proxy struct {
	Next      middleware.Handler
	Upstreams []Upstream
}

// An upstream manages a pool of proxy upstream hosts. Select should return a
// suitable upstream host, or nil if no such hosts are available.
type Upstream interface {
	// The path this upstream host should be routed on
	From() string
	// Selects an upstream host to be routed to.
	Select() *UpstreamHost
}

type UpstreamHostDownFunc func(*UpstreamHost) bool

// An UpstreamHost represents a single proxy upstream
type UpstreamHost struct {
	Name         string
	ReverseProxy *ReverseProxy
	Conns        int64
	Fails        int32
	FailTimeout  time.Duration
	Unhealthy    bool
	ExtraHeaders http.Header
	CheckDown    UpstreamHostDownFunc
}

func (uh *UpstreamHost) Down() bool {
	if uh.CheckDown == nil {
		// Default settings
		return uh.Unhealthy || uh.Fails > 0
	}
	return uh.CheckDown(uh)
}

//https://github.com/mgutz/str
var tRe = regexp.MustCompile(`([\-\[\]()*\s])`)
var tRe2 = regexp.MustCompile(`\$`)
var openDelim = tRe2.ReplaceAllString(tRe.ReplaceAllString("{{", "\\$1"), "\\$")
var closDelim = tRe2.ReplaceAllString(tRe.ReplaceAllString("}}", "\\$1"), "\\$")
var templateDelim = regexp.MustCompile(openDelim + `(.+?)` + closDelim)

type requestVars struct {
	Host         string
	RemoteIp     string
	Scheme       string
	Upstream     string
	UpstreamHost string
}

func templateWithDelimiters(s string, vars requestVars) string {
	matches := templateDelim.FindAllStringSubmatch(s, -1)
	for _, submatches := range matches {
		match := submatches[0]
		key := submatches[1]
		found := true
		repl := ""
		switch key {
		case "http_host":
			repl = vars.Host
		case "remote_addr":
			repl = vars.RemoteIp
		case "scheme":
			repl = vars.Scheme
		case "upstream":
			repl = vars.Upstream
		case "upstream_host":
			repl = vars.UpstreamHost
		default:
			found = false
		}
		if found {
			s = strings.Replace(s, match, repl, -1)
		}
	}
	return s
}

// ServeHTTP satisfies the middleware.Handler interface.
func (p Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) (int, error) {

	for _, upstream := range p.Upstreams {
		if middleware.Path(r.URL.Path).Matches(upstream.From()) {
			vars := requestVars{
				Host:   r.Host,
				Scheme: "http",
			}
			if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				vars.RemoteIp = clientIP
			}
			if fFor := r.Header.Get("X-Forwarded-For"); fFor != "" {
				vars.RemoteIp = fFor
			}
			if r.TLS != nil {
				vars.Scheme = "https"
			}
			// Since Select() should give us "up" hosts, keep retrying
			// hosts until timeout (or until we get a nil host).
			start := time.Now()
			for time.Now().Sub(start) < (60 * time.Second) {
				host := upstream.Select()
				if host == nil {
					return http.StatusBadGateway, errUnreachable
				}
				proxy := host.ReverseProxy
				vars.Upstream = host.Name
				r.Host = host.Name

				if baseUrl, err := url.Parse(host.Name); err == nil {
					vars.UpstreamHost = baseUrl.Host
					if proxy == nil {
						proxy = NewSingleHostReverseProxy(baseUrl)
					}
				} else if proxy == nil {
					return http.StatusInternalServerError, err
				}
				var extraHeaders http.Header
				if host.ExtraHeaders != nil {
					extraHeaders = make(http.Header)
					for header, values := range host.ExtraHeaders {
						for _, value := range values {
							extraHeaders.Add(header,
								templateWithDelimiters(value, vars))
							if header == "Host" {
								r.Host = templateWithDelimiters(value, vars)
							}
						}
					}
				}

				atomic.AddInt64(&host.Conns, 1)
				backendErr := proxy.ServeHTTP(w, r, extraHeaders)
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

// New creates a new instance of proxy middleware.
func New(c middleware.Controller) (middleware.Middleware, error) {
	if upstreams, err := newStaticUpstreams(c); err == nil {
		return func(next middleware.Handler) middleware.Handler {
			return Proxy{Next: next, Upstreams: upstreams}
		}, nil
	} else {
		return nil, err
	}
}
