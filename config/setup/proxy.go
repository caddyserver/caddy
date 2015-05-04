package setup

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/proxy"
)

// Proxy configures a new Proxy middleware instance.
func Proxy(c *Controller) (middleware.Middleware, error) {
	if upstreams, err := newStaticUpstreams(c); err == nil {
		return func(next middleware.Handler) middleware.Handler {
			return proxy.Proxy{Next: next, Upstreams: upstreams}
		}, nil
	} else {
		return nil, err
	}
}

// newStaticUpstreams parses the configuration input and sets up
// static upstreams for the proxy middleware.
func newStaticUpstreams(c *Controller) ([]proxy.Upstream, error) {
	var upstreams []proxy.Upstream

	for c.Next() {
		upstream := &proxy.StaticUpstream{
			From:        "",
			Hosts:       nil,
			Policy:      &proxy.Random{},
			FailTimeout: 10 * time.Second,
			MaxFails:    1,
		}
		var proxyHeaders http.Header
		if !c.Args(&upstream.From) {
			return upstreams, c.ArgErr()
		}
		to := c.RemainingArgs()
		if len(to) == 0 {
			return upstreams, c.ArgErr()
		}

		for c.NextBlock() {
			switch c.Val() {
			case "policy":
				if !c.NextArg() {
					return upstreams, c.ArgErr()
				}
				switch c.Val() {
				case "random":
					upstream.Policy = &proxy.Random{}
				case "round_robin":
					upstream.Policy = &proxy.RoundRobin{}
				case "least_conn":
					upstream.Policy = &proxy.LeastConn{}
				default:
					return upstreams, c.ArgErr()
				}
			case "fail_timeout":
				if !c.NextArg() {
					return upstreams, c.ArgErr()
				}
				if dur, err := time.ParseDuration(c.Val()); err == nil {
					upstream.FailTimeout = dur
				} else {
					return upstreams, err
				}
			case "max_fails":
				if !c.NextArg() {
					return upstreams, c.ArgErr()
				}
				if n, err := strconv.Atoi(c.Val()); err == nil {
					upstream.MaxFails = int32(n)
				} else {
					return upstreams, err
				}
			case "health_check":
				if !c.NextArg() {
					return upstreams, c.ArgErr()
				}
				upstream.HealthCheck.Path = c.Val()
				upstream.HealthCheck.Interval = 30 * time.Second
				if c.NextArg() {
					if dur, err := time.ParseDuration(c.Val()); err == nil {
						upstream.HealthCheck.Interval = dur
					} else {
						return upstreams, err
					}
				}
			case "proxy_header":
				var header, value string
				if !c.Args(&header, &value) {
					return upstreams, c.ArgErr()
				}
				if proxyHeaders == nil {
					proxyHeaders = make(map[string][]string)
				}
				proxyHeaders.Add(header, value)
			}
		}

		upstream.Hosts = make([]*proxy.UpstreamHost, len(to))
		for i, host := range to {
			if !strings.HasPrefix(host, "http") {
				host = "http://" + host
			}
			uh := &proxy.UpstreamHost{
				Name:         host,
				Conns:        0,
				Fails:        0,
				FailTimeout:  upstream.FailTimeout,
				Unhealthy:    false,
				ExtraHeaders: proxyHeaders,
				CheckDown: func(upstream *proxy.StaticUpstream) proxy.UpstreamHostDownFunc {
					return func(uh *proxy.UpstreamHost) bool {
						if uh.Unhealthy {
							return true
						}
						if uh.Fails >= upstream.MaxFails &&
							upstream.MaxFails != 0 {
							return true
						}
						return false
					}
				}(upstream),
			}
			if baseUrl, err := url.Parse(uh.Name); err == nil {
				uh.ReverseProxy = proxy.NewSingleHostReverseProxy(baseUrl)
			} else {
				return upstreams, err
			}
			upstream.Hosts[i] = uh
		}

		if upstream.HealthCheck.Path != "" {
			go upstream.HealthCheckWorker(nil)
		}
		upstreams = append(upstreams, upstream)
	}
	return upstreams, nil
}
