package proxy

import (
	"github.com/mholt/caddy/config/parse"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type staticUpstream struct {
	from   string
	Hosts  HostPool
	Policy Policy

	FailTimeout time.Duration
	MaxFails    int32
	HealthCheck struct {
		Path     string
		Interval time.Duration
	}
}

// newStaticUpstreams parses the configuration input and sets up
// static upstreams for the proxy middleware.
func NewStaticUpstreams(c parse.Dispenser) ([]Upstream, error) {
	var upstreams []Upstream

	for c.Next() {
		upstream := &staticUpstream{
			from:        "",
			Hosts:       nil,
			Policy:      &Random{},
			FailTimeout: 10 * time.Second,
			MaxFails:    1,
		}
		var proxyHeaders http.Header
		if !c.Args(&upstream.from) {
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
					upstream.Policy = &Random{}
				case "round_robin":
					upstream.Policy = &RoundRobin{}
				case "least_conn":
					upstream.Policy = &LeastConn{}
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

		upstream.Hosts = make([]*UpstreamHost, len(to))
		for i, host := range to {
			if !strings.HasPrefix(host, "http") {
				host = "http://" + host
			}
			uh := &UpstreamHost{
				Name:         host,
				Conns:        0,
				Fails:        0,
				FailTimeout:  upstream.FailTimeout,
				Unhealthy:    false,
				ExtraHeaders: proxyHeaders,
				CheckDown: func(upstream *staticUpstream) UpstreamHostDownFunc {
					return func(uh *UpstreamHost) bool {
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
				uh.ReverseProxy = NewSingleHostReverseProxy(baseUrl)
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

func (u *staticUpstream) From() string {
	return u.from
}

func (u *staticUpstream) healthCheck() {
	for _, host := range u.Hosts {
		hostUrl := host.Name + u.HealthCheck.Path
		if r, err := http.Get(hostUrl); err == nil {
			io.Copy(ioutil.Discard, r.Body)
			r.Body.Close()
			host.Unhealthy = r.StatusCode < 200 || r.StatusCode >= 400
		} else {
			host.Unhealthy = true
		}
	}
}

func (u *staticUpstream) HealthCheckWorker(stop chan struct{}) {
	ticker := time.NewTicker(u.HealthCheck.Interval)
	u.healthCheck()
	for {
		select {
		case <-ticker.C:
			u.healthCheck()
		case <-stop:
			// TODO: the library should provide a stop channel and global
			// waitgroup to allow goroutines started by plugins a chance
			// to clean themselves up.
		}
	}
}

func (u *staticUpstream) Select() *UpstreamHost {
	pool := u.Hosts
	if len(pool) == 1 {
		if pool[0].Down() {
			return nil
		}
		return pool[0]
	}
	allDown := true
	for _, host := range pool {
		if !host.Down() {
			allDown = false
			break
		}
	}
	if allDown {
		return nil
	}

	if u.Policy == nil {
		return (&Random{}).Select(pool)
	} else {
		return u.Policy.Select(pool)
	}
}
