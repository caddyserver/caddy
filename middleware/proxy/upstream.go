package proxy

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/mholt/caddy/caddy/parse"
	"github.com/mholt/caddy/middleware"
)

var (
	supportedPolicies = make(map[string]func() Policy)
)

type staticUpstream struct {
	from               string
	proxyHeaders       http.Header
	hiddenHeaders      http.Header
	Hosts              HostPool
	Policy             Policy
	insecureSkipVerify bool

	FailTimeout time.Duration
	MaxFails    int32
	HealthCheck struct {
		Path     string
		Interval time.Duration
	}
	WithoutPathPrefix string
	IgnoredSubPaths   []string
}

// NewStaticUpstreams parses the configuration input and sets up
// static upstreams for the proxy middleware.
func NewStaticUpstreams(c parse.Dispenser) ([]Upstream, error) {
	var upstreams []Upstream
	for c.Next() {
		upstream := &staticUpstream{
			from:          "",
			proxyHeaders:  make(http.Header),
			hiddenHeaders: make(http.Header),
			Hosts:         nil,
			Policy:        &Random{},
			FailTimeout:   10 * time.Second,
			MaxFails:      1,
		}

		if !c.Args(&upstream.from) {
			return upstreams, c.ArgErr()
		}
		to := c.RemainingArgs()
		if len(to) == 0 {
			return upstreams, c.ArgErr()
		}

		for c.NextBlock() {
			if err := parseBlock(&c, upstream); err != nil {
				return upstreams, err
			}
		}

		upstream.Hosts = make([]*UpstreamHost, len(to))
		for i, host := range to {
			if !strings.HasPrefix(host, "http") &&
				!strings.HasPrefix(host, "unix:") {
				host = "http://" + host
			}
			uh := &UpstreamHost{
				Name:          host,
				Conns:         0,
				Fails:         0,
				FailTimeout:   upstream.FailTimeout,
				Unhealthy:     false,
				ExtraHeaders:  upstream.proxyHeaders,
				HiddenHeaders: upstream.hiddenHeaders,
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
				WithoutPathPrefix: upstream.WithoutPathPrefix,
			}
			if baseURL, err := url.Parse(uh.Name); err == nil {
				uh.ReverseProxy = NewSingleHostReverseProxy(baseURL, uh.WithoutPathPrefix)
				if upstream.insecureSkipVerify {
					uh.ReverseProxy.Transport = InsecureTransport
				}
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

// RegisterPolicy adds a custom policy to the proxy.
func RegisterPolicy(name string, policy func() Policy) {
	supportedPolicies[name] = policy
}

func (u *staticUpstream) From() string {
	return u.from
}

func parseBlock(c *parse.Dispenser, u *staticUpstream) error {
	switch c.Val() {
	case "policy":
		if !c.NextArg() {
			return c.ArgErr()
		}
		policyCreateFunc, ok := supportedPolicies[c.Val()]
		if !ok {
			return c.ArgErr()
		}
		u.Policy = policyCreateFunc()
	case "fail_timeout":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		u.FailTimeout = dur
	case "max_fails":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
		u.MaxFails = int32(n)
	case "health_check":
		if !c.NextArg() {
			return c.ArgErr()
		}
		u.HealthCheck.Path = c.Val()
		u.HealthCheck.Interval = 30 * time.Second
		if c.NextArg() {
			dur, err := time.ParseDuration(c.Val())
			if err != nil {
				return err
			}
			u.HealthCheck.Interval = dur
		}
	case "proxy_header":
		var header, value string
		if !c.Args(&header, &value) {
			return c.ArgErr()
		}
		u.proxyHeaders.Add(header, value)
	case "hide_header":
		var header, value string
		if !c.Args(&header, &value) {
			return c.ArgErr()
		}
		u.hiddenHeaders.Add(header, value)
	case "websocket":
		u.proxyHeaders.Add("Connection", "{>Connection}")
		u.proxyHeaders.Add("Upgrade", "{>Upgrade}")
	case "without":
		if !c.NextArg() {
			return c.ArgErr()
		}
		u.WithoutPathPrefix = c.Val()
	case "except":
		ignoredPaths := c.RemainingArgs()
		if len(ignoredPaths) == 0 {
			return c.ArgErr()
		}
		u.IgnoredSubPaths = ignoredPaths
	case "insecure_skip_verify":
		u.insecureSkipVerify = true
	default:
		return c.Errf("unknown property '%s'", c.Val())
	}
	return nil
}

func (u *staticUpstream) healthCheck() {
	for _, host := range u.Hosts {
		hostURL := host.Name + u.HealthCheck.Path
		if r, err := http.Get(hostURL); err == nil {
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
	}
	return u.Policy.Select(pool)
}

func (u *staticUpstream) IsAllowedPath(requestPath string) bool {
	for _, ignoredSubPath := range u.IgnoredSubPaths {
		if middleware.Path(path.Clean(requestPath)).Matches(path.Join(u.From(), ignoredSubPath)) {
			return false
		}
	}
	return true
}
