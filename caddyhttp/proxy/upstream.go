package proxy

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/mholt/caddy/caddyfile"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

var (
	supportedPolicies = make(map[string]func() Policy)
)

type staticUpstream struct {
	from               string
	upstreamHeaders    http.Header
	downstreamHeaders  http.Header
	Hosts              HostPool
	Policy             Policy
	insecureSkipVerify bool

	FailTimeout time.Duration
	MaxFails    int32
	MaxConns    int64
	HealthCheck struct {
		Client   http.Client
		Path     string
		Interval time.Duration
		Timeout  time.Duration
	}
	WithoutPathPrefix string
	IgnoredSubPaths   []string
}

// NewStaticUpstreams parses the configuration input and sets up
// static upstreams for the proxy middleware.
func NewStaticUpstreams(c caddyfile.Dispenser) ([]Upstream, error) {
	var upstreams []Upstream
	for c.Next() {
		upstream := &staticUpstream{
			from:              "",
			upstreamHeaders:   make(http.Header),
			downstreamHeaders: make(http.Header),
			Hosts:             nil,
			Policy:            &Random{},
			FailTimeout:       10 * time.Second,
			MaxFails:          1,
			MaxConns:          0,
		}

		if !c.Args(&upstream.from) {
			return upstreams, c.ArgErr()
		}

		var to []string
		for _, t := range c.RemainingArgs() {
			parsed, err := parseUpstream(t)
			if err != nil {
				return upstreams, err
			}
			to = append(to, parsed...)
		}

		for c.NextBlock() {
			switch c.Val() {
			case "upstream":
				if !c.NextArg() {
					return upstreams, c.ArgErr()
				}
				parsed, err := parseUpstream(c.Val())
				if err != nil {
					return upstreams, err
				}
				to = append(to, parsed...)
			default:
				if err := parseBlock(&c, upstream); err != nil {
					return upstreams, err
				}
			}
		}

		if len(to) == 0 {
			return upstreams, c.ArgErr()
		}

		upstream.Hosts = make([]*UpstreamHost, len(to))
		for i, host := range to {
			uh, err := upstream.NewHost(host)
			if err != nil {
				return upstreams, err
			}
			upstream.Hosts[i] = uh
		}

		if upstream.HealthCheck.Path != "" {
			upstream.HealthCheck.Client = http.Client{
				Timeout: upstream.HealthCheck.Timeout,
			}
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

func (u *staticUpstream) NewHost(host string) (*UpstreamHost, error) {
	if !strings.HasPrefix(host, "http") &&
		!strings.HasPrefix(host, "unix:") {
		host = "http://" + host
	}
	uh := &UpstreamHost{
		Name:              host,
		Conns:             0,
		Fails:             0,
		FailTimeout:       u.FailTimeout,
		Unhealthy:         false,
		UpstreamHeaders:   u.upstreamHeaders,
		DownstreamHeaders: u.downstreamHeaders,
		CheckDown: func(u *staticUpstream) UpstreamHostDownFunc {
			return func(uh *UpstreamHost) bool {
				if uh.Unhealthy {
					return true
				}
				if uh.Fails >= u.MaxFails &&
					u.MaxFails != 0 {
					return true
				}
				return false
			}
		}(u),
		WithoutPathPrefix: u.WithoutPathPrefix,
		MaxConns:          u.MaxConns,
	}

	baseURL, err := url.Parse(uh.Name)
	if err != nil {
		return nil, err
	}

	uh.ReverseProxy = NewSingleHostReverseProxy(baseURL, uh.WithoutPathPrefix)
	if u.insecureSkipVerify {
		uh.ReverseProxy.Transport = InsecureTransport
	}
	return uh, nil
}

func parseUpstream(u string) ([]string, error) {
	if !strings.HasPrefix(u, "unix:") {
		colonIdx := strings.LastIndex(u, ":")
		protoIdx := strings.Index(u, "://")

		if colonIdx != -1 && colonIdx != protoIdx {
			us := u[:colonIdx]
			ports := u[len(us)+1:]
			if separators := strings.Count(ports, "-"); separators > 1 {
				return nil, fmt.Errorf("port range [%s] is invalid", ports)
			} else if separators == 1 {
				portsStr := strings.Split(ports, "-")
				pIni, err := strconv.Atoi(portsStr[0])
				if err != nil {
					return nil, err
				}

				pEnd, err := strconv.Atoi(portsStr[1])
				if err != nil {
					return nil, err
				}

				if pEnd <= pIni {
					return nil, fmt.Errorf("port range [%s] is invalid", ports)
				}

				hosts := []string{}
				for p := pIni; p <= pEnd; p++ {
					hosts = append(hosts, fmt.Sprintf("%s:%d", us, p))
				}
				return hosts, nil
			}
		}
	}

	return []string{u}, nil

}

func parseBlock(c *caddyfile.Dispenser, u *staticUpstream) error {
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
	case "max_conns":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.ParseInt(c.Val(), 10, 64)
		if err != nil {
			return err
		}
		u.MaxConns = n
	case "health_check":
		if !c.NextArg() {
			return c.ArgErr()
		}
		u.HealthCheck.Path = c.Val()

		// Set defaults
		if u.HealthCheck.Interval == 0 {
			u.HealthCheck.Interval = 30 * time.Second
		}
		if u.HealthCheck.Timeout == 0 {
			u.HealthCheck.Timeout = 60 * time.Second
		}
	case "health_check_interval":
		var interval string
		if !c.Args(&interval) {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(interval)
		if err != nil {
			return err
		}
		u.HealthCheck.Interval = dur
	case "health_check_timeout":
		var interval string
		if !c.Args(&interval) {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(interval)
		if err != nil {
			return err
		}
		u.HealthCheck.Timeout = dur
	case "header_upstream":
		fallthrough
	case "proxy_header":
		var header, value string
		if !c.Args(&header, &value) {
			return c.ArgErr()
		}
		u.upstreamHeaders.Add(header, value)
	case "header_downstream":
		var header, value string
		if !c.Args(&header, &value) {
			return c.ArgErr()
		}
		u.downstreamHeaders.Add(header, value)
	case "transparent":
		u.upstreamHeaders.Add("Host", "{host}")
		u.upstreamHeaders.Add("X-Real-IP", "{remote}")
		u.upstreamHeaders.Add("X-Forwarded-Proto", "{scheme}")
	case "websocket":
		u.upstreamHeaders.Add("Connection", "{>Connection}")
		u.upstreamHeaders.Add("Upgrade", "{>Upgrade}")
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
		if r, err := u.HealthCheck.Client.Get(hostURL); err == nil {
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
		if !pool[0].Available() {
			return nil
		}
		return pool[0]
	}
	allUnavailable := true
	for _, host := range pool {
		if host.Available() {
			allUnavailable = false
			break
		}
	}
	if allUnavailable {
		return nil
	}

	if u.Policy == nil {
		return (&Random{}).Select(pool)
	}
	return u.Policy.Select(pool)
}

func (u *staticUpstream) AllowedPath(requestPath string) bool {
	for _, ignoredSubPath := range u.IgnoredSubPaths {
		if httpserver.Path(path.Clean(requestPath)).Matches(path.Join(u.From(), ignoredSubPath)) {
			return false
		}
	}
	return true
}
