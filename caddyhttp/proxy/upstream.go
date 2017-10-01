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

package proxy

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/tls"

	"github.com/mholt/caddy/caddyfile"
	"github.com/mholt/caddy/caddyhttp/httpserver"
)

var (
	supportedPolicies = make(map[string]func(string) Policy)
)

type staticUpstream struct {
	from              string
	upstreamHeaders   http.Header
	downstreamHeaders http.Header
	stop              chan struct{}  // Signals running goroutines to stop.
	wg                sync.WaitGroup // Used to wait for running goroutines to stop.
	Hosts             HostPool
	Policy            Policy
	KeepAlive         int
	FailTimeout       time.Duration
	TryDuration       time.Duration
	TryInterval       time.Duration
	MaxConns          int64
	HealthCheck       struct {
		Client        http.Client
		Path          string
		Interval      time.Duration
		Timeout       time.Duration
		Host          string
		Port          string
		ContentString string
	}
	WithoutPathPrefix  string
	IgnoredSubPaths    []string
	insecureSkipVerify bool
	MaxFails           int32
}

// NewStaticUpstreams parses the configuration input and sets up
// static upstreams for the proxy middleware. The host string parameter,
// if not empty, is used for setting the upstream Host header for the
// health checks if the upstream header config requires it.
func NewStaticUpstreams(c caddyfile.Dispenser, host string) ([]Upstream, error) {
	var upstreams []Upstream
	for c.Next() {

		upstream := &staticUpstream{
			from:              "",
			stop:              make(chan struct{}),
			upstreamHeaders:   make(http.Header),
			downstreamHeaders: make(http.Header),
			Hosts:             nil,
			Policy:            &Random{},
			MaxFails:          1,
			TryInterval:       250 * time.Millisecond,
			MaxConns:          0,
			KeepAlive:         http.DefaultMaxIdleConnsPerHost,
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
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: upstream.insecureSkipVerify},
				},
			}

			// set up health check upstream host if we have one
			if host != "" {
				hostHeader := upstream.upstreamHeaders.Get("Host")
				if strings.Contains(hostHeader, "{host}") {
					upstream.HealthCheck.Host = strings.Replace(hostHeader, "{host}", host, -1)
				}
			}
			upstream.wg.Add(1)
			go func() {
				defer upstream.wg.Done()
				upstream.HealthCheckWorker(upstream.stop)
			}()
		}
		upstreams = append(upstreams, upstream)
	}
	return upstreams, nil
}

func (u *staticUpstream) From() string {
	return u.from
}

func (u *staticUpstream) NewHost(host string) (*UpstreamHost, error) {
	if !strings.HasPrefix(host, "http") &&
		!strings.HasPrefix(host, "unix:") &&
		!strings.HasPrefix(host, "quic:") {
		host = "http://" + host
	}
	uh := &UpstreamHost{
		Name:              host,
		Conns:             0,
		Fails:             0,
		FailTimeout:       u.FailTimeout,
		Unhealthy:         0,
		UpstreamHeaders:   u.upstreamHeaders,
		DownstreamHeaders: u.downstreamHeaders,
		CheckDown: func(u *staticUpstream) UpstreamHostDownFunc {
			return func(uh *UpstreamHost) bool {
				if atomic.LoadInt32(&uh.Unhealthy) != 0 {
					return true
				}
				if atomic.LoadInt32(&uh.Fails) >= u.MaxFails {
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

	uh.ReverseProxy = NewSingleHostReverseProxy(baseURL, uh.WithoutPathPrefix, u.KeepAlive)
	if u.insecureSkipVerify {
		uh.ReverseProxy.UseInsecureTransport()
	}

	return uh, nil
}

func parseUpstream(u string) ([]string, error) {
	if !strings.HasPrefix(u, "unix:") {
		colonIdx := strings.LastIndex(u, ":")
		protoIdx := strings.Index(u, "://")

		if colonIdx != -1 && colonIdx != protoIdx {
			us := u[:colonIdx]
			ue := ""
			portsEnd := len(u)
			if nextSlash := strings.Index(u[colonIdx:], "/"); nextSlash != -1 {
				portsEnd = colonIdx + nextSlash
				ue = u[portsEnd:]
			}
			ports := u[len(us)+1 : portsEnd]

			if separators := strings.Count(ports, "-"); separators == 1 {
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
					hosts = append(hosts, fmt.Sprintf("%s:%d%s", us, p, ue))
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
		arg := ""
		if c.NextArg() {
			arg = c.Val()
		}
		u.Policy = policyCreateFunc(arg)
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
		if n < 1 {
			return c.Err("max_fails must be at least 1")
		}
		u.MaxFails = int32(n)
	case "try_duration":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		u.TryDuration = dur
	case "try_interval":
		if !c.NextArg() {
			return c.ArgErr()
		}
		interval, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		u.TryInterval = interval
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
	case "health_check_port":
		if !c.NextArg() {
			return c.ArgErr()
		}
		port := c.Val()
		n, err := strconv.Atoi(port)
		if err != nil {
			return err
		}

		if n < 0 {
			return c.Errf("invalid health_check_port '%s'", port)
		}
		u.HealthCheck.Port = port
	case "health_check_contains":
		if !c.NextArg() {
			return c.ArgErr()
		}
		u.HealthCheck.ContentString = c.Val()
	case "header_upstream":
		var header, value string
		if !c.Args(&header, &value) {
			// When removing a header, the value can be optional.
			if !strings.HasPrefix(header, "-") {
				return c.ArgErr()
			}
		}
		u.upstreamHeaders.Add(header, value)
	case "header_downstream":
		var header, value string
		if !c.Args(&header, &value) {
			// When removing a header, the value can be optional.
			if !strings.HasPrefix(header, "-") {
				return c.ArgErr()
			}
		}
		u.downstreamHeaders.Add(header, value)
	case "transparent":
		u.upstreamHeaders.Add("Host", "{host}")
		u.upstreamHeaders.Add("X-Real-IP", "{remote}")
		u.upstreamHeaders.Add("X-Forwarded-For", "{remote}")
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
	case "keepalive":
		if !c.NextArg() {
			return c.ArgErr()
		}
		n, err := strconv.Atoi(c.Val())
		if err != nil {
			return err
		}
		if n < 0 {
			return c.ArgErr()
		}
		u.KeepAlive = n
	default:
		return c.Errf("unknown property '%s'", c.Val())
	}
	return nil
}

func (u *staticUpstream) healthCheck() {
	for _, host := range u.Hosts {
		hostURL := host.Name
		if u.HealthCheck.Port != "" {
			hostURL = replacePort(host.Name, u.HealthCheck.Port)
		}
		hostURL += u.HealthCheck.Path

		unhealthy := func() bool {
			// set up request, needed to be able to modify headers
			// possible errors are bad HTTP methods or un-parsable urls
			req, err := http.NewRequest("GET", hostURL, nil)
			if err != nil {
				return true
			}
			// set host for request going upstream
			if u.HealthCheck.Host != "" {
				req.Host = u.HealthCheck.Host
			}
			r, err := u.HealthCheck.Client.Do(req)
			if err != nil {
				return true
			}
			defer func() {
				io.Copy(ioutil.Discard, r.Body)
				r.Body.Close()
			}()
			if r.StatusCode < 200 || r.StatusCode >= 400 {
				return true
			}
			if u.HealthCheck.ContentString == "" { // don't check for content string
				return false
			}
			// TODO ReadAll will be replaced if deemed necessary
			//      See https://github.com/mholt/caddy/pull/1691
			buf, err := ioutil.ReadAll(r.Body)
			if err != nil {
				return true
			}
			if bytes.Contains(buf, []byte(u.HealthCheck.ContentString)) {
				return false
			}
			return true
		}()
		if unhealthy {
			atomic.StoreInt32(&host.Unhealthy, 1)
		} else {
			atomic.StoreInt32(&host.Unhealthy, 0)
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
			ticker.Stop()
			return
		}
	}
}

func (u *staticUpstream) Select(r *http.Request) *UpstreamHost {
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
		return (&Random{}).Select(pool, r)
	}
	return u.Policy.Select(pool, r)
}

func (u *staticUpstream) AllowedPath(requestPath string) bool {
	for _, ignoredSubPath := range u.IgnoredSubPaths {
		if httpserver.Path(path.Clean(requestPath)).Matches(path.Join(u.From(), ignoredSubPath)) {
			return false
		}
	}
	return true
}

// GetTryDuration returns u.TryDuration.
func (u *staticUpstream) GetTryDuration() time.Duration {
	return u.TryDuration
}

// GetTryInterval returns u.TryInterval.
func (u *staticUpstream) GetTryInterval() time.Duration {
	return u.TryInterval
}

func (u *staticUpstream) GetHostCount() int {
	return len(u.Hosts)
}

// Stop sends a signal to all goroutines started by this staticUpstream to exit
// and waits for them to finish before returning.
func (u *staticUpstream) Stop() error {
	close(u.stop)
	u.wg.Wait()
	return nil
}

// RegisterPolicy adds a custom policy to the proxy.
func RegisterPolicy(name string, policy func(string) Policy) {
	supportedPolicies[name] = policy
}

func replacePort(originalURL string, newPort string) string {
	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return originalURL
	}

	// handles 'localhost' and 'localhost:8080'
	parsedHost, _, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		parsedHost = parsedURL.Host
	}

	parsedURL.Host = net.JoinHostPort(parsedHost, newPort)
	return parsedURL.String()
}
