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
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/tls"

	"github.com/caddyserver/caddy/caddyfile"
	"github.com/caddyserver/caddy/caddyhttp/httpserver"
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
	FallbackDelay     time.Duration
	Timeout           time.Duration
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
	WithoutPathPrefix            string
	IgnoredSubPaths              []string
	insecureSkipVerify           bool
	MaxFails                     int32
	resolver                     srvResolver
	CaCertPool                   *x509.CertPool
	upstreamHeaderReplacements   headerReplacements
	downstreamHeaderReplacements headerReplacements
	ClientKeyPair                *tls.Certificate
}

type srvResolver interface {
	LookupSRV(context.Context, string, string, string) (string, []*net.SRV, error)
}

// headerReplacement stores a compiled regex matcher and a string replacer, for replacement rules
type headerReplacement struct {
	regexp *regexp.Regexp
	to     string
}

// headerReplacements stores a mapping of canonical MIME header to headerReplacement
// Implements a subset of http.Header functions, to allow convenient addition and deletion of rules
type headerReplacements map[string][]headerReplacement

func (h headerReplacements) Add(key string, value headerReplacement) {
	key = textproto.CanonicalMIMEHeaderKey(key)
	h[key] = append(h[key], value)
}

func (h headerReplacements) Del(key string) {
	delete(h, textproto.CanonicalMIMEHeaderKey(key))
}

// NewStaticUpstreams parses the configuration input and sets up
// static upstreams for the proxy middleware. The host string parameter,
// if not empty, is used for setting the upstream Host header for the
// health checks if the upstream header config requires it.
func NewStaticUpstreams(c caddyfile.Dispenser, host string) ([]Upstream, error) {
	var upstreams []Upstream
	for c.Next() {

		upstream := &staticUpstream{
			from:                         "",
			stop:                         make(chan struct{}),
			upstreamHeaders:              make(http.Header),
			downstreamHeaders:            make(http.Header),
			Hosts:                        nil,
			Policy:                       &Random{},
			MaxFails:                     1,
			TryInterval:                  250 * time.Millisecond,
			MaxConns:                     0,
			KeepAlive:                    http.DefaultMaxIdleConnsPerHost,
			Timeout:                      30 * time.Second,
			resolver:                     net.DefaultResolver,
			upstreamHeaderReplacements:   make(headerReplacements),
			downstreamHeaderReplacements: make(headerReplacements),
		}

		if !c.Args(&upstream.from) {
			return upstreams, c.ArgErr()
		}

		var to []string
		hasSrv := false

		for _, t := range c.RemainingArgs() {
			if len(to) > 0 && hasSrv {
				return upstreams, c.Err("only one upstream is supported when using SRV locator")
			}

			if strings.HasPrefix(t, "srv://") || strings.HasPrefix(t, "srv+https://") {
				if len(to) > 0 {
					return upstreams, c.Err("service locator upstreams can not be mixed with host names")
				}

				hasSrv = true
			}

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

				if hasSrv {
					return upstreams, c.Err("upstream directive is not supported when backend is service locator")
				}

				parsed, err := parseUpstream(c.Val())
				if err != nil {
					return upstreams, err
				}
				to = append(to, parsed...)
			default:
				if err := parseBlock(&c, upstream, hasSrv); err != nil {
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
		!strings.HasPrefix(host, "quic:") &&
		!strings.HasPrefix(host, "srv://") &&
		!strings.HasPrefix(host, "srv+https://") {
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
		WithoutPathPrefix:            u.WithoutPathPrefix,
		MaxConns:                     u.MaxConns,
		HealthCheckResult:            atomic.Value{},
		UpstreamHeaderReplacements:   u.upstreamHeaderReplacements,
		DownstreamHeaderReplacements: u.downstreamHeaderReplacements,
	}

	baseURL, err := url.Parse(uh.Name)
	if err != nil {
		return nil, err
	}

	uh.ReverseProxy = NewSingleHostReverseProxy(baseURL, uh.WithoutPathPrefix, u.KeepAlive, u.Timeout, u.FallbackDelay)
	if u.insecureSkipVerify {
		uh.ReverseProxy.UseInsecureTransport()
	}

	if u.CaCertPool != nil {
		uh.ReverseProxy.UseOwnCACertificates(u.CaCertPool)
	}

	if u.ClientKeyPair != nil {
		uh.ReverseProxy.UseClientCertificates(u.ClientKeyPair)
	}

	return uh, nil
}

func parseUpstream(u string) ([]string, error) {
	if strings.HasPrefix(u, "unix:") {
		return []string{u}, nil
	}

	isSrv := strings.HasPrefix(u, "srv://") || strings.HasPrefix(u, "srv+https://")
	colonIdx := strings.LastIndex(u, ":")
	protoIdx := strings.Index(u, "://")

	if colonIdx == -1 || colonIdx == protoIdx {
		return []string{u}, nil
	}

	if isSrv {
		return nil, fmt.Errorf("service locator %s can not have port specified", u)
	}

	us := u[:colonIdx]
	ue := ""
	portsEnd := len(u)
	if nextSlash := strings.Index(u[colonIdx:], "/"); nextSlash != -1 {
		portsEnd = colonIdx + nextSlash
		ue = u[portsEnd:]
	}

	ports := u[len(us)+1 : portsEnd]
	separators := strings.Count(ports, "-")

	if separators == 0 {
		return []string{u}, nil
	}

	if separators > 1 {
		return nil, fmt.Errorf("port range [%s] has %d separators", ports, separators)
	}

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

func parseBlock(c *caddyfile.Dispenser, u *staticUpstream, hasSrv bool) error {
	var isUpstream bool

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
	case "fallback_delay":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return err
		}
		u.FallbackDelay = dur
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

		if hasSrv {
			return c.Err("health_check_port directive is not allowed when upstream is SRV locator")
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
		isUpstream = true
		fallthrough
	case "header_downstream":
		var header, value, replaced string
		if c.Args(&header, &value, &replaced) {
			// Don't allow - or + in replacements
			if strings.HasPrefix(header, "-") || strings.HasPrefix(header, "+") {
				return c.ArgErr()
			}
			r, err := regexp.Compile(value)
			if err != nil {
				return err
			}
			if isUpstream {
				u.upstreamHeaderReplacements.Add(header, headerReplacement{r, replaced})
			} else {
				u.downstreamHeaderReplacements.Add(header, headerReplacement{r, replaced})
			}
		} else {
			if len(value) == 0 {
				// When removing a header, the value can be optional.
				if !strings.HasPrefix(header, "-") {
					return c.ArgErr()
				}
			}
			if isUpstream {
				u.upstreamHeaders.Add(header, value)
			} else {
				u.downstreamHeaders.Add(header, value)
			}
		}
	case "transparent":
		// Note: X-Forwarded-For header is always being appended for proxy connections
		// See implementation of createUpstreamRequest in proxy.go
		u.upstreamHeaders.Add("Host", "{host}")
		u.upstreamHeaders.Add("X-Real-IP", "{remote}")
		u.upstreamHeaders.Add("X-Forwarded-Proto", "{scheme}")
		u.upstreamHeaders.Add("X-Forwarded-Port", "{server_port}")
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
	case "ca_certificates":
		caCertificates := c.RemainingArgs()
		if len(caCertificates) == 0 {
			return c.ArgErr()
		}

		pool := x509.NewCertPool()
		caCertificatesAdded := make(map[string]struct{})
		for _, caFile := range caCertificates {
			// don't add cert to pool more than once
			if _, ok := caCertificatesAdded[caFile]; ok {
				continue
			}
			caCertificatesAdded[caFile] = struct{}{}

			// any client with a certificate from this CA will be allowed to connect
			caCrt, err := ioutil.ReadFile(caFile)
			if err != nil {
				return c.Err(err.Error())
			}

			// attempt to parse pem and append to cert pool
			if ok := pool.AppendCertsFromPEM(caCrt); !ok {
				return c.Errf("loading CA certificate '%s': no certificates were successfully parsed", caFile)
			}
		}

		u.CaCertPool = pool
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
	case "timeout":
		if !c.NextArg() {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(c.Val())
		if err != nil {
			return c.Errf("unable to parse timeout duration '%s'", c.Val())
		}
		u.Timeout = dur
	case "tls_client":
		if !c.NextArg() {
                        return c.ArgErr()
                }
                clientCertFile := c.Val()
		if !c.NextArg() {
                        return c.ArgErr()
                }
                clientKeyFile := c.Val()
		clientKeyPair, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
        	if (err != nil) {
                	return c.Errf("unable to load keypair from certfile:%s keyfile:%", clientCertFile, clientKeyFile)
        	}
		u.ClientKeyPair = &clientKeyPair

	default:
		return c.Errf("unknown property '%s'", c.Val())
	}

	// these settings are at odds with one another. insecure_skip_verify disables security features over HTTPS
	// which is what we are trying to achieve with ca_certificates
	if u.insecureSkipVerify && u.CaCertPool != nil {
		return c.Errf("both insecure_skip_verify and ca_certificates cannot be set in the proxy directive")
	}

	return nil
}

func (u *staticUpstream) resolveHost(h string) ([]string, bool, error) {
	names := []string{}
	proto := "http"
	if !strings.HasPrefix(h, "srv://") && !strings.HasPrefix(h, "srv+https://") {
		return []string{h}, false, nil
	}

	if strings.HasPrefix(h, "srv+https://") {
		proto = "https"
	}

	_, addrs, err := u.resolver.LookupSRV(context.Background(), "", "", h)
	if err != nil {
		return names, true, err
	}

	for _, addr := range addrs {
		names = append(names, fmt.Sprintf("%s://%s:%d", proto, addr.Target, addr.Port))
	}

	return names, true, nil
}

func (u *staticUpstream) healthCheck() {
	for _, host := range u.Hosts {
		candidates, isSrv, err := u.resolveHost(host.Name)
		if err != nil {
			host.HealthCheckResult.Store(err.Error())
			atomic.StoreInt32(&host.Unhealthy, 1)
			continue
		}

		unhealthyCount := 0
		for _, addr := range candidates {
			hostURL := addr
			if !isSrv && u.HealthCheck.Port != "" {
				hostURL = replacePort(hostURL, u.HealthCheck.Port)
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
					if _, err := io.Copy(ioutil.Discard, r.Body); err != nil {
						log.Println("[ERROR] failed to copy: ", err)
					}
					_ = r.Body.Close()
				}()
				if r.StatusCode < 200 || r.StatusCode >= 400 {
					return true
				}
				if u.HealthCheck.ContentString == "" { // don't check for content string
					return false
				}
				// TODO ReadAll will be replaced if deemed necessary
				//      See https://github.com/caddyserver/caddy/pull/1691
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
				unhealthyCount++
			}
		}

		if unhealthyCount == len(candidates) {
			atomic.StoreInt32(&host.Unhealthy, 1)
			host.HealthCheckResult.Store("Failed")
		} else {
			atomic.StoreInt32(&host.Unhealthy, 0)
			host.HealthCheckResult.Store("OK")
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
		p := path.Clean(requestPath)
		e := path.Join(u.From(), ignoredSubPath)
		// Re-add a trailing slashes if the original
		// paths had one and the cleaned paths don't
		if strings.HasSuffix(requestPath, "/") && !strings.HasSuffix(p, "/") {
			p = p + "/"
		}
		if strings.HasSuffix(ignoredSubPath, "/") && !strings.HasSuffix(e, "/") {
			e = e + "/"
		}
		if httpserver.Path(p).Matches(e) {
			return false
		}
	}
	return true
}

// GetFallbackDelay returns u.FallbackDelay.
func (u *staticUpstream) GetFallbackDelay() time.Duration {
	return u.FallbackDelay
}

// GetTryDuration returns u.TryDuration.
func (u *staticUpstream) GetTryDuration() time.Duration {
	return u.TryDuration
}

// GetTryInterval returns u.TryInterval.
func (u *staticUpstream) GetTryInterval() time.Duration {
	return u.TryInterval
}

// GetTimeout returns u.Timeout.
func (u *staticUpstream) GetTimeout() time.Duration {
	return u.Timeout
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
