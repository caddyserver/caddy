package proxy

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mholt/caddy/caddy/parse"
	"github.com/mholt/caddy/middleware"
	"github.com/mholt/caddy/middleware/proxy/provider"
)

var (
	supportedPolicies = make(map[string]func() Policy)
)

type staticUpstream struct {
	from               string
	proxyHeaders       http.Header
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

	// Ensure distinct hosts
	hostSet map[string]struct{}

	sync.RWMutex
}

// NewStaticUpstreams parses the configuration input and sets up
// static upstreams for the proxy middleware.
func NewStaticUpstreams(c parse.Dispenser) ([]Upstream, error) {
	var upstreams []Upstream
	for c.Next() {
		upstream := &staticUpstream{
			from:         "",
			proxyHeaders: make(http.Header),
			Hosts:        nil,
			Policy:       &Random{},
			FailTimeout:  10 * time.Second,
			MaxFails:     1,
			hostSet:      make(map[string]struct{}),
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

		for _, addr := range to {
			var p provider.Provider
			var err error
			var hosts []string
			// fetch provider
			if p, err = provider.Get(addr); err != nil {
				return upstreams, err
			}
			// fetch hosts from provider
			if hosts, err = p.Hosts(); err != nil {
				return upstreams, err
			}
			// add hosts to upstream
			for _, host := range hosts {
				err := upstream.AddHost(host)
				if err != nil {
					return upstreams, err
				}
			}
			// if provider is dynamic
			// watch for upcoming changes
			if dp, ok := p.(provider.DynamicProvider); ok {
				watcher := dp.Watch()
				go upstream.ProviderWorker(watcher, nil)
			}
		}

		if upstream.HealthCheck.Path != "" {
			// TODO provide stop channel
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

func (upstream *staticUpstream) ProviderWorker(watcher provider.Watcher, stop <-chan struct{}) {
	type message struct {
		msgs []provider.WatcherMsg
		err  error
	}
	resp := make(chan message)
	go func() {
		for {
			// blocks until there's a message from Watcher
			m, err := watcher.Next()
			select {
			case resp <- message{m, err}:
			case <-stop:
				return
			}
		}
	}()

	interval := 5
	delay := func() {
		log.Printf("Delaying %d seconds before next attempt.", interval)
		time.Sleep(time.Second * time.Duration(interval))

		// delay at most 60 seconds.
		interval += 5
		if interval > 60 {
			interval = 60
		}
	}
	for {
		m, ok := <-resp
		if !ok {
			break
		}
		if m.err != nil {
			log.Println(m.err)
			delay()
			continue
		} else {
			// no errors, reset delay interval.
			interval = 0
		}
		for _, msg := range m.msgs {
			if msg.Remove {
				// remove from upstream
				if upstream.RemoveHost(msg.Host) {
					log.Printf("Host %v removed from upstream", msg.Host)
				}
			} else {
				// add host to upstream
				if err := upstream.AddHost(msg.Host); err != nil {
					log.Println(err)
					continue
				}
				log.Printf("New host %v added to upstream", msg.Host)
			}
		}

	}
}

func (u *staticUpstream) Select() *UpstreamHost {
	u.RLock()
	defer u.RUnlock()

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

// AddHost adds host to upstream hosts.
func (upstream *staticUpstream) AddHost(host string) error {
	upstream.Lock()
	defer upstream.Unlock()

	host = hostName(host).String()

	// If its previously added, ignore
	if _, ok := upstream.hostSet[host]; ok {
		return nil
	}

	uh := &UpstreamHost{
		Name:         host,
		Conns:        0,
		Fails:        0,
		FailTimeout:  upstream.FailTimeout,
		Unhealthy:    false,
		ExtraHeaders: upstream.proxyHeaders,
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
		return err
	}
	upstream.Hosts = append(upstream.Hosts, uh)
	upstream.hostSet[host] = struct{}{}
	return nil
}

// RemoveHost removes host from upstream hosts.
func (upstream *staticUpstream) RemoveHost(host string) bool {
	upstream.Lock()
	defer upstream.Unlock()

	host = hostName(host).String()

	// If it does not exist, ignore
	if _, ok := upstream.hostSet[host]; !ok {
		return false
	}

	idx := -1
	for i, h := range upstream.Hosts {
		if hostName(host).equals(h.Name) {
			idx = i
			break
		}
	}
	if idx == -1 {
		return false
	}

	delete(upstream.hostSet, host)

	if idx == len(upstream.Hosts)-1 {
		upstream.Hosts = upstream.Hosts[:idx]
		return true
	}
	upstream.Hosts = append(upstream.Hosts[:idx], upstream.Hosts[idx+1:]...)
	return true
}

type hostName string

func (h hostName) equals(host string) bool {
	return h.String() == hostName(host).String()
}

func (h hostName) String() string {
	if !strings.HasPrefix(string(h), "http") && !strings.HasPrefix(string(h), "unix:") {
		return "http://" + string(h)
	}
	return string(h)
}
