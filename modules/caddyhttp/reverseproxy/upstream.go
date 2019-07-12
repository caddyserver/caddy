// Copyright 2015 Matthew Holt and The Caddy Authors
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

// Package reverseproxy implements a load-balanced reverse proxy.
package reverseproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// CircuitBreaker defines the functionality of a circuit breaker module.
type CircuitBreaker interface {
	Ok() bool
	RecordMetric(statusCode int, latency time.Duration)
}

type noopCircuitBreaker struct{}

func (ncb noopCircuitBreaker) RecordMetric(statusCode int, latency time.Duration) {}
func (ncb noopCircuitBreaker) Ok() bool {
	return true
}

const (
	// TypeBalanceRoundRobin represents the value to use for configuring a load balanced reverse proxy to use round robin load balancing.
	TypeBalanceRoundRobin = iota

	// TypeBalanceRandom represents the value to use for configuring a load balanced reverse proxy to use random load balancing.
	TypeBalanceRandom

	// TODO: add random with two choices

	// msgNoHealthyUpstreams is returned if there are no upstreams that are healthy to proxy a request to
	msgNoHealthyUpstreams = "No healthy upstreams."

	// by default perform health checks every 30 seconds
	defaultHealthCheckDur = time.Second * 30

	// used when an upstream is unhealthy, health checks can be configured to perform at a faster rate
	defaultFastHealthCheckDur = time.Second * 1
)

var (
	// defaultTransport is the default transport to use for the reverse proxy.
	defaultTransport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	// defaultHTTPClient is the default http client to use for the healthchecker.
	defaultHTTPClient = &http.Client{
		Timeout:   time.Second * 10,
		Transport: defaultTransport,
	}

	// typeMap maps caddy load balance configuration to the internal representation of the loadbalance algorithm type.
	typeMap = map[string]int{
		"round_robin": TypeBalanceRoundRobin,
		"random":      TypeBalanceRandom,
	}
)

// NewLoadBalancedReverseProxy returns a collection of Upstreams that are to be loadbalanced.
func NewLoadBalancedReverseProxy(lb *LoadBalanced, ctx caddy.Context) error {
	// set defaults
	if lb.NoHealthyUpstreamsMessage == "" {
		lb.NoHealthyUpstreamsMessage = msgNoHealthyUpstreams
	}

	if lb.TryInterval == "" {
		lb.TryInterval = "20s"
	}

	// set request retry interval
	ti, err := time.ParseDuration(lb.TryInterval)
	if err != nil {
		return fmt.Errorf("NewLoadBalancedReverseProxy: %v", err.Error())
	}
	lb.tryInterval = ti

	// set load balance algorithm
	t, ok := typeMap[lb.LoadBalanceType]
	if !ok {
		t = TypeBalanceRandom
	}
	lb.loadBalanceType = t

	// setup each upstream
	var us []*upstream
	for _, uc := range lb.Upstreams {
		// pass the upstream decr and incr methods to keep track of unhealthy nodes
		nu, err := newUpstream(uc, lb.decrUnhealthy, lb.incrUnhealthy)
		if err != nil {
			return err
		}

		// setup any configured circuit breakers
		var cbModule = "http.handlers.reverse_proxy.circuit_breaker"
		var cb CircuitBreaker

		if uc.CircuitBreaker != nil {
			if _, err := caddy.GetModule(cbModule); err == nil {
				val, err := ctx.LoadModule(cbModule, uc.CircuitBreaker)
				if err == nil {
					cbv, ok := val.(CircuitBreaker)
					if ok {
						cb = cbv
					} else {
						fmt.Printf("\nerr: %v; cannot load circuit_breaker, using noop", err.Error())
						cb = noopCircuitBreaker{}
					}
				} else {
					fmt.Printf("\nerr: %v; cannot load circuit_breaker, using noop", err.Error())
					cb = noopCircuitBreaker{}
				}
			} else {
				fmt.Println("circuit_breaker module not loaded, using noop")
				cb = noopCircuitBreaker{}
			}
		} else {
			cb = noopCircuitBreaker{}
		}
		nu.CB = cb

		// start a healthcheck worker which will periodically check to see if an upstream is healthy
		// to proxy requests to.
		nu.healthChecker = NewHealthCheckWorker(nu, defaultHealthCheckDur, defaultHTTPClient)

		// TODO :- if path is empty why does this empty the entire Target?
		// nu.Target.Path = uc.HealthCheckPath

		nu.healthChecker.ScheduleChecks(nu.Target.String())
		lb.HealthCheckers = append(lb.HealthCheckers, nu.healthChecker)

		us = append(us, nu)
	}

	lb.upstreams = us

	return nil
}

// LoadBalanced represents a collection of upstream hosts that are loadbalanced. It
// contains multiple features like health checking and circuit breaking functionality
// for upstreams.
type LoadBalanced struct {
	mu              sync.Mutex
	numUnhealthy    int32
	selectedServer  int // used during round robin load balancing
	loadBalanceType int
	tryInterval     time.Duration
	upstreams       []*upstream

	// The following struct fields are set by caddy configuration.
	// TryInterval is the max duration for which request retrys will be performed for a request.
	TryInterval string `json:"try_interval"`

	// Upstreams are the configs for upstream hosts
	Upstreams []*UpstreamConfig `json:"upstreams"`

	// LoadBalanceType is the string representation of what loadbalancing algorithm to use. i.e. "random" or "round_robin".
	LoadBalanceType string `json:"load_balance_type"`

	// NoHealthyUpstreamsMessage is returned as a response when there are no healthy upstreams to loadbalance to.
	NoHealthyUpstreamsMessage string `json:"no_healthy_upstreams_message"`

	// TODO :- store healthcheckers as package level state where each upstream gets a single healthchecker
	// currently a healthchecker is created for each upstream defined, even if a healthchecker was previously created
	// for that upstream
	HealthCheckers []*HealthChecker
}

// Cleanup stops all health checkers on a loadbalanced reverse proxy.
func (lb *LoadBalanced) Cleanup() error {
	for _, hc := range lb.HealthCheckers {
		hc.Stop()
	}

	return nil
}

// Provision sets up a new loadbalanced reverse proxy.
func (lb *LoadBalanced) Provision(ctx caddy.Context) error {
	return NewLoadBalancedReverseProxy(lb, ctx)
}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface to
// dispatch an HTTP request to the proper server.
func (lb *LoadBalanced) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	// ensure requests don't hang if an upstream does not respond or is not eventually healthy
	var u *upstream
	var done bool

	retryTimer := time.NewTicker(lb.tryInterval)
	defer retryTimer.Stop()

	go func() {
		select {
		case <-retryTimer.C:
			done = true
		}
	}()

	// keep trying to get an available upstream to process the request
	for {
		switch lb.loadBalanceType {
		case TypeBalanceRandom:
			u = lb.random()
		case TypeBalanceRoundRobin:
			u = lb.roundRobin()
		}

		// if we can't get an upstream and our retry interval has ended return an error response
		if u == nil && done {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, lb.NoHealthyUpstreamsMessage)

			return fmt.Errorf(msgNoHealthyUpstreams)
		}

		// attempt to get an available upstream
		if u == nil {
			continue
		}

		start := time.Now()

		// if we get an error retry until we get a healthy upstream
		res, err := u.ReverseProxy.ServeHTTP(w, r)
		if err != nil {
			if err == context.Canceled {
				return nil
			}

			continue
		}

		// record circuit breaker metrics
		go u.CB.RecordMetric(res.StatusCode, time.Now().Sub(start))

		return nil
	}
}

// incrUnhealthy increments the amount of unhealthy nodes in a loadbalancer.
func (lb *LoadBalanced) incrUnhealthy() {
	atomic.AddInt32(&lb.numUnhealthy, 1)
}

// decrUnhealthy decrements the amount of unhealthy nodes in a loadbalancer.
func (lb *LoadBalanced) decrUnhealthy() {
	atomic.AddInt32(&lb.numUnhealthy, -1)
}

// roundRobin implements a round robin load balancing algorithm to select
// which server to forward requests to.
func (lb *LoadBalanced) roundRobin() *upstream {
	if atomic.LoadInt32(&lb.numUnhealthy) == int32(len(lb.upstreams)) {
		return nil
	}

	selected := lb.upstreams[lb.selectedServer]

	lb.mu.Lock()
	lb.selectedServer++
	if lb.selectedServer >= len(lb.upstreams) {
		lb.selectedServer = 0
	}
	lb.mu.Unlock()

	if selected.IsHealthy() && selected.CB.Ok() {
		return selected
	}

	return nil
}

// random implements a random server selector for load balancing.
func (lb *LoadBalanced) random() *upstream {
	if atomic.LoadInt32(&lb.numUnhealthy) == int32(len(lb.upstreams)) {
		return nil
	}

	n := rand.Int() % len(lb.upstreams)
	selected := lb.upstreams[n]

	if selected.IsHealthy() && selected.CB.Ok() {
		return selected
	}

	return nil
}

// UpstreamConfig represents the config of an upstream.
type UpstreamConfig struct {
	// Host is the host name of the upstream server.
	Host string `json:"host"`

	// FastHealthCheckDuration is the duration for which a health check is performed when a node is considered unhealthy.
	FastHealthCheckDuration string `json:"fast_health_check_duration"`

	CircuitBreaker json.RawMessage `json:"circuit_breaker"`

	// // CircuitBreakerConfig is the config passed to setup a circuit breaker.
	// CircuitBreakerConfig *circuitbreaker.Config `json:"circuit_breaker"`
	circuitbreaker CircuitBreaker

	// HealthCheckDuration is the default duration for which a health check is performed.
	HealthCheckDuration string `json:"health_check_duration"`

	// HealthCheckPath is the path at the upstream host to use for healthchecks.
	HealthCheckPath string `json:"health_check_path"`
}

// upstream represents an upstream host.
type upstream struct {
	Healthy            int32 // 0 = false, 1 = true
	Target             *url.URL
	ReverseProxy       *ReverseProxy
	Incr               func()
	Decr               func()
	CB                 CircuitBreaker
	healthChecker      *HealthChecker
	healthCheckDur     time.Duration
	fastHealthCheckDur time.Duration
}

// newUpstream returns a new upstream.
func newUpstream(uc *UpstreamConfig, d func(), i func()) (*upstream, error) {
	host := strings.TrimSpace(uc.Host)
	protoIdx := strings.Index(host, "://")
	if protoIdx == -1 || len(host[:protoIdx]) == 0 {
		return nil, fmt.Errorf("protocol is required for host")
	}

	hostURL, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	// parse healthcheck durations
	hcd, err := time.ParseDuration(uc.HealthCheckDuration)
	if err != nil {
		hcd = defaultHealthCheckDur
	}

	fhcd, err := time.ParseDuration(uc.FastHealthCheckDuration)
	if err != nil {
		fhcd = defaultFastHealthCheckDur
	}

	u := upstream{
		healthCheckDur:     hcd,
		fastHealthCheckDur: fhcd,
		Target:             hostURL,
		Decr:               d,
		Incr:               i,
		Healthy:            int32(0), // assume is unhealthy on start
	}

	u.ReverseProxy = newReverseProxy(hostURL, u.SetHealthiness)
	return &u, nil
}

// SetHealthiness sets whether an upstream is healthy or not. The health check worker is updated to
// perform checks faster if a node is unhealthy.
func (u *upstream) SetHealthiness(ok bool) {
	h := atomic.LoadInt32(&u.Healthy)
	var wasHealthy bool
	if h == 1 {
		wasHealthy = true
	} else {
		wasHealthy = false
	}

	if ok {
		u.healthChecker.Ticker = time.NewTicker(u.healthCheckDur)

		if !wasHealthy {
			atomic.AddInt32(&u.Healthy, 1)
			u.Decr()
		}
	} else {
		u.healthChecker.Ticker = time.NewTicker(u.fastHealthCheckDur)

		if wasHealthy {
			atomic.AddInt32(&u.Healthy, -1)
			u.Incr()
		}
	}
}

// IsHealthy returns whether an Upstream is healthy or not.
func (u *upstream) IsHealthy() bool {
	i := atomic.LoadInt32(&u.Healthy)
	if i == 1 {
		return true
	}

	return false
}

// newReverseProxy returns a new reverse proxy handler.
func newReverseProxy(target *url.URL, setHealthiness func(bool)) *ReverseProxy {
	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		// we don't need to worry about cancelled contexts since this doesn't necessarilly mean that
		// the upstream is unhealthy.
		if err != context.Canceled {
			setHealthiness(false)
		}
	}

	rp := NewSingleHostReverseProxy(target)
	rp.ErrorHandler = errorHandler
	rp.Transport = defaultTransport // use default transport that times out in 5 seconds
	return rp
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*LoadBalanced)(nil)
	_ caddy.Provisioner           = (*LoadBalanced)(nil)
	_ caddy.CleanerUpper          = (*LoadBalanced)(nil)
)
