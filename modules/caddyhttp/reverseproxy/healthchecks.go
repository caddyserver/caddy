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

package reverseproxy

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// HealthChecks configures active and passive health checks.
type HealthChecks struct {
	// Active health checks run in the background on a timer. To
	// minimally enable active health checks, set either path or
	// port (or both).
	Active *ActiveHealthChecks `json:"active,omitempty"`

	// Passive health checks monitor proxied requests for errors or timeouts.
	// To minimally enable passive health checks, specify at least an empty
	// config object.
	Passive *PassiveHealthChecks `json:"passive,omitempty"`
}

// ActiveHealthChecks holds configuration related to active
// health checks (that is, health checks which occur in a
// background goroutine independently).
type ActiveHealthChecks struct {
	// The path to use for health checks.
	// DEPRECATED: Use 'uri' instead.
	Path string `json:"path,omitempty"`

	// The URI (path and query) to use for health checks
	URI string `json:"uri,omitempty"`

	// The port to use (if different from the upstream's dial
	// address) for health checks.
	Port int `json:"port,omitempty"`

	// HTTP headers to set on health check requests.
	Headers http.Header `json:"headers,omitempty"`

	// How frequently to perform active health checks (default 30s).
	Interval caddy.Duration `json:"interval,omitempty"`

	// How long to wait for a response from a backend before
	// considering it unhealthy (default 5s).
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// The maximum response body to download from the backend
	// during a health check.
	MaxSize int64 `json:"max_size,omitempty"`

	// The HTTP status code to expect from a healthy backend.
	ExpectStatus int `json:"expect_status,omitempty"`

	// A regular expression against which to match the response
	// body of a healthy backend.
	ExpectBody string `json:"expect_body,omitempty"`

	uri        *url.URL
	httpClient *http.Client
	bodyRegexp *regexp.Regexp
	logger     *zap.Logger
}

// PassiveHealthChecks holds configuration related to passive
// health checks (that is, health checks which occur during
// the normal flow of request proxying).
type PassiveHealthChecks struct {
	// How long to remember a failed request to a backend. A duration > 0
	// enables passive health checking. Default is 0.
	FailDuration caddy.Duration `json:"fail_duration,omitempty"`

	// The number of failed requests within the FailDuration window to
	// consider a backend as "down". Must be >= 1; default is 1. Requires
	// that FailDuration be > 0.
	MaxFails int `json:"max_fails,omitempty"`

	// Limits the number of simultaneous requests to a backend by
	// marking the backend as "down" if it has this many concurrent
	// requests or more.
	UnhealthyRequestCount int `json:"unhealthy_request_count,omitempty"`

	// Count the request as failed if the response comes back with
	// one of these status codes.
	UnhealthyStatus []int `json:"unhealthy_status,omitempty"`

	// Count the request as failed if the response takes at least this
	// long to receive.
	UnhealthyLatency caddy.Duration `json:"unhealthy_latency,omitempty"`

	logger *zap.Logger
}

// CircuitBreaker is a type that can act as an early-warning
// system for the health checker when backends are getting
// overloaded. This interface is still experimental and is
// subject to change.
type CircuitBreaker interface {
	OK() bool
	RecordMetric(statusCode int, latency time.Duration)
}

// activeHealthChecker runs active health checks on a
// regular basis and blocks until
// h.HealthChecks.Active.stopChan is closed.
func (h *Handler) activeHealthChecker() {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("[PANIC] active health checks: %v\n%s", err, debug.Stack())
		}
	}()
	ticker := time.NewTicker(time.Duration(h.HealthChecks.Active.Interval))
	h.doActiveHealthCheckForAllHosts()
	for {
		select {
		case <-ticker.C:
			h.doActiveHealthCheckForAllHosts()
		case <-h.ctx.Done():
			ticker.Stop()
			return
		}
	}
}

// doActiveHealthCheckForAllHosts immediately performs a
// health checks for all upstream hosts configured by h.
func (h *Handler) doActiveHealthCheckForAllHosts() {
	for _, upstream := range h.Upstreams {
		go func(upstream *Upstream) {
			defer func() {
				if err := recover(); err != nil {
					log.Printf("[PANIC] active health check: %v\n%s", err, debug.Stack())
				}
			}()

			networkAddr, err := caddy.NewReplacer().ReplaceOrErr(upstream.Dial, true, true)
			if err != nil {
				h.HealthChecks.Active.logger.Error("invalid use of placeholders in dial address for active health checks",
					zap.String("address", networkAddr),
					zap.Error(err),
				)
				return
			}
			addr, err := caddy.ParseNetworkAddress(networkAddr)
			if err != nil {
				h.HealthChecks.Active.logger.Error("bad network address",
					zap.String("address", networkAddr),
					zap.Error(err),
				)
				return
			}
			if hcp := uint(upstream.activeHealthCheckPort); hcp != 0 {
				if addr.IsUnixNetwork() {
					addr.Network = "tcp" // I guess we just assume TCP since we are using a port??
				}
				addr.StartPort, addr.EndPort = hcp, hcp
			}
			if upstream.LookupSRV == "" && addr.PortRangeSize() != 1 {
				h.HealthChecks.Active.logger.Error("multiple addresses (upstream must map to only one address)",
					zap.String("address", networkAddr),
				)
				return
			}
			hostAddr := addr.JoinHostPort(0)
			dialAddr := hostAddr
			if addr.IsUnixNetwork() {
				// this will be used as the Host portion of a http.Request URL, and
				// paths to socket files would produce an error when creating URL,
				// so use a fake Host value instead; unix sockets are usually local
				hostAddr = "localhost"
			}
			err = h.doActiveHealthCheck(DialInfo{Network: addr.Network, Address: dialAddr}, hostAddr, upstream.Host)
			if err != nil {
				h.HealthChecks.Active.logger.Error("active health check failed",
					zap.String("address", hostAddr),
					zap.Error(err),
				)
			}
		}(upstream)
	}
}

// doActiveHealthCheck performs a health check to host which
// can be reached at address hostAddr. The actual address for
// the request will be built according to active health checker
// config. The health status of the host will be updated
// according to whether it passes the health check. An error is
// returned only if the health check fails to occur or if marking
// the host's health status fails.
func (h *Handler) doActiveHealthCheck(dialInfo DialInfo, hostAddr string, host Host) error {
	// create the URL for the request that acts as a health check
	scheme := "http"
	if ht, ok := h.Transport.(TLSTransport); ok && ht.TLSEnabled() {
		// this is kind of a hacky way to know if we should use HTTPS, but whatever
		scheme = "https"
	}
	u := &url.URL{
		Scheme: scheme,
		Host:   hostAddr,
	}

	// if we have a provisioned uri, use that, otherwise use
	// the deprecated Path option
	if h.HealthChecks.Active.uri != nil {
		u.Path = h.HealthChecks.Active.uri.Path
		u.RawQuery = h.HealthChecks.Active.uri.RawQuery
	} else {
		u.Path = h.HealthChecks.Active.Path
	}

	// adjust the port, if configured to be different
	if h.HealthChecks.Active.Port != 0 {
		portStr := strconv.Itoa(h.HealthChecks.Active.Port)
		host, _, err := net.SplitHostPort(hostAddr)
		if err != nil {
			host = hostAddr
		}
		u.Host = net.JoinHostPort(host, portStr)
	}

	// attach dialing information to this request
	ctx := h.ctx.Context
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]interface{}{
		dialInfoVarKey: dialInfo,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("making request: %v", err)
	}
	for key, hdrs := range h.HealthChecks.Active.Headers {
		if strings.ToLower(key) == "host" {
			req.Host = h.HealthChecks.Active.Headers.Get(key)
		} else {
			req.Header[key] = hdrs
		}
	}

	// do the request, being careful to tame the response body
	resp, err := h.HealthChecks.Active.httpClient.Do(req)
	if err != nil {
		h.HealthChecks.Active.logger.Info("HTTP request failed",
			zap.String("host", hostAddr),
			zap.Error(err),
		)
		_, err2 := host.SetHealthy(false)
		if err2 != nil {
			return fmt.Errorf("marking unhealthy: %v", err2)
		}
		return nil
	}
	var body io.Reader = resp.Body
	if h.HealthChecks.Active.MaxSize > 0 {
		body = io.LimitReader(body, h.HealthChecks.Active.MaxSize)
	}
	defer func() {
		// drain any remaining body so connection could be re-used
		_, _ = io.Copy(ioutil.Discard, body)
		resp.Body.Close()
	}()

	// if status code is outside criteria, mark down
	if h.HealthChecks.Active.ExpectStatus > 0 {
		if !caddyhttp.StatusCodeMatches(resp.StatusCode, h.HealthChecks.Active.ExpectStatus) {
			h.HealthChecks.Active.logger.Info("unexpected status code",
				zap.Int("status_code", resp.StatusCode),
				zap.String("host", hostAddr),
			)
			_, err := host.SetHealthy(false)
			if err != nil {
				return fmt.Errorf("marking unhealthy: %v", err)
			}
			return nil
		}
	} else if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		h.HealthChecks.Active.logger.Info("status code out of tolerances",
			zap.Int("status_code", resp.StatusCode),
			zap.String("host", hostAddr),
		)
		_, err := host.SetHealthy(false)
		if err != nil {
			return fmt.Errorf("marking unhealthy: %v", err)
		}
		return nil
	}

	// if body does not match regex, mark down
	if h.HealthChecks.Active.bodyRegexp != nil {
		bodyBytes, err := ioutil.ReadAll(body)
		if err != nil {
			h.HealthChecks.Active.logger.Info("failed to read response body",
				zap.String("host", hostAddr),
				zap.Error(err),
			)
			_, err := host.SetHealthy(false)
			if err != nil {
				return fmt.Errorf("marking unhealthy: %v", err)
			}
			return nil
		}
		if !h.HealthChecks.Active.bodyRegexp.Match(bodyBytes) {
			h.HealthChecks.Active.logger.Info("response body failed expectations",
				zap.String("host", hostAddr),
			)
			_, err := host.SetHealthy(false)
			if err != nil {
				return fmt.Errorf("marking unhealthy: %v", err)
			}
			return nil
		}
	}

	// passed health check parameters, so mark as healthy
	swapped, err := host.SetHealthy(true)
	if swapped {
		h.HealthChecks.Active.logger.Info("host is up",
			zap.String("host", hostAddr),
		)
	}
	if err != nil {
		return fmt.Errorf("marking healthy: %v", err)
	}

	return nil
}

// countFailure is used with passive health checks. It
// remembers 1 failure for upstream for the configured
// duration. If passive health checks are disabled or
// failure expiry is 0, this is a no-op.
func (h *Handler) countFailure(upstream *Upstream) {
	// only count failures if passive health checking is enabled
	// and if failures are configured have a non-zero expiry
	if h.HealthChecks == nil || h.HealthChecks.Passive == nil {
		return
	}
	failDuration := time.Duration(h.HealthChecks.Passive.FailDuration)
	if failDuration == 0 {
		return
	}

	// count failure immediately
	err := upstream.Host.CountFail(1)
	if err != nil {
		h.HealthChecks.Passive.logger.Error("could not count failure",
			zap.String("host", upstream.Dial),
			zap.Error(err))
		return
	}

	// forget it later
	go func(host Host, failDuration time.Duration) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[PANIC] health check failure forgetter: %v\n%s", err, debug.Stack())
			}
		}()
		time.Sleep(failDuration)
		err := host.CountFail(-1)
		if err != nil {
			h.HealthChecks.Passive.logger.Error("could not forget failure",
				zap.String("host", upstream.Dial),
				zap.Error(err))
		}
	}(upstream.Host, failDuration)
}
