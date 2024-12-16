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
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// HealthChecks configures active and passive health checks.
type HealthChecks struct {
	// Active health checks run in the background on a timer. To
	// minimally enable active health checks, set either path or
	// port (or both). Note that active health check status
	// (healthy/unhealthy) is stored per-proxy-handler, not
	// globally; this allows different handlers to use different
	// criteria to decide what defines a healthy backend.
	//
	// Active health checks do not run for dynamic upstreams.
	Active *ActiveHealthChecks `json:"active,omitempty"`

	// Passive health checks monitor proxied requests for errors or timeouts.
	// To minimally enable passive health checks, specify at least an empty
	// config object with fail_duration > 0. Passive health check state is
	// shared (stored globally), so a failure from one handler will be counted
	// by all handlers; but the tolerances or standards for what defines
	// healthy/unhealthy backends is configured per-proxy-handler.
	//
	// Passive health checks technically do operate on dynamic upstreams,
	// but are only effective for very busy proxies where the list of
	// upstreams is mostly stable. This is because the shared/global
	// state of upstreams is cleaned up when the upstreams are no longer
	// used. Since dynamic upstreams are allocated dynamically at each
	// request (specifically, each iteration of the proxy loop per request),
	// they are also cleaned up after every request. Thus, if there is a
	// moment when no requests are actively referring to a particular
	// upstream host, the passive health check state will be reset because
	// it will be garbage-collected. It is usually better for the dynamic
	// upstream module to only return healthy, available backends instead.
	Passive *PassiveHealthChecks `json:"passive,omitempty"`
}

// ActiveHealthChecks holds configuration related to active
// health checks (that is, health checks which occur in a
// background goroutine independently).
type ActiveHealthChecks struct {
	// Deprecated: Use 'uri' instead. This field will be removed. TODO: remove this field
	Path string `json:"path,omitempty"`

	// The URI (path and query) to use for health checks
	URI string `json:"uri,omitempty"`

	// The host:port to use (if different from the upstream's dial address)
	// for health checks. This should be used in tandem with `health_header` and
	// `{http.reverse_proxy.active.target_upstream}`. This can be helpful when
	// creating an intermediate service to do a more thorough health check.
	// If upstream is set, the active health check port is ignored.
	Upstream string `json:"upstream,omitempty"`

	// The port to use (if different from the upstream's dial
	// address) for health checks. If active upstream is set,
	// this value is ignored.
	Port int `json:"port,omitempty"`

	// HTTP headers to set on health check requests.
	Headers http.Header `json:"headers,omitempty"`

	// The HTTP method to use for health checks (default "GET").
	Method string `json:"method,omitempty"`

	// The body to send with the health check request.
	Body string `json:"body,omitempty"`

	// Whether to follow HTTP redirects in response to active health checks (default off).
	FollowRedirects bool `json:"follow_redirects,omitempty"`

	// How frequently to perform active health checks (default 30s).
	Interval caddy.Duration `json:"interval,omitempty"`

	// How long to wait for a response from a backend before
	// considering it unhealthy (default 5s).
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// Number of consecutive health check passes before marking
	// a previously unhealthy backend as healthy again (default 1).
	Passes int `json:"passes,omitempty"`

	// Number of consecutive health check failures before marking
	// a previously healthy backend as unhealthy (default 1).
	Fails int `json:"fails,omitempty"`

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

// Provision ensures that a is set up properly before use.
func (a *ActiveHealthChecks) Provision(ctx caddy.Context, h *Handler) error {
	if !a.IsEnabled() {
		return nil
	}

	// Canonicalize the header keys ahead of time, since
	// JSON unmarshaled headers may be incorrect
	cleaned := http.Header{}
	for key, hdrs := range a.Headers {
		for _, val := range hdrs {
			cleaned.Add(key, val)
		}
	}
	a.Headers = cleaned

	// If Method is not set, default to GET
	if a.Method == "" {
		a.Method = http.MethodGet
	}

	h.HealthChecks.Active.logger = h.logger.Named("health_checker.active")

	timeout := time.Duration(a.Timeout)
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	if a.Path != "" {
		a.logger.Warn("the 'path' option is deprecated, please use 'uri' instead!")
	}

	// parse the URI string (supports path and query)
	if a.URI != "" {
		parsedURI, err := url.Parse(a.URI)
		if err != nil {
			return err
		}
		a.uri = parsedURI
	}

	a.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: h.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !a.FollowRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for _, upstream := range h.Upstreams {
		// if there's an alternative upstream for health-check provided in the config,
		// then use it, otherwise use the upstream's dial address. if upstream is used,
		// then the port is ignored.
		if a.Upstream != "" {
			upstream.activeHealthCheckUpstream = a.Upstream
		} else if a.Port != 0 {
			// if there's an alternative port for health-check provided in the config,
			// then use it, otherwise use the port of upstream.
			upstream.activeHealthCheckPort = a.Port
		}
	}

	if a.Interval == 0 {
		a.Interval = caddy.Duration(30 * time.Second)
	}

	if a.ExpectBody != "" {
		var err error
		a.bodyRegexp, err = regexp.Compile(a.ExpectBody)
		if err != nil {
			return fmt.Errorf("expect_body: compiling regular expression: %v", err)
		}
	}

	if a.Passes < 1 {
		a.Passes = 1
	}

	if a.Fails < 1 {
		a.Fails = 1
	}

	return nil
}

// IsEnabled checks if the active health checks have
// the minimum config necessary to be enabled.
func (a *ActiveHealthChecks) IsEnabled() bool {
	return a.Path != "" || a.URI != "" || a.Port != 0
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
			if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "active health checker panicked"); c != nil {
				c.Write(
					zap.Any("error", err),
					zap.ByteString("stack", debug.Stack()),
				)
			}
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
					if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "active health checker panicked"); c != nil {
						c.Write(
							zap.Any("error", err),
							zap.ByteString("stack", debug.Stack()),
						)
					}
				}
			}()

			networkAddr, err := caddy.NewReplacer().ReplaceOrErr(upstream.Dial, true, true)
			if err != nil {
				if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "invalid use of placeholders in dial address for active health checks"); c != nil {
					c.Write(
						zap.String("address", networkAddr),
						zap.Error(err),
					)
				}
				return
			}
			addr, err := caddy.ParseNetworkAddress(networkAddr)
			if err != nil {
				if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "bad network address"); c != nil {
					c.Write(
						zap.String("address", networkAddr),
						zap.Error(err),
					)
				}
				return
			}
			if hcp := uint(upstream.activeHealthCheckPort); hcp != 0 {
				if addr.IsUnixNetwork() || addr.IsFdNetwork() {
					addr.Network = "tcp" // I guess we just assume TCP since we are using a port??
				}
				addr.StartPort, addr.EndPort = hcp, hcp
			}
			if addr.PortRangeSize() != 1 {
				if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "multiple addresses (upstream must map to only one address)"); c != nil {
					c.Write(
						zap.String("address", networkAddr),
					)
				}
				return
			}
			hostAddr := addr.JoinHostPort(0)
			dialAddr := hostAddr
			if addr.IsUnixNetwork() || addr.IsFdNetwork() {
				// this will be used as the Host portion of a http.Request URL, and
				// paths to socket files would produce an error when creating URL,
				// so use a fake Host value instead; unix sockets are usually local
				hostAddr = "localhost"
			}
			err = h.doActiveHealthCheck(DialInfo{Network: addr.Network, Address: dialAddr}, hostAddr, networkAddr, upstream)
			if err != nil {
				if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "active health check failed"); c != nil {
					c.Write(
						zap.String("address", hostAddr),
						zap.Error(err),
					)
				}
			}
		}(upstream)
	}
}

// doActiveHealthCheck performs a health check to upstream which
// can be reached at address hostAddr. The actual address for
// the request will be built according to active health checker
// config. The health status of the host will be updated
// according to whether it passes the health check. An error is
// returned only if the health check fails to occur or if marking
// the host's health status fails.
func (h *Handler) doActiveHealthCheck(dialInfo DialInfo, hostAddr string, networkAddr string, upstream *Upstream) error {
	// create the URL for the request that acts as a health check
	u := &url.URL{
		Scheme: "http",
		Host:   hostAddr,
	}

	// split the host and port if possible, override the port if configured
	host, port, err := net.SplitHostPort(hostAddr)
	if err != nil {
		host = hostAddr
	}

	// ignore active health check port if active upstream is provided as the
	// active upstream already contains the replacement port
	if h.HealthChecks.Active.Upstream != "" {
		u.Host = h.HealthChecks.Active.Upstream
	} else if h.HealthChecks.Active.Port != 0 {
		port := strconv.Itoa(h.HealthChecks.Active.Port)
		u.Host = net.JoinHostPort(host, port)
	}

	// this is kind of a hacky way to know if we should use HTTPS, but whatever
	if tt, ok := h.Transport.(TLSTransport); ok && tt.TLSEnabled() {
		u.Scheme = "https"

		// if the port is in the except list, flip back to HTTP
		if ht, ok := h.Transport.(*HTTPTransport); ok && slices.Contains(ht.TLS.ExceptPorts, port) {
			u.Scheme = "http"
		}
	}

	// if we have a provisioned uri, use that, otherwise use
	// the deprecated Path option
	if h.HealthChecks.Active.uri != nil {
		u.Path = h.HealthChecks.Active.uri.Path
		u.RawQuery = h.HealthChecks.Active.uri.RawQuery
	} else {
		u.Path = h.HealthChecks.Active.Path
	}

	// replacer used for both body and headers. Only globals (env vars, system info, etc.) are available
	repl := caddy.NewReplacer()

	// if body is provided, create a reader for it, otherwise nil
	var requestBody io.Reader
	if h.HealthChecks.Active.Body != "" {
		// set body, using replacer
		requestBody = strings.NewReader(repl.ReplaceAll(h.HealthChecks.Active.Body, ""))
	}

	// attach dialing information to this request, as well as context values that
	// may be expected by handlers of this request
	ctx := h.ctx.Context
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	ctx = context.WithValue(ctx, caddyhttp.VarsCtxKey, map[string]any{
		dialInfoVarKey: dialInfo,
	})
	req, err := http.NewRequestWithContext(ctx, h.HealthChecks.Active.Method, u.String(), requestBody)
	if err != nil {
		return fmt.Errorf("making request: %v", err)
	}
	ctx = context.WithValue(ctx, caddyhttp.OriginalRequestCtxKey, *req)
	req = req.WithContext(ctx)

	// set headers, using replacer
	repl.Set("http.reverse_proxy.active.target_upstream", networkAddr)
	for key, vals := range h.HealthChecks.Active.Headers {
		key = repl.ReplaceAll(key, "")
		if key == "Host" {
			req.Host = repl.ReplaceAll(h.HealthChecks.Active.Headers.Get(key), "")
			continue
		}
		for _, val := range vals {
			req.Header.Add(key, repl.ReplaceKnown(val, ""))
		}
	}

	markUnhealthy := func() {
		// increment failures and then check if it has reached the threshold to mark unhealthy
		err := upstream.Host.countHealthFail(1)
		if err != nil {
			if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "could not count active health failure"); c != nil {
				c.Write(
					zap.String("host", upstream.Dial),
					zap.Error(err),
				)
			}
			return
		}
		if upstream.Host.activeHealthFails() >= h.HealthChecks.Active.Fails {
			// dispatch an event that the host newly became unhealthy
			if upstream.setHealthy(false) {
				h.events.Emit(h.ctx, "unhealthy", map[string]any{"host": hostAddr})
				upstream.Host.resetHealth()
			}
		}
	}

	markHealthy := func() {
		// increment passes and then check if it has reached the threshold to be healthy
		err := upstream.Host.countHealthPass(1)
		if err != nil {
			if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "could not count active health pass"); c != nil {
				c.Write(
					zap.String("host", upstream.Dial),
					zap.Error(err),
				)
			}
			return
		}
		if upstream.Host.activeHealthPasses() >= h.HealthChecks.Active.Passes {
			if upstream.setHealthy(true) {
				if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "host is up"); c != nil {
					c.Write(zap.String("host", hostAddr))
				}
				h.events.Emit(h.ctx, "healthy", map[string]any{"host": hostAddr})
				upstream.Host.resetHealth()
			}
		}
	}

	// do the request, being careful to tame the response body
	resp, err := h.HealthChecks.Active.httpClient.Do(req)
	if err != nil {
		if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "HTTP request failed"); c != nil {
			c.Write(
				zap.String("host", hostAddr),
				zap.Error(err),
			)
		}
		markUnhealthy()
		return nil
	}
	var body io.Reader = resp.Body
	if h.HealthChecks.Active.MaxSize > 0 {
		body = io.LimitReader(body, h.HealthChecks.Active.MaxSize)
	}
	defer func() {
		// drain any remaining body so connection could be re-used
		_, _ = io.Copy(io.Discard, body)
		resp.Body.Close()
	}()

	// if status code is outside criteria, mark down
	if h.HealthChecks.Active.ExpectStatus > 0 {
		if !caddyhttp.StatusCodeMatches(resp.StatusCode, h.HealthChecks.Active.ExpectStatus) {
			if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "unexpected status code"); c != nil {
				c.Write(
					zap.Int("status_code", resp.StatusCode),
					zap.String("host", hostAddr),
				)
			}
			markUnhealthy()
			return nil
		}
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "status code out of tolerances"); c != nil {
			c.Write(
				zap.Int("status_code", resp.StatusCode),
				zap.String("host", hostAddr),
			)
		}
		markUnhealthy()
		return nil
	}

	// if body does not match regex, mark down
	if h.HealthChecks.Active.bodyRegexp != nil {
		bodyBytes, err := io.ReadAll(body)
		if err != nil {
			if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "failed to read response body"); c != nil {
				c.Write(
					zap.String("host", hostAddr),
					zap.Error(err),
				)
			}
			markUnhealthy()
			return nil
		}
		if !h.HealthChecks.Active.bodyRegexp.Match(bodyBytes) {
			if c := h.HealthChecks.Active.logger.Check(zapcore.InfoLevel, "response body failed expectations"); c != nil {
				c.Write(
					zap.String("host", hostAddr),
				)
			}
			markUnhealthy()
			return nil
		}
	}

	// passed health check parameters, so mark as healthy
	markHealthy()

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
	err := upstream.Host.countFail(1)
	if err != nil {
		if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "could not count failure"); c != nil {
			c.Write(
				zap.String("host", upstream.Dial),
				zap.Error(err),
			)
		}
		return
	}

	// forget it later
	go func(host *Host, failDuration time.Duration) {
		defer func() {
			if err := recover(); err != nil {
				if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "passive health check failure forgetter panicked"); c != nil {
					c.Write(
						zap.Any("error", err),
						zap.ByteString("stack", debug.Stack()),
					)
				}
			}
		}()
		timer := time.NewTimer(failDuration)
		select {
		case <-h.ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
		err := host.countFail(-1)
		if err != nil {
			if c := h.HealthChecks.Active.logger.Check(zapcore.ErrorLevel, "could not forget failure"); c != nil {
				c.Write(
					zap.String("host", upstream.Dial),
					zap.Error(err),
				)
			}
		}
	}(upstream.Host, failDuration)
}
