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
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// HealthChecks holds configuration related to health checking.
type HealthChecks struct {
	Active  *ActiveHealthChecks  `json:"active,omitempty"`
	Passive *PassiveHealthChecks `json:"passive,omitempty"`
}

// ActiveHealthChecks holds configuration related to active
// health checks (that is, health checks which occur in a
// background goroutine independently).
type ActiveHealthChecks struct {
	Path         string         `json:"path,omitempty"`
	Port         int            `json:"port,omitempty"`
	Headers      http.Header    `json:"headers,omitempty"`
	Interval     caddy.Duration `json:"interval,omitempty"`
	Timeout      caddy.Duration `json:"timeout,omitempty"`
	MaxSize      int64          `json:"max_size,omitempty"`
	ExpectStatus int            `json:"expect_status,omitempty"`
	ExpectBody   string         `json:"expect_body,omitempty"`

	stopChan   chan struct{}
	httpClient *http.Client
	bodyRegexp *regexp.Regexp
	logger     *zap.Logger
}

// PassiveHealthChecks holds configuration related to passive
// health checks (that is, health checks which occur during
// the normal flow of request proxying).
type PassiveHealthChecks struct {
	MaxFails              int            `json:"max_fails,omitempty"`
	FailDuration          caddy.Duration `json:"fail_duration,omitempty"`
	UnhealthyRequestCount int            `json:"unhealthy_request_count,omitempty"`
	UnhealthyStatus       []int          `json:"unhealthy_status,omitempty"`
	UnhealthyLatency      caddy.Duration `json:"unhealthy_latency,omitempty"`

	logger *zap.Logger
}

// CircuitBreaker is a type that can act as an early-warning
// system for the health checker when backends are getting
// overloaded.
type CircuitBreaker interface {
	OK() bool
	RecordMetric(statusCode int, latency time.Duration)
}

// activeHealthChecker runs active health checks on a
// regular basis and blocks until
// h.HealthChecks.Active.stopChan is closed.
func (h *Handler) activeHealthChecker() {
	ticker := time.NewTicker(time.Duration(h.HealthChecks.Active.Interval))
	h.doActiveHealthChecksForAllHosts()
	for {
		select {
		case <-ticker.C:
			h.doActiveHealthChecksForAllHosts()
		case <-h.HealthChecks.Active.stopChan:
			ticker.Stop()
			return
		}
	}
}

// doActiveHealthChecksForAllHosts immediately performs a
// health checks for all hosts in the global repository.
func (h *Handler) doActiveHealthChecksForAllHosts() {
	hosts.Range(func(key, value interface{}) bool {
		networkAddr := key.(string)
		host := value.(Host)

		go func(networkAddr string, host Host) {
			addr, err := caddy.ParseNetworkAddress(networkAddr)
			if err != nil {
				h.HealthChecks.Active.logger.Error("bad network address",
					zap.String("address", networkAddr),
					zap.Error(err),
				)
				return
			}
			if addr.PortSpanSize() != 1 {
				h.HealthChecks.Active.logger.Error("multiple addresses (upstream must map to only one address)",
					zap.String("address", networkAddr),
				)
				return
			}
			hostAddr := net.JoinHostPort(addr.Host, fmt.Sprintf("%d", addr.FromPort))
			if addr.Network == "unix" || addr.Network == "unixgram" || addr.Network == "unixpacket" {
				// this will be used as the Host portion of a http.Request URL, and
				// paths to socket files would produce an error when creating URL,
				// so use a fake Host value instead; unix sockets are usually local
				hostAddr = "localhost"
			}
			err = h.doActiveHealthCheck(DialInfo{Network: addr.Network, Address: hostAddr}, hostAddr, host)
			if err != nil {
				h.HealthChecks.Active.logger.Error("active health check failed",
					zap.String("address", networkAddr),
					zap.Error(err),
				)
			}
		}(networkAddr, host)

		// continue to iterate all hosts
		return true
	})
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
	if ht, ok := h.Transport.(*http.Transport); ok && ht.TLSClientConfig != nil {
		// this is kind of a hacky way to know if we should use HTTPS, but whatever
		scheme = "https"
	}
	u := &url.URL{
		Scheme: scheme,
		Host:   hostAddr,
		Path:   h.HealthChecks.Active.Path,
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
	ctx := context.Background()
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	ctx = context.WithValue(ctx, DialInfoCtxKey, dialInfo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("making request: %v", err)
	}
	for key, hdrs := range h.HealthChecks.Active.Headers {
		req.Header[key] = hdrs
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
		io.Copy(ioutil.Discard, body)
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
			zap.Error(err),
		)
	}

	// forget it later
	go func(host Host, failDuration time.Duration) {
		time.Sleep(failDuration)
		err := host.CountFail(-1)
		if err != nil {
			h.HealthChecks.Passive.logger.Error("could not forget failure",
				zap.String("host", upstream.Dial),
				zap.Error(err),
			)
		}
	}(upstream.Host, failDuration)
}
