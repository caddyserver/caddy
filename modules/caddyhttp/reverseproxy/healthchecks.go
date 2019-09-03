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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type HealthChecks struct {
	Active  *ActiveHealthChecks  `json:"active,omitempty"`
	Passive *PassiveHealthChecks `json:"passive,omitempty"`
}

type ActiveHealthChecks struct {
	Path         string         `json:"path,omitempty"`
	Port         int            `json:"port,omitempty"`
	Interval     caddy.Duration `json:"interval,omitempty"`
	Timeout      caddy.Duration `json:"timeout,omitempty"`
	MaxSize      int64          `json:"max_size,omitempty"`
	ExpectStatus int            `json:"expect_status,omitempty"`
	ExpectBody   string         `json:"expect_body,omitempty"`

	stopChan   chan struct{}
	httpClient *http.Client
	bodyRegexp *regexp.Regexp
}

type PassiveHealthChecks struct {
	MaxFails              int            `json:"max_fails,omitempty"`
	FailDuration          caddy.Duration `json:"fail_duration,omitempty"`
	UnhealthyRequestCount int            `json:"unhealthy_request_count,omitempty"`
	UnhealthyStatus       []int          `json:"unhealthy_status,omitempty"`
	UnhealthyLatency      caddy.Duration `json:"unhealthy_latency,omitempty"`
}

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

func (h *Handler) doActiveHealthChecksForAllHosts() {
	hosts.Range(func(key, value interface{}) bool {
		addr := key.(string)
		host := value.(Host)

		go func(addr string, host Host) {
			err := h.doActiveHealthCheck(addr, host)
			if err != nil {
				log.Printf("[ERROR] reverse_proxy: active health check for host %s: %v", addr, err)
			}
		}(addr, host)

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
func (h *Handler) doActiveHealthCheck(hostAddr string, host Host) error {
	// create the URL for the health check
	u, err := url.Parse(hostAddr)
	if err != nil {
		return err
	}
	if h.HealthChecks.Active.Path != "" {
		u.Path = h.HealthChecks.Active.Path
	}
	if h.HealthChecks.Active.Port != 0 {
		portStr := strconv.Itoa(h.HealthChecks.Active.Port)
		u.Host = net.JoinHostPort(u.Hostname(), portStr)
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}

	// do the request, careful to tame the response body
	resp, err := h.HealthChecks.Active.httpClient.Do(req)
	if err != nil {
		log.Printf("[INFO] reverse_proxy: active health check: %s is down (HTTP request failed: %v)", hostAddr, err)
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
		// drain any remaining body so connection can be re-used
		io.Copy(ioutil.Discard, body)
		resp.Body.Close()
	}()

	// if status code is outside criteria, mark down
	if h.HealthChecks.Active.ExpectStatus > 0 {
		if !caddyhttp.StatusCodeMatches(resp.StatusCode, h.HealthChecks.Active.ExpectStatus) {
			log.Printf("[INFO] reverse_proxy: active health check: %s is down (status code %d unexpected)", hostAddr, resp.StatusCode)
			_, err := host.SetHealthy(false)
			if err != nil {
				return fmt.Errorf("marking unhealthy: %v", err)
			}
			return nil
		}
	} else if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		log.Printf("[INFO] reverse_proxy: active health check: %s is down (status code %d out of tolerances)", hostAddr, resp.StatusCode)
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
			log.Printf("[INFO] reverse_proxy: active health check: %s is down (failed to read response body)", hostAddr)
			_, err := host.SetHealthy(false)
			if err != nil {
				return fmt.Errorf("marking unhealthy: %v", err)
			}
			return nil
		}
		if !h.HealthChecks.Active.bodyRegexp.Match(bodyBytes) {
			log.Printf("[INFO] reverse_proxy: active health check: %s is down (response body failed expectations)", hostAddr)
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
		log.Printf("[INFO] reverse_proxy: active health check: %s is back up", hostAddr)
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
func (h Handler) countFailure(upstream *Upstream) {
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
		log.Printf("[ERROR] proxy: upstream %s: counting failure: %v",
			upstream.hostURL, err)
	}

	// forget it later
	go func(host Host, failDuration time.Duration) {
		time.Sleep(failDuration)
		err := host.CountFail(-1)
		if err != nil {
			log.Printf("[ERROR] proxy: upstream %s: expiring failure: %v",
				upstream.hostURL, err)
		}
	}(upstream.Host, failDuration)
}
