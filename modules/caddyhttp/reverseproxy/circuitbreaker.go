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
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/vulcand/oxy/memmetrics"
)

func init() {
	caddy.RegisterModule(localCircuitBreaker{})
}

// localCircuitBreaker implements circuit breaking functionality
// for requests within this process over a sliding time window.
type localCircuitBreaker struct {
	tripped   int32
	cbType    int32
	threshold float64
	metrics   *memmetrics.RTMetrics
	tripTime  time.Duration
	Config
}

// CaddyModule returns the Caddy module information.
func (localCircuitBreaker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.circuit_breakers.local",
		New: func() caddy.Module { return new(localCircuitBreaker) },
	}
}

// Provision sets up a configured circuit breaker.
func (c *localCircuitBreaker) Provision(ctx caddy.Context) error {
	t, ok := typeCB[c.Type]
	if !ok {
		return fmt.Errorf("type is not defined")
	}

	if c.TripTime == "" {
		c.TripTime = defaultTripTime
	}

	tw, err := time.ParseDuration(c.TripTime)
	if err != nil {
		return fmt.Errorf("cannot parse trip_time duration, %v", err.Error())
	}

	mt, err := memmetrics.NewRTMetrics()
	if err != nil {
		return fmt.Errorf("cannot create new metrics: %v", err.Error())
	}

	c.cbType = t
	c.tripTime = tw
	c.threshold = c.Threshold
	c.metrics = mt
	c.tripped = 0

	return nil
}

// Ok returns whether the circuit breaker is tripped or not.
func (c *localCircuitBreaker) Ok() bool {
	tripped := atomic.LoadInt32(&c.tripped)
	return tripped == 0
}

// RecordMetric records a response status code and execution time of a request. This function should be run in a separate goroutine.
func (c *localCircuitBreaker) RecordMetric(statusCode int, latency time.Duration) {
	c.metrics.Record(statusCode, latency)
	c.checkAndSet()
}

// Ok checks our metrics to see if we should trip our circuit breaker, or if the fallback duration has completed.
func (c *localCircuitBreaker) checkAndSet() {
	var isTripped bool

	switch c.cbType {
	case typeErrorRatio:
		// check if amount of network errors exceed threshold over sliding window, threshold for comparison should be < 1.0 i.e. .5 = 50th percentile
		if c.metrics.NetworkErrorRatio() > c.threshold {
			isTripped = true
		}
	case typeLatency:
		// check if threshold in milliseconds is reached and trip
		hist, err := c.metrics.LatencyHistogram()
		if err != nil {
			return
		}

		l := hist.LatencyAtQuantile(c.threshold)
		if l.Nanoseconds()/int64(time.Millisecond) > int64(c.threshold) {
			isTripped = true
		}
	case typeStatusCodeRatio:
		// check ratio of error status codes of sliding window, threshold for comparison should be < 1.0 i.e. .5 = 50th percentile
		if c.metrics.ResponseCodeRatio(500, 600, 0, 600) > c.threshold {
			isTripped = true
		}
	}

	if isTripped {
		c.metrics.Reset()
		atomic.AddInt32(&c.tripped, 1)

		// wait tripTime amount before allowing operations to resume.
		t := time.NewTimer(c.tripTime)
		<-t.C

		atomic.AddInt32(&c.tripped, -1)
	}
}

// Config represents the configuration of a circuit breaker.
type Config struct {
	// The threshold over sliding window that would trip the circuit breaker
	Threshold float64 `json:"threshold"`
	// Possible values: latency, error_ratio, and status_ratio. It
	// defaults to latency.
	Type string `json:"type"`
	// How long to wait after the circuit is tripped before allowing operations to resume.
	// The default is 5s.
	TripTime string `json:"trip_time"`
}

const (
	typeLatency = iota + 1
	typeErrorRatio
	typeStatusCodeRatio
	defaultTripTime = "5s"
)

var (
	// typeCB handles converting a Config Type value to the internal circuit breaker types.
	typeCB = map[string]int32{
		"latency":      typeLatency,
		"error_ratio":  typeErrorRatio,
		"status_ratio": typeStatusCodeRatio,
	}
)
