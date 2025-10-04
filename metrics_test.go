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

package caddy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestGlobalMetrics_ConfigSuccess(t *testing.T) {
	// Test setting config success metric
	originalValue := getMetricValue(globalMetrics.configSuccess)

	// Set to success
	globalMetrics.configSuccess.Set(1)
	newValue := getMetricValue(globalMetrics.configSuccess)

	if newValue != 1 {
		t.Errorf("Expected config success metric to be 1, got %f", newValue)
	}

	// Set to failure
	globalMetrics.configSuccess.Set(0)
	failureValue := getMetricValue(globalMetrics.configSuccess)

	if failureValue != 0 {
		t.Errorf("Expected config success metric to be 0, got %f", failureValue)
	}

	// Restore original value if it existed
	if originalValue != 0 {
		globalMetrics.configSuccess.Set(originalValue)
	}
}

func TestGlobalMetrics_ConfigSuccessTime(t *testing.T) {
	// Set success time
	globalMetrics.configSuccessTime.SetToCurrentTime()

	// Get the metric value
	metricValue := getMetricValue(globalMetrics.configSuccessTime)

	// Should be a reasonable Unix timestamp (not zero)
	if metricValue == 0 {
		t.Error("Config success time should not be zero")
	}

	// Should be recent (within last minute)
	now := time.Now().Unix()
	if int64(metricValue) < now-60 || int64(metricValue) > now {
		t.Errorf("Config success time %f should be recent (now: %d)", metricValue, now)
	}
}

func TestAdminMetrics_RequestCount(t *testing.T) {
	// Initialize admin metrics for testing
	initAdminMetrics()

	labels := prometheus.Labels{
		"handler": "test",
		"path":    "/config",
		"method":  "GET",
		"code":    "200",
	}

	// Get initial value
	initialValue := getCounterValue(adminMetrics.requestCount, labels)

	// Increment counter
	adminMetrics.requestCount.With(labels).Inc()

	// Verify increment
	newValue := getCounterValue(adminMetrics.requestCount, labels)
	if newValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, newValue)
	}
}

func TestAdminMetrics_RequestErrors(t *testing.T) {
	// Initialize admin metrics for testing
	initAdminMetrics()

	labels := prometheus.Labels{
		"handler": "test",
		"path":    "/test",
		"method":  "POST",
	}

	// Get initial value
	initialValue := getCounterValue(adminMetrics.requestErrors, labels)

	// Increment error counter
	adminMetrics.requestErrors.With(labels).Inc()

	// Verify increment
	newValue := getCounterValue(adminMetrics.requestErrors, labels)
	if newValue != initialValue+1 {
		t.Errorf("Expected error counter to increment by 1, got %f -> %f", initialValue, newValue)
	}
}

func TestMetrics_ConcurrentAccess(t *testing.T) {
	// Initialize admin metrics
	initAdminMetrics()

	const numGoroutines = 100
	const incrementsPerGoroutine = 10

	var wg sync.WaitGroup

	labels := prometheus.Labels{
		"handler": "concurrent",
		"path":    "/concurrent",
		"method":  "GET",
		"code":    "200",
	}

	initialCount := getCounterValue(adminMetrics.requestCount, labels)

	// Concurrent increments
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				adminMetrics.requestCount.With(labels).Inc()
			}
		}()
	}

	wg.Wait()

	// Verify final count
	finalCount := getCounterValue(adminMetrics.requestCount, labels)
	expectedIncrement := float64(numGoroutines * incrementsPerGoroutine)

	if finalCount-initialCount != expectedIncrement {
		t.Errorf("Expected counter to increase by %f, got %f",
			expectedIncrement, finalCount-initialCount)
	}
}

func TestMetrics_LabelValidation(t *testing.T) {
	// Test various label combinations
	tests := []struct {
		name   string
		labels prometheus.Labels
		metric string
	}{
		{
			name: "valid request count labels",
			labels: prometheus.Labels{
				"handler": "test",
				"path":    "/api/test",
				"method":  "GET",
				"code":    "200",
			},
			metric: "requestCount",
		},
		{
			name: "valid error labels",
			labels: prometheus.Labels{
				"handler": "test",
				"path":    "/api/error",
				"method":  "POST",
			},
			metric: "requestErrors",
		},
		{
			name: "empty path",
			labels: prometheus.Labels{
				"handler": "test",
				"path":    "",
				"method":  "GET",
				"code":    "404",
			},
			metric: "requestCount",
		},
		{
			name: "special characters in path",
			labels: prometheus.Labels{
				"handler": "test",
				"path":    "/api/test%20with%20spaces",
				"method":  "PUT",
				"code":    "201",
			},
			metric: "requestCount",
		},
	}

	initAdminMetrics()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// This should not panic or error
			switch test.metric {
			case "requestCount":
				adminMetrics.requestCount.With(test.labels).Inc()
			case "requestErrors":
				adminMetrics.requestErrors.With(test.labels).Inc()
			}
		})
	}
}

func TestMetrics_Initialization_Idempotent(t *testing.T) {
	// Test that initializing admin metrics multiple times is safe
	for i := 0; i < 5; i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Iteration %d: initAdminMetrics panicked: %v", i, r)
				}
			}()
			initAdminMetrics()
		}()
	}
}

func TestInstrumentHandlerCounter(t *testing.T) {
	// Create a test counter with the expected labels
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_counter",
			Help: "Test counter for instrumentation",
		},
		[]string{"code", "method"},
	)

	// Create instrumented handler
	testHandler := instrumentHandlerCounter(
		counter,
		&mockHTTPHandler{statusCode: 200},
	)

	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()

	// Get initial counter value
	initialValue := getCounterValue(counter, prometheus.Labels{"code": "200", "method": "GET"})

	// Serve request
	testHandler.ServeHTTP(rr, req)

	// Verify counter was incremented
	finalValue := getCounterValue(counter, prometheus.Labels{"code": "200", "method": "GET"})
	if finalValue != initialValue+1 {
		t.Errorf("Expected counter to increment by 1, got %f -> %f", initialValue, finalValue)
	}
}

func TestInstrumentHandlerCounter_ErrorStatus(t *testing.T) {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_error_counter",
			Help: "Test counter for error status",
		},
		[]string{"code", "method"},
	)

	// Test different status codes
	statusCodes := []int{200, 404, 500, 301, 401}

	for _, status := range statusCodes {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			handler := instrumentHandlerCounter(
				counter,
				&mockHTTPHandler{statusCode: status},
			)

			req := httptest.NewRequest("GET", "/test", nil)
			rr := httptest.NewRecorder()

			statusLabels := prometheus.Labels{"code": fmt.Sprintf("%d", status), "method": "GET"}
			initialValue := getCounterValue(counter, statusLabels)

			handler.ServeHTTP(rr, req)

			finalValue := getCounterValue(counter, statusLabels)
			if finalValue != initialValue+1 {
				t.Errorf("Status %d: Expected counter increment", status)
			}
		})
	}
}

// Helper functions
func getMetricValue(gauge prometheus.Gauge) float64 {
	metric := &dto.Metric{}
	gauge.Write(metric)
	return metric.GetGauge().GetValue()
}

func getCounterValue(counter *prometheus.CounterVec, labels prometheus.Labels) float64 {
	metric, err := counter.GetMetricWith(labels)
	if err != nil {
		return 0
	}

	pb := &dto.Metric{}
	metric.Write(pb)
	return pb.GetCounter().GetValue()
}

type mockHTTPHandler struct {
	statusCode int
}

func (m *mockHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(m.statusCode)
}

func TestMetrics_Memory_Usage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	// Initialize metrics
	initAdminMetrics()

	// Create many different label combinations
	const numLabels = 1000

	for i := 0; i < numLabels; i++ {
		labels := prometheus.Labels{
			"handler": fmt.Sprintf("handler_%d", i%10),
			"path":    fmt.Sprintf("/path_%d", i),
			"method":  []string{"GET", "POST", "PUT", "DELETE"}[i%4],
			"code":    []string{"200", "404", "500"}[i%3],
		}

		adminMetrics.requestCount.With(labels).Inc()

		// Also increment error counter occasionally
		if i%10 == 0 {
			errorLabels := prometheus.Labels{
				"handler": labels["handler"],
				"path":    labels["path"],
				"method":  labels["method"],
			}
			adminMetrics.requestErrors.With(errorLabels).Inc()
		}
	}

	// Test passes if we don't run out of memory or panic
}

func BenchmarkGlobalMetrics_ConfigSuccess(b *testing.B) {
	for i := 0; i < b.N; i++ {
		globalMetrics.configSuccess.Set(float64(i % 2))
	}
}

func BenchmarkGlobalMetrics_ConfigSuccessTime(b *testing.B) {
	for i := 0; i < b.N; i++ {
		globalMetrics.configSuccessTime.SetToCurrentTime()
	}
}

func BenchmarkAdminMetrics_RequestCount_WithLabels(b *testing.B) {
	initAdminMetrics()

	labels := prometheus.Labels{
		"handler": "benchmark",
		"path":    "/benchmark",
		"method":  "GET",
		"code":    "200",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		adminMetrics.requestCount.With(labels).Inc()
	}
}
