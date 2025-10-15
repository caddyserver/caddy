package caddyhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/caddyserver/caddy/v2"
)

func TestServerNameFromContext(t *testing.T) {
	ctx := context.Background()
	expected := "UNKNOWN"
	if actual := serverNameFromContext(ctx); actual != expected {
		t.Errorf("Not equal: expected %q, but got %q", expected, actual)
	}

	in := "foo"
	ctx = context.WithValue(ctx, ServerCtxKey, &Server{name: in})
	if actual := serverNameFromContext(ctx); actual != in {
		t.Errorf("Not equal: expected %q, but got %q", in, actual)
	}
}

func TestMetricsInstrumentedHandler(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	metrics := &Metrics{
		init:        sync.Once{},
		httpMetrics: &httpMetrics{},
	}
	handlerErr := errors.New("oh noes")
	response := []byte("hello world!")
	h := HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if actual := testutil.ToFloat64(metrics.httpMetrics.requestInFlight); actual != 1.0 {
			t.Errorf("Not same: expected %#v, but got %#v", 1.0, actual)
		}
		if handlerErr == nil {
			w.Write(response)
		}
		return handlerErr
	})

	mh := middlewareHandlerFunc(func(w http.ResponseWriter, r *http.Request, h Handler) error {
		return h.ServeHTTP(w, r)
	})

	ih := newMetricsInstrumentedHandler(ctx, "bar", mh, metrics)

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	if actual := ih.ServeHTTP(w, r, h); actual != handlerErr {
		t.Errorf("Not same: expected %#v, but got %#v", handlerErr, actual)
	}
	if actual := testutil.ToFloat64(metrics.httpMetrics.requestInFlight); actual != 0.0 {
		t.Errorf("Not same: expected %#v, but got %#v", 0.0, actual)
	}

	handlerErr = nil
	if err := ih.ServeHTTP(w, r, h); err != nil {
		t.Errorf("Received unexpected error: %v", err)
	}

	// an empty handler - no errors, no header written
	mh = middlewareHandlerFunc(func(w http.ResponseWriter, r *http.Request, h Handler) error {
		return nil
	})
	ih = newMetricsInstrumentedHandler(ctx, "empty", mh, metrics)
	r = httptest.NewRequest("GET", "/", nil)
	w = httptest.NewRecorder()

	if err := ih.ServeHTTP(w, r, h); err != nil {
		t.Errorf("Received unexpected error: %v", err)
	}
	if actual := w.Result().StatusCode; actual != 200 {
		t.Errorf("Not same: expected status code %#v, but got %#v", 200, actual)
	}
	if actual := w.Result().Header; len(actual) != 0 {
		t.Errorf("Not empty: expected headers to be empty, but got %#v", actual)
	}

	// handler returning an error with an HTTP status
	mh = middlewareHandlerFunc(func(w http.ResponseWriter, r *http.Request, h Handler) error {
		return Error(http.StatusTooManyRequests, nil)
	})

	ih = newMetricsInstrumentedHandler(ctx, "foo", mh, metrics)

	r = httptest.NewRequest("GET", "/", nil)
	w = httptest.NewRecorder()

	if err := ih.ServeHTTP(w, r, nil); err == nil {
		t.Errorf("expected error to be propagated")
	}

	expected := `
	# HELP caddy_http_request_duration_seconds Histogram of round-trip request durations.
	# TYPE caddy_http_request_duration_seconds histogram
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="0.005"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="0.01"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="0.025"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="0.05"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="0.1"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="0.25"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="0.5"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="1"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="2.5"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="5"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="10"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="+Inf"} 1
	caddy_http_request_duration_seconds_count{code="429",handler="foo",method="GET",server="UNKNOWN"} 1
	# HELP caddy_http_request_size_bytes Total size of the request. Includes body
	# TYPE caddy_http_request_size_bytes histogram
	caddy_http_request_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="256"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="1024"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="4096"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="16384"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="65536"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="262144"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="+Inf"} 1
    caddy_http_request_size_bytes_sum{code="200",handler="bar",method="GET",server="UNKNOWN"} 23
    caddy_http_request_size_bytes_count{code="200",handler="bar",method="GET",server="UNKNOWN"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="256"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="1024"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="4096"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="16384"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="65536"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="262144"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="+Inf"} 1
    caddy_http_request_size_bytes_sum{code="200",handler="empty",method="GET",server="UNKNOWN"} 23
    caddy_http_request_size_bytes_count{code="200",handler="empty",method="GET",server="UNKNOWN"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="256"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="1024"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="4096"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="16384"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="65536"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="262144"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="+Inf"} 1
	caddy_http_request_size_bytes_sum{code="429",handler="foo",method="GET",server="UNKNOWN"} 23
	caddy_http_request_size_bytes_count{code="429",handler="foo",method="GET",server="UNKNOWN"} 1
	# HELP caddy_http_response_size_bytes Size of the returned response.
	# TYPE caddy_http_response_size_bytes histogram
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="256"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="1024"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="4096"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="16384"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="65536"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="262144"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",method="GET",server="UNKNOWN",le="+Inf"} 1
	caddy_http_response_size_bytes_sum{code="200",handler="bar",method="GET",server="UNKNOWN"} 12
	caddy_http_response_size_bytes_count{code="200",handler="bar",method="GET",server="UNKNOWN"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="256"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="1024"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="4096"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="16384"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="65536"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="262144"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",method="GET",server="UNKNOWN",le="+Inf"} 1
	caddy_http_response_size_bytes_sum{code="200",handler="empty",method="GET",server="UNKNOWN"} 0
	caddy_http_response_size_bytes_count{code="200",handler="empty",method="GET",server="UNKNOWN"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="256"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="1024"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="4096"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="16384"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="65536"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="262144"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",method="GET",server="UNKNOWN",le="+Inf"} 1
	caddy_http_response_size_bytes_sum{code="429",handler="foo",method="GET",server="UNKNOWN"} 0
	caddy_http_response_size_bytes_count{code="429",handler="foo",method="GET",server="UNKNOWN"} 1
	# HELP caddy_http_request_errors_total Number of requests resulting in middleware errors.
	# TYPE caddy_http_request_errors_total counter
	caddy_http_request_errors_total{handler="bar",server="UNKNOWN"} 1
	caddy_http_request_errors_total{handler="foo",server="UNKNOWN"} 1
	`
	if err := testutil.GatherAndCompare(ctx.GetMetricsRegistry(), strings.NewReader(expected),
		"caddy_http_request_size_bytes",
		"caddy_http_response_size_bytes",
		// caddy_http_request_duration_seconds_sum will vary based on how long the test took to run,
		// so we check just the _bucket and _count metrics
		"caddy_http_request_duration_seconds_bucket",
		"caddy_http_request_duration_seconds_count",
		"caddy_http_request_errors_total",
	); err != nil {
		t.Errorf("received unexpected error: %s", err)
	}
}

func TestMetricsInstrumentedHandlerPerHost(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})
	metrics := &Metrics{
		PerHost:            true,
		AllowCatchAllHosts: true, // Allow all hosts for testing
		init:               sync.Once{},
		httpMetrics:        &httpMetrics{},
		allowedHosts:       make(map[string]struct{}),
	}
	handlerErr := errors.New("oh noes")
	response := []byte("hello world!")
	h := HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if actual := testutil.ToFloat64(metrics.httpMetrics.requestInFlight); actual != 1.0 {
			t.Errorf("Not same: expected %#v, but got %#v", 1.0, actual)
		}
		if handlerErr == nil {
			w.Write(response)
		}
		return handlerErr
	})

	mh := middlewareHandlerFunc(func(w http.ResponseWriter, r *http.Request, h Handler) error {
		return h.ServeHTTP(w, r)
	})

	ih := newMetricsInstrumentedHandler(ctx, "bar", mh, metrics)

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	if actual := ih.ServeHTTP(w, r, h); actual != handlerErr {
		t.Errorf("Not same: expected %#v, but got %#v", handlerErr, actual)
	}
	if actual := testutil.ToFloat64(metrics.httpMetrics.requestInFlight); actual != 0.0 {
		t.Errorf("Not same: expected %#v, but got %#v", 0.0, actual)
	}

	handlerErr = nil
	if err := ih.ServeHTTP(w, r, h); err != nil {
		t.Errorf("Received unexpected error: %v", err)
	}

	// an empty handler - no errors, no header written
	mh = middlewareHandlerFunc(func(w http.ResponseWriter, r *http.Request, h Handler) error {
		return nil
	})
	ih = newMetricsInstrumentedHandler(ctx, "empty", mh, metrics)
	r = httptest.NewRequest("GET", "/", nil)
	w = httptest.NewRecorder()

	if err := ih.ServeHTTP(w, r, h); err != nil {
		t.Errorf("Received unexpected error: %v", err)
	}
	if actual := w.Result().StatusCode; actual != 200 {
		t.Errorf("Not same: expected status code %#v, but got %#v", 200, actual)
	}
	if actual := w.Result().Header; len(actual) != 0 {
		t.Errorf("Not empty: expected headers to be empty, but got %#v", actual)
	}

	// handler returning an error with an HTTP status
	mh = middlewareHandlerFunc(func(w http.ResponseWriter, r *http.Request, h Handler) error {
		return Error(http.StatusTooManyRequests, nil)
	})

	ih = newMetricsInstrumentedHandler(ctx, "foo", mh, metrics)

	r = httptest.NewRequest("GET", "/", nil)
	w = httptest.NewRecorder()

	if err := ih.ServeHTTP(w, r, nil); err == nil {
		t.Errorf("expected error to be propagated")
	}

	expected := `
	# HELP caddy_http_request_duration_seconds Histogram of round-trip request durations.
	# TYPE caddy_http_request_duration_seconds histogram
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="0.005"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="0.01"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="0.025"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="0.05"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="0.1"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="0.25"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="0.5"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="1"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="2.5"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="5"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="10"} 1
	caddy_http_request_duration_seconds_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="+Inf"} 1
	caddy_http_request_duration_seconds_count{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN"} 1
	# HELP caddy_http_request_size_bytes Total size of the request. Includes body
	# TYPE caddy_http_request_size_bytes histogram
	caddy_http_request_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="256"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="1024"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="4096"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="16384"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="65536"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="262144"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="+Inf"} 1
    caddy_http_request_size_bytes_sum{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN"} 23
    caddy_http_request_size_bytes_count{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="256"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="1024"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="4096"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="16384"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="65536"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="262144"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
    caddy_http_request_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="+Inf"} 1
    caddy_http_request_size_bytes_sum{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN"} 23
    caddy_http_request_size_bytes_count{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="256"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="1024"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="4096"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="16384"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="65536"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="262144"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
	caddy_http_request_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="+Inf"} 1
	caddy_http_request_size_bytes_sum{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN"} 23
	caddy_http_request_size_bytes_count{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN"} 1
	# HELP caddy_http_response_size_bytes Size of the returned response.
	# TYPE caddy_http_response_size_bytes histogram
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="256"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="1024"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="4096"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="16384"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="65536"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="262144"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN",le="+Inf"} 1
	caddy_http_response_size_bytes_sum{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN"} 12
	caddy_http_response_size_bytes_count{code="200",handler="bar",host="example.com",method="GET",server="UNKNOWN"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="256"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="1024"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="4096"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="16384"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="65536"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="262144"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
	caddy_http_response_size_bytes_bucket{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN",le="+Inf"} 1
	caddy_http_response_size_bytes_sum{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN"} 0
	caddy_http_response_size_bytes_count{code="200",handler="empty",host="example.com",method="GET",server="UNKNOWN"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="256"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="1024"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="4096"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="16384"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="65536"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="262144"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="1.048576e+06"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="4.194304e+06"} 1
	caddy_http_response_size_bytes_bucket{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN",le="+Inf"} 1
	caddy_http_response_size_bytes_sum{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN"} 0
	caddy_http_response_size_bytes_count{code="429",handler="foo",host="example.com",method="GET",server="UNKNOWN"} 1
	# HELP caddy_http_request_errors_total Number of requests resulting in middleware errors.
	# TYPE caddy_http_request_errors_total counter
	caddy_http_request_errors_total{handler="bar",host="example.com",server="UNKNOWN"} 1
	caddy_http_request_errors_total{handler="foo",host="example.com",server="UNKNOWN"} 1
	`
	if err := testutil.GatherAndCompare(ctx.GetMetricsRegistry(), strings.NewReader(expected),
		"caddy_http_request_size_bytes",
		"caddy_http_response_size_bytes",
		// caddy_http_request_duration_seconds_sum will vary based on how long the test took to run,
		// so we check just the _bucket and _count metrics
		"caddy_http_request_duration_seconds_bucket",
		"caddy_http_request_duration_seconds_count",
		"caddy_http_request_errors_total",
	); err != nil {
		t.Errorf("received unexpected error: %s", err)
	}
}

func TestMetricsCardinalityProtection(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})

	// Test 1: Without AllowCatchAllHosts, arbitrary hosts should be mapped to "_other"
	metrics := &Metrics{
		PerHost:            true,
		AllowCatchAllHosts: false, // Default - should map unknown hosts to "_other"
		init:               sync.Once{},
		httpMetrics:        &httpMetrics{},
		allowedHosts:       make(map[string]struct{}),
	}

	// Add one allowed host
	metrics.allowedHosts["allowed.com"] = struct{}{}

	mh := middlewareHandlerFunc(func(w http.ResponseWriter, r *http.Request, h Handler) error {
		w.Write([]byte("hello"))
		return nil
	})

	ih := newMetricsInstrumentedHandler(ctx, "test", mh, metrics)

	// Test request to allowed host
	r1 := httptest.NewRequest("GET", "http://allowed.com/", nil)
	r1.Host = "allowed.com"
	w1 := httptest.NewRecorder()
	ih.ServeHTTP(w1, r1, HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil }))

	// Test request to unknown host (should be mapped to "_other")
	r2 := httptest.NewRequest("GET", "http://attacker.com/", nil)
	r2.Host = "attacker.com"
	w2 := httptest.NewRecorder()
	ih.ServeHTTP(w2, r2, HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil }))

	// Test request to another unknown host (should also be mapped to "_other")
	r3 := httptest.NewRequest("GET", "http://evil.com/", nil)
	r3.Host = "evil.com"
	w3 := httptest.NewRecorder()
	ih.ServeHTTP(w3, r3, HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil }))

	// Check that metrics contain:
	// - One entry for "allowed.com"
	// - One entry for "_other" (aggregating attacker.com and evil.com)
	expected := `
	# HELP caddy_http_requests_total Counter of HTTP(S) requests made.
	# TYPE caddy_http_requests_total counter
	caddy_http_requests_total{handler="test",host="_other",server="UNKNOWN"} 2
	caddy_http_requests_total{handler="test",host="allowed.com",server="UNKNOWN"} 1
	`

	if err := testutil.GatherAndCompare(ctx.GetMetricsRegistry(), strings.NewReader(expected),
		"caddy_http_requests_total",
	); err != nil {
		t.Errorf("Cardinality protection test failed: %s", err)
	}
}

func TestMetricsHTTPSCatchAll(t *testing.T) {
	ctx, _ := caddy.NewContext(caddy.Context{Context: context.Background()})

	// Test that HTTPS requests allow catch-all even when AllowCatchAllHosts is false
	metrics := &Metrics{
		PerHost:            true,
		AllowCatchAllHosts: false,
		hasHTTPSServer:     true, // Simulate having HTTPS servers
		init:               sync.Once{},
		httpMetrics:        &httpMetrics{},
		allowedHosts:       make(map[string]struct{}), // Empty - no explicitly allowed hosts
	}

	mh := middlewareHandlerFunc(func(w http.ResponseWriter, r *http.Request, h Handler) error {
		w.Write([]byte("hello"))
		return nil
	})

	ih := newMetricsInstrumentedHandler(ctx, "test", mh, metrics)

	// Test HTTPS request (should be allowed even though not in allowedHosts)
	r1 := httptest.NewRequest("GET", "https://unknown.com/", nil)
	r1.Host = "unknown.com"
	r1.TLS = &tls.ConnectionState{} // Mark as TLS/HTTPS
	w1 := httptest.NewRecorder()
	ih.ServeHTTP(w1, r1, HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil }))

	// Test HTTP request (should be mapped to "_other")
	r2 := httptest.NewRequest("GET", "http://unknown.com/", nil)
	r2.Host = "unknown.com"
	// No TLS field = HTTP request
	w2 := httptest.NewRecorder()
	ih.ServeHTTP(w2, r2, HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil }))

	// Check that HTTPS request gets real host, HTTP gets "_other"
	expected := `
	# HELP caddy_http_requests_total Counter of HTTP(S) requests made.
	# TYPE caddy_http_requests_total counter
	caddy_http_requests_total{handler="test",host="_other",server="UNKNOWN"} 1
	caddy_http_requests_total{handler="test",host="unknown.com",server="UNKNOWN"} 1
	`

	if err := testutil.GatherAndCompare(ctx.GetMetricsRegistry(), strings.NewReader(expected),
		"caddy_http_requests_total",
	); err != nil {
		t.Errorf("HTTPS catch-all test failed: %s", err)
	}
}

type middlewareHandlerFunc func(http.ResponseWriter, *http.Request, Handler) error

func (f middlewareHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request, h Handler) error {
	return f(w, r, h)
}
