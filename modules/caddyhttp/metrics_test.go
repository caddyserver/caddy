package caddyhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus/testutil"
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
		PerHost:     true,
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

type middlewareHandlerFunc func(http.ResponseWriter, *http.Request, Handler) error

func (f middlewareHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request, h Handler) error {
	return f(w, r, h)
}
