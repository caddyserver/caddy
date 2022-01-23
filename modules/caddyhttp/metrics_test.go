package caddyhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	handlerErr := errors.New("oh noes")
	response := []byte("hello world!")
	h := HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if actual := testutil.ToFloat64(httpMetrics.requestInFlight); actual != 1.0 {
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

	ih := newMetricsInstrumentedHandler("bar", mh)

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	if actual := ih.ServeHTTP(w, r, h); actual != handlerErr {
		t.Errorf("Not same: expected %#v, but got %#v", handlerErr, actual)
	}
	if actual := testutil.ToFloat64(httpMetrics.requestInFlight); actual != 0.0 {
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
	ih = newMetricsInstrumentedHandler("empty", mh)
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
}

type middlewareHandlerFunc func(http.ResponseWriter, *http.Request, Handler) error

func (f middlewareHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request, h Handler) error {
	return f(w, r, h)
}

func TestSanitizeMethod(t *testing.T) {
	tests := []struct {
		method   string
		expected string
	}{
		{method: "get", expected: "GET"},
		{method: "POST", expected: "POST"},
		{method: "OPTIONS", expected: "OPTIONS"},
		{method: "connect", expected: "CONNECT"},
		{method: "trace", expected: "TRACE"},
		{method: "UNKNOWN", expected: "other"},
		{method: strings.Repeat("ohno", 9999), expected: "other"},
	}

	for _, d := range tests {
		actual := sanitizeMethod(d.method)
		if actual != d.expected {
			t.Errorf("Not same: expected %#v, but got %#v", d.expected, actual)
		}
	}
}
