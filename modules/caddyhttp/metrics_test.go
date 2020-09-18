package caddyhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
	ctx = contextWithServerName(ctx, in)
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
		t.Errorf("Received unexpected error: %w", err)
	}
}

type middlewareHandlerFunc func(http.ResponseWriter, *http.Request, Handler) error

func (f middlewareHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request, h Handler) error {
	return f(w, r, h)
}
