package caddyhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestServerNameFromContext(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "UNKNOWN", serverNameFromContext(ctx))

	in := "foo"
	ctx = contextWithServerName(ctx, in)
	assert.Equal(t, in, serverNameFromContext(ctx))
}

func TestMetricsInstrumentedHandler(t *testing.T) {
	handlerErr := errors.New("oh noes")
	response := []byte("hello world!")
	h := HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		assert.Equal(t, 1.0, testutil.ToFloat64(httpMetrics.requestInFlight))
		if handlerErr == nil {
			w.Write(response)
		}
		return handlerErr
	})

	mh := middlewareHandlerFunc(func(w http.ResponseWriter, r *http.Request, h Handler) error {
		return h.ServeHTTP(w, r)
	})

	ih := newMetricsInstrumentedHandler("foo", "bar", mh)

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	assert.Same(t, handlerErr, ih.ServeHTTP(w, r, h))
	assert.Equal(t, 0.0, testutil.ToFloat64(httpMetrics.requestInFlight))

	handlerErr = nil
	assert.NoError(t, handlerErr, ih.ServeHTTP(w, r, h))
}

type middlewareHandlerFunc func(http.ResponseWriter, *http.Request, Handler) error

func (f middlewareHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request, h Handler) error {
	return f(w, r, h)
}
