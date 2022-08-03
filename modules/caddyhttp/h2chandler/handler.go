package h2chandler

import (
	"context"
	"math/rand"
	"net/http"
	"net/textproto"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
)

// Handler is a Handler which counts possible h2c upgrade requests
type Handler struct {
	cnt     uint64
	Handler http.Handler
}

// NewHandler returns an http.Handler that tracks possible h2c upgrade requests.
func NewHandler(h http.Handler) *Handler {
	return &Handler{
		Handler: h,
	}
}

const shutdownPollIntervalMax = 500 * time.Millisecond

// Shutdown mirrors stdlib http.Server Shutdown behavior, because h2 connections are always marked active, there is no closing to be done.
func (h *Handler) Shutdown(ctx context.Context) error {
	pollIntervalBase := time.Millisecond
	nextPollInterval := func() time.Duration {
		// Add 10% jitter.
		interval := pollIntervalBase + time.Duration(rand.Intn(int(pollIntervalBase/10)))
		// Double and clamp for next time.
		pollIntervalBase *= 2
		if pollIntervalBase > shutdownPollIntervalMax {
			pollIntervalBase = shutdownPollIntervalMax
		}
		return interval
	}

	timer := time.NewTimer(nextPollInterval())
	defer timer.Stop()
	for {
		if atomic.LoadUint64(&h.cnt) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			timer.Reset(nextPollInterval())
		}
	}
}

// isH2cUpgrade check whether request is h2c upgrade request, copied from golang.org/x/net/http2/h2c
func isH2cUpgrade(r *http.Request) bool {
	if r.Method == "PRI" && len(r.Header) == 0 && r.URL.Path == "*" && r.Proto == "HTTP/2.0" {
		return true
	}

	if httpguts.HeaderValuesContainsToken(r.Header[textproto.CanonicalMIMEHeaderKey("Upgrade")], "h2c") &&
		httpguts.HeaderValuesContainsToken(r.Header[textproto.CanonicalMIMEHeaderKey("Connection")], "HTTP2-Settings") {
		return true
	}

	return false
}

// ServeHTTP records underlying connections that are likely to be h2c.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isH2cUpgrade(r) {
		atomic.AddUint64(&h.cnt, 1)
		defer atomic.AddUint64(&h.cnt, ^uint64(0))
	}
	h.Handler.ServeHTTP(w, r)
	return
}
