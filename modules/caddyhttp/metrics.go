package caddyhttp

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var httpMetrics = struct {
	init             sync.Once
	requestInFlight  *prometheus.GaugeVec
	requestCount     *prometheus.CounterVec
	requestErrors    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	requestSize      *prometheus.HistogramVec
	responseSize     *prometheus.HistogramVec
	responseDuration *prometheus.HistogramVec
}{
	init: sync.Once{},
}

func initHTTPMetrics() {
	ns := "caddy"
	sub := "http"

	basicLabels := []string{"server", "handler"}
	httpMetrics.requestInFlight = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "requests_in_flight",
		Help:      "Number of requests currently handled by this server.",
	}, basicLabels)
	httpMetrics.requestErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "request_errors_total",
		Help:      "Number of requests resulting in middleware errors.",
	}, basicLabels)
	httpMetrics.requestCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "requests_total",
		Help:      "Counter of HTTP(S) requests made.",
	}, basicLabels)

	// TODO: allow these to be customized in the config
	durationBuckets := prometheus.DefBuckets
	sizeBuckets := prometheus.ExponentialBuckets(256, 4, 8)

	httpLabels := []string{"server", "handler", "code", "method"}
	httpMetrics.requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "request_duration_seconds",
		Help:      "Histogram of round-trip request durations.",
		Buckets:   durationBuckets,
	}, httpLabels)
	httpMetrics.requestSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "request_size_bytes",
		Help:      "Total size of the request. Includes body",
		Buckets:   sizeBuckets,
	}, httpLabels)
	httpMetrics.responseSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "response_size_bytes",
		Help:      "Size of the returned response.",
		Buckets:   sizeBuckets,
	}, httpLabels)
	httpMetrics.responseDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "response_duration_seconds",
		Help:      "Histogram of times to first byte in response bodies.",
		Buckets:   durationBuckets,
	}, httpLabels)
}

type ctxKeyServerName struct{}

// serverNameFromContext extracts the current server name from the context.
// Returns "UNKNOWN" if none is available (should probably never happen?)
func serverNameFromContext(ctx context.Context) string {
	srvName, ok := ctx.Value(ctxKeyServerName{}).(string)
	if !ok {
		return "UNKNOWN"
	}
	return srvName
}

func contextWithServerName(ctx context.Context, serverName string) context.Context {
	return context.WithValue(ctx, ctxKeyServerName{}, serverName)
}

type metricsInstrumentedHandler struct {
	labels       prometheus.Labels
	statusLabels prometheus.Labels
	mh           MiddlewareHandler
}

func newMetricsInstrumentedHandler(server, handler string, mh MiddlewareHandler) *metricsInstrumentedHandler {
	httpMetrics.init.Do(func() {
		initHTTPMetrics()
	})

	labels := prometheus.Labels{"server": server, "handler": handler}
	statusLabels := prometheus.Labels{"server": server, "handler": handler, "code": "", "method": ""}
	return &metricsInstrumentedHandler{labels, statusLabels, mh}
}

func (h *metricsInstrumentedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
	inFlight := httpMetrics.requestInFlight.With(h.labels)
	inFlight.Inc()
	defer inFlight.Dec()

	statusLabels := prometheus.Labels{"method": r.Method}
	for k, v := range h.labels {
		statusLabels[k] = v
	}

	start := time.Now()

	// This is a _bit_ of a hack - it depends on the ShouldBufferFunc always
	// being called when the headers are written.
	// Effectively the same behaviour as promhttp.InstrumentHandlerTimeToWriteHeader.
	writeHeaderRecorder := ShouldBufferFunc(func(status int, header http.Header) bool {
		statusLabels["code"] = sanitizeCode(status)
		ttfb := time.Since(start).Seconds()
		observeWithExemplar(statusLabels, httpMetrics.responseDuration, ttfb)
		return false
	})
	wrec := NewResponseRecorder(w, nil, writeHeaderRecorder)
	err := h.mh.ServeHTTP(wrec, r, next)
	dur := time.Since(start).Seconds()
	httpMetrics.requestCount.With(h.labels).Inc()
	if err != nil {
		httpMetrics.requestErrors.With(h.labels).Inc()
		return err
	}

	observeWithExemplar(statusLabels, httpMetrics.requestDuration, dur)
	observeWithExemplar(statusLabels, httpMetrics.requestSize, float64(computeApproximateRequestSize(r)))
	httpMetrics.responseSize.With(statusLabels).Observe(float64(wrec.Size()))

	return nil
}

func observeWithExemplar(l prometheus.Labels, o *prometheus.HistogramVec, value float64) {
	obs := o.With(l)
	if oe, ok := obs.(prometheus.ExemplarObserver); ok {
		oe.ObserveWithExemplar(value, l)
		return
	}
	// _should_ be a noop, but here just in case...
	obs.Observe(value)
}

func sanitizeCode(code int) string {
	if code == 0 {
		return "200"
	}
	return strconv.Itoa(code)

}

// taken from https://github.com/prometheus/client_golang/blob/6007b2b5cae01203111de55f753e76d8dac1f529/prometheus/promhttp/instrument_server.go#L298
func computeApproximateRequestSize(r *http.Request) int {
	s := 0
	if r.URL != nil {
		s += len(r.URL.String())
	}

	s += len(r.Method)
	s += len(r.Proto)
	for name, values := range r.Header {
		s += len(name)
		for _, value := range values {
			s += len(value)
		}
	}
	s += len(r.Host)

	// N.B. r.Form and r.MultipartForm are assumed to be included in r.URL.

	if r.ContentLength != -1 {
		s += int(r.ContentLength)
	}
	return s
}
