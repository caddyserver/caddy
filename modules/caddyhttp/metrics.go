package caddyhttp

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/internal/metrics"
)

// Metrics configures metrics observations.
// EXPERIMENTAL and subject to change or removal.
//
// Example configuration:
//
//	{
//		"apps": {
//			"http": {
//				"metrics": {
//					"per_host": true,
//					"allow_catch_all_hosts": false
//				},
//				"servers": {
//					"srv0": {
//						"routes": [{
//							"match": [{"host": ["example.com", "www.example.com"]}],
//							"handle": [{"handler": "static_response", "body": "Hello"}]
//						}]
//					}
//				}
//			}
//		}
//	}
//
// In this configuration:
// - Requests to example.com and www.example.com get individual host labels
// - All other hosts (e.g., attacker.com) are aggregated under "_other" label
// - This prevents unlimited cardinality from arbitrary Host headers
type Metrics struct {
	// Enable per-host metrics. Enabling this option may
	// incur high-memory consumption, depending on the number of hosts
	// managed by Caddy.
	//
	// CARDINALITY PROTECTION: To prevent unbounded cardinality attacks,
	// only explicitly configured hosts (via host matchers) are allowed
	// by default. Other hosts are aggregated under the "_other" label.
	// See AllowCatchAllHosts to change this behavior.
	PerHost bool `json:"per_host,omitempty"`

	// Allow metrics for catch-all hosts (hosts without explicit configuration).
	// When false (default), only hosts explicitly configured via host matchers
	// will get individual metrics labels. All other hosts will be aggregated
	// under the "_other" label to prevent cardinality explosion.
	//
	// This is automatically enabled for HTTPS servers (since certificates provide
	// some protection against unbounded cardinality), but disabled for HTTP servers
	// by default to prevent cardinality attacks from arbitrary Host headers.
	//
	// Set to true to allow all hosts to get individual metrics (NOT RECOMMENDED
	// for production environments exposed to the internet).
	AllowCatchAllHosts bool `json:"allow_catch_all_hosts,omitempty"`

	init           sync.Once
	httpMetrics    *httpMetrics
	allowedHosts   map[string]struct{}
	hasHTTPSServer bool
}

type httpMetrics struct {
	requestInFlight  *prometheus.GaugeVec
	requestCount     *prometheus.CounterVec
	requestErrors    *prometheus.CounterVec
	requestDuration  *prometheus.HistogramVec
	requestSize      *prometheus.HistogramVec
	responseSize     *prometheus.HistogramVec
	responseDuration *prometheus.HistogramVec
}

func initHTTPMetrics(ctx caddy.Context, metrics *Metrics) {
	const ns, sub = "caddy", "http"
	registry := ctx.GetMetricsRegistry()
	basicLabels := []string{"server", "handler"}
	if metrics.PerHost {
		basicLabels = append(basicLabels, "host")
	}
	metrics.httpMetrics.requestInFlight = promauto.With(registry).NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "requests_in_flight",
		Help:      "Number of requests currently handled by this server.",
	}, basicLabels)
	metrics.httpMetrics.requestErrors = promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "request_errors_total",
		Help:      "Number of requests resulting in middleware errors.",
	}, basicLabels)
	metrics.httpMetrics.requestCount = promauto.With(registry).NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "requests_total",
		Help:      "Counter of HTTP(S) requests made.",
	}, basicLabels)

	// TODO: allow these to be customized in the config
	durationBuckets := prometheus.DefBuckets
	sizeBuckets := prometheus.ExponentialBuckets(256, 4, 8)

	httpLabels := []string{"server", "handler", "code", "method"}
	if metrics.PerHost {
		httpLabels = append(httpLabels, "host")
	}
	metrics.httpMetrics.requestDuration = promauto.With(registry).NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "request_duration_seconds",
		Help:      "Histogram of round-trip request durations.",
		Buckets:   durationBuckets,
	}, httpLabels)
	metrics.httpMetrics.requestSize = promauto.With(registry).NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "request_size_bytes",
		Help:      "Total size of the request. Includes body",
		Buckets:   sizeBuckets,
	}, httpLabels)
	metrics.httpMetrics.responseSize = promauto.With(registry).NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "response_size_bytes",
		Help:      "Size of the returned response.",
		Buckets:   sizeBuckets,
	}, httpLabels)
	metrics.httpMetrics.responseDuration = promauto.With(registry).NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "response_duration_seconds",
		Help:      "Histogram of times to first byte in response bodies.",
		Buckets:   durationBuckets,
	}, httpLabels)
}

// scanConfigForHosts scans the HTTP app configuration to build a set of allowed hosts
// for metrics collection, similar to how auto-HTTPS scans for domain names.
func (m *Metrics) scanConfigForHosts(app *App) {
	if !m.PerHost {
		return
	}

	m.allowedHosts = make(map[string]struct{})
	m.hasHTTPSServer = false

	for _, srv := range app.Servers {
		// Check if this server has TLS enabled
		serverHasTLS := len(srv.TLSConnPolicies) > 0
		if serverHasTLS {
			m.hasHTTPSServer = true
		}

		// Collect hosts from route matchers
		for _, route := range srv.Routes {
			for _, matcherSet := range route.MatcherSets {
				for _, matcher := range matcherSet {
					if hm, ok := matcher.(*MatchHost); ok {
						for _, host := range *hm {
							// Only allow non-fuzzy hosts to prevent unbounded cardinality
							if !hm.fuzzy(host) {
								m.allowedHosts[strings.ToLower(host)] = struct{}{}
							}
						}
					}
				}
			}
		}
	}
}

// shouldAllowHostMetrics determines if metrics should be collected for the given host.
// This implements the cardinality protection by only allowing metrics for:
// 1. Explicitly configured hosts
// 2. Catch-all requests on HTTPS servers (if AllowCatchAllHosts is true or auto-enabled)
// 3. Catch-all requests on HTTP servers only if explicitly allowed
func (m *Metrics) shouldAllowHostMetrics(host string, isHTTPS bool) bool {
	if !m.PerHost {
		return true // host won't be used in labels anyway
	}

	normalizedHost := strings.ToLower(host)

	// Always allow explicitly configured hosts
	if _, exists := m.allowedHosts[normalizedHost]; exists {
		return true
	}

	// For catch-all requests (not in allowed hosts)
	allowCatchAll := m.AllowCatchAllHosts || (isHTTPS && m.hasHTTPSServer)
	return allowCatchAll
}

// serverNameFromContext extracts the current server name from the context.
// Returns "UNKNOWN" if none is available (should probably never happen).
func serverNameFromContext(ctx context.Context) string {
	srv, ok := ctx.Value(ServerCtxKey).(*Server)
	if !ok || srv == nil || srv.name == "" {
		return "UNKNOWN"
	}
	return srv.name
}

type metricsInstrumentedHandler struct {
	handler string
	mh      MiddlewareHandler
	metrics *Metrics
}

func newMetricsInstrumentedHandler(ctx caddy.Context, handler string, mh MiddlewareHandler, metrics *Metrics) *metricsInstrumentedHandler {
	metrics.init.Do(func() {
		initHTTPMetrics(ctx, metrics)
	})

	return &metricsInstrumentedHandler{handler, mh, metrics}
}

func (h *metricsInstrumentedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next Handler) error {
	server := serverNameFromContext(r.Context())
	labels := prometheus.Labels{"server": server, "handler": h.handler}
	method := metrics.SanitizeMethod(r.Method)
	// the "code" value is set later, but initialized here to eliminate the possibility
	// of a panic
	statusLabels := prometheus.Labels{"server": server, "handler": h.handler, "method": method, "code": ""}

	// Determine if this is an HTTPS request
	isHTTPS := r.TLS != nil

	if h.metrics.PerHost {
		// Apply cardinality protection for host metrics
		if h.metrics.shouldAllowHostMetrics(r.Host, isHTTPS) {
			labels["host"] = strings.ToLower(r.Host)
			statusLabels["host"] = strings.ToLower(r.Host)
		} else {
			// Use a catch-all label for unallowed hosts to prevent cardinality explosion
			labels["host"] = "_other"
			statusLabels["host"] = "_other"
		}
	}

	inFlight := h.metrics.httpMetrics.requestInFlight.With(labels)
	inFlight.Inc()
	defer inFlight.Dec()

	start := time.Now()

	// This is a _bit_ of a hack - it depends on the ShouldBufferFunc always
	// being called when the headers are written.
	// Effectively the same behaviour as promhttp.InstrumentHandlerTimeToWriteHeader.
	writeHeaderRecorder := ShouldBufferFunc(func(status int, header http.Header) bool {
		statusLabels["code"] = metrics.SanitizeCode(status)
		ttfb := time.Since(start).Seconds()
		h.metrics.httpMetrics.responseDuration.With(statusLabels).Observe(ttfb)
		return false
	})
	wrec := NewResponseRecorder(w, nil, writeHeaderRecorder)
	err := h.mh.ServeHTTP(wrec, r, next)
	dur := time.Since(start).Seconds()
	h.metrics.httpMetrics.requestCount.With(labels).Inc()

	observeRequest := func(status int) {
		// If the code hasn't been set yet, and we didn't encounter an error, we're
		// probably falling through with an empty handler.
		if statusLabels["code"] == "" {
			// we still sanitize it, even though it's likely to be 0. A 200 is
			// returned on fallthrough so we want to reflect that.
			statusLabels["code"] = metrics.SanitizeCode(status)
		}

		h.metrics.httpMetrics.requestDuration.With(statusLabels).Observe(dur)
		h.metrics.httpMetrics.requestSize.With(statusLabels).Observe(float64(computeApproximateRequestSize(r)))
		h.metrics.httpMetrics.responseSize.With(statusLabels).Observe(float64(wrec.Size()))
	}

	if err != nil {
		var handlerErr HandlerError
		if errors.As(err, &handlerErr) {
			observeRequest(handlerErr.StatusCode)
		}

		h.metrics.httpMetrics.requestErrors.With(labels).Inc()

		return err
	}

	observeRequest(wrec.Status())

	return nil
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
