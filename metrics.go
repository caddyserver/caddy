package caddy

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/caddyserver/caddy/v2/internal/metrics"
)

// define and register the metrics used in this package.
func init() {
	const ns, sub = "caddy", "admin"
	adminMetrics.requestCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "http_requests_total",
		Help:      "Counter of requests made to the Admin API's HTTP endpoints.",
	}, []string{"handler", "path", "code", "method"})
	adminMetrics.requestErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "http_request_errors_total",
		Help:      "Number of requests resulting in middleware errors.",
	}, []string{"handler", "path", "method"})
	globalMetrics.configSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "caddy_config_last_reload_successful",
		Help: "Whether the last configuration reload attempt was successful.",
	})
	globalMetrics.configSuccessTime = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "caddy_config_last_reload_success_timestamp_seconds",
		Help: "Timestamp of the last successful configuration reload.",
	})
}

// adminMetrics is a collection of metrics that can be tracked for the admin API.
var adminMetrics = struct {
	requestCount  *prometheus.CounterVec
	requestErrors *prometheus.CounterVec
}{}

// globalMetrics is a collection of metrics that can be tracked for Caddy global state
var globalMetrics = struct {
	configSuccess     prometheus.Gauge
	configSuccessTime prometheus.Gauge
}{}

// Similar to promhttp.InstrumentHandlerCounter, but upper-cases method names
// instead of lower-casing them.
//
// Unlike promhttp.InstrumentHandlerCounter, this assumes a "code" and "method"
// label is present, and will panic otherwise.
func instrumentHandlerCounter(counter *prometheus.CounterVec, next http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := newDelegator(w)
		next.ServeHTTP(d, r)
		counter.With(prometheus.Labels{
			"code":   metrics.SanitizeCode(d.status),
			"method": metrics.SanitizeMethod(r.Method),
		}).Inc()
	})
}

func newDelegator(w http.ResponseWriter) *delegator {
	return &delegator{
		ResponseWriter: w,
	}
}

type delegator struct {
	http.ResponseWriter
	status int
}

func (d *delegator) WriteHeader(code int) {
	d.status = code
	d.ResponseWriter.WriteHeader(code)
}

// Unwrap returns the underlying ResponseWriter, necessary for
// http.ResponseController to work correctly.
func (d *delegator) Unwrap() http.ResponseWriter {
	return d.ResponseWriter
}
