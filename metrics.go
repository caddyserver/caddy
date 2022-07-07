package caddy

import (
	"net/http"

	internal "github.com/caddyserver/caddy/v2/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// define and register the metrics used in this package.
func init() {
	prometheus.MustRegister(collectors.NewBuildInfoCollector())

	const ns, sub = "caddy", "admin"

	adminMetrics.requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "http_requests_total",
		Help:      "Counter of requests made to the Admin API's HTTP endpoints.",
	}, []string{"handler", "path", "code", "method"})
	adminMetrics.errors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "http_request_errors_total",
		Help:      "Number of requests resulting in middleware errors.",
	}, []string{"handler", "path", "method"})
}

// adminMetrics is a collection of metrics that can be tracked for the admin API.
var adminMetrics = struct {
	requests *prometheus.CounterVec
	errors   *prometheus.CounterVec
}{}

// instrumentAdminHandler wraps the handler with total and errored-out request count
// in a manner similar to promhttp.InstrumentHandlerCounter. All errors are handled
// using the passed error handler.
func instrumentAdminHandler(pattern, handlerLabel string,
	h AdminHandler, errorHandler func(http.ResponseWriter, *http.Request, error),
) http.HandlerFunc {
	labels := prometheus.Labels{"path": pattern, "handler": handlerLabel}
	requests := adminMetrics.requests.MustCurryWith(labels)
	errors := adminMetrics.errors.MustCurryWith(labels)

	return func(w http.ResponseWriter, r *http.Request) {
		d := delegator{ResponseWriter: w}
		labels := prometheus.Labels{
			"method": internal.SanitizeMethod(r.Method),
		}

		if err := h.ServeHTTP(w, r); err != nil {
			errors.With(labels).Inc()
			errorHandler(w, r, err)
		}

		labels["code"] = internal.SanitizeCode(d.status)
		requests.With(labels).Inc()
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
