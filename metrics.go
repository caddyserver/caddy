package caddy

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// define and register the metrics used in this package.
func init() {
	prometheus.MustRegister(prometheus.NewBuildInfoCollector())

	const ns, sub = "caddy", "admin"

	adminMetrics.requestCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "http_requests_total",
		Help:      "Counter of requests made to the Admin API's HTTP endpoints.",
	}, []string{"handler", "path", "code", "method"})
	adminMetrics.requestErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "http_request_errors_total",
		Help:      "Number of requests resulting in middleware errors.",
	}, []string{"handler", "path", "method"})
}

// adminMetrics is a collection of metrics that can be tracked for the admin API.
var adminMetrics = struct {
	requestCount  *prometheus.CounterVec
	requestErrors *prometheus.CounterVec
}{}
