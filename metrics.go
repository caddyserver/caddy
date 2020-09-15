package caddy

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// define and register the metrics used in this package.
func init() {
	initAdminMetrics()
	prometheus.MustRegister(prometheus.NewBuildInfoCollector())

}

// adminMetrics is a collection of metrics that can be tracked for the admin API.
// Call initAdminMetrics to initialize.
var adminMetrics = struct {
	requestCount *prometheus.CounterVec
}{}

func initAdminMetrics() {
	const ns = "caddy"
	const sub = "admin_http"
	adminMetrics.requestCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "requests_total",
		Help:      "Counter of requests made to admin endpoints.",
	}, []string{"handler", "path", "code", "method"})
}
