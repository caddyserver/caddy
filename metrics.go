package caddy

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// define and register the metrics used in this package.
func init() {
	prometheus.MustRegister(collectors.NewBuildInfoCollector())

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
			"code":   sanitizeCode(d.status),
			"method": strings.ToUpper(r.Method),
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

func sanitizeCode(s int) string {
	switch s {
	case 0, 200:
		return "200"
	default:
		return strconv.Itoa(s)
	}
}
