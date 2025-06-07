package caddy

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"

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

type RegistererGatherer interface {
	prometheus.Registerer
	prometheus.Gatherer
}
type registryGatherer struct {
	registry prometheus.Registerer
	gatherer prometheus.Gatherer
	tracker  map[string]*sync.Once

	callerModule string
}

// Gather implements prometheus.Gatherer.
func (r *registryGatherer) Gather() ([]*io_prometheus_client.MetricFamily, error) {
	return r.gatherer.Gather()
}

// MustRegister implements prometheus.Registerer.
func (r *registryGatherer) MustRegister(cs ...prometheus.Collector) {
	if _, ok := r.tracker[r.callerModule]; !ok {
		r.tracker[r.callerModule] = &sync.Once{}
	}
	r.tracker[r.callerModule].Do(func() {
		r.registry.MustRegister(cs...)
	})
}

// Register implements prometheus.Registerer.
func (r *registryGatherer) Register(c prometheus.Collector) error {
	var err error
	if _, ok := r.tracker[r.callerModule]; !ok {
		r.tracker[r.callerModule] = &sync.Once{}
	}
	r.tracker[r.callerModule].Do(func() {
		err = r.registry.Register(c)
	})
	return err
}

// Unregister implements prometheus.Registerer.
func (r *registryGatherer) Unregister(c prometheus.Collector) bool {
	delete(r.tracker, r.callerModule)
	return r.registry.Unregister(c)
}

var (
	_ prometheus.Registerer = (*registryGatherer)(nil)
	_ prometheus.Gatherer   = (*registryGatherer)(nil)
)
