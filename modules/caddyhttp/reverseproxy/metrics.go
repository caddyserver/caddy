package reverseproxy

import (
	"errors"
	"runtime/debug"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/internal/metrics"
)

var reverseProxyMetrics = struct {
	once             sync.Once
	upstreamsHealthy *prometheus.GaugeVec
	upstreamRequests *prometheus.CounterVec
	upstreamDuration *prometheus.HistogramVec
	logger           *zap.Logger
}{}

func initReverseProxyMetrics(handler *Handler, registry *prometheus.Registry) {
	const ns, sub = "caddy", "reverse_proxy"

	upstreamsLabels := []string{"upstream"}
	upstreamRequestLabels := []string{"upstream", "code", "method"}

	reverseProxyMetrics.once.Do(func() {
		reverseProxyMetrics.upstreamsHealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "upstreams_healthy",
			Help:      "Health status of reverse proxy upstreams.",
		}, upstreamsLabels)

		reverseProxyMetrics.upstreamRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "upstream_requests_total",
			Help:      "Counter of requests made to upstreams.",
		}, upstreamRequestLabels)

		reverseProxyMetrics.upstreamDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "upstream_request_duration_seconds",
			Help:      "Histogram of request durations to upstreams.",
			Buckets:   prometheus.DefBuckets,
		}, upstreamsLabels)
	})

	// duplicate registration could happen if multiple sites with reverse proxy are configured; so ignore the error because
	// there's no good way to capture having multiple sites with reverse proxy. If this happens, the metrics will be
	// registered twice, but the second registration will be ignored.
	if err := registry.Register(reverseProxyMetrics.upstreamsHealthy); err != nil &&
		!errors.Is(err, prometheus.AlreadyRegisteredError{
			ExistingCollector: reverseProxyMetrics.upstreamsHealthy,
			NewCollector:      reverseProxyMetrics.upstreamsHealthy,
		}) {
		panic(err)
	}

	if err := registry.Register(reverseProxyMetrics.upstreamRequests); err != nil &&
		!errors.Is(err, prometheus.AlreadyRegisteredError{
			ExistingCollector: reverseProxyMetrics.upstreamRequests,
			NewCollector:      reverseProxyMetrics.upstreamRequests,
		}) {
		panic(err)
	}

	if err := registry.Register(reverseProxyMetrics.upstreamDuration); err != nil &&
		!errors.Is(err, prometheus.AlreadyRegisteredError{
			ExistingCollector: reverseProxyMetrics.upstreamDuration,
			NewCollector:      reverseProxyMetrics.upstreamDuration,
		}) {
		panic(err)
	}

	reverseProxyMetrics.logger = handler.logger.Named("reverse_proxy.metrics")
}

type metricsUpstreamsHealthyUpdater struct {
	handler *Handler
}

func newMetricsUpstreamsHealthyUpdater(handler *Handler, ctx caddy.Context) *metricsUpstreamsHealthyUpdater {
	initReverseProxyMetrics(handler, ctx.GetMetricsRegistry())
	reverseProxyMetrics.upstreamsHealthy.Reset()

	return &metricsUpstreamsHealthyUpdater{handler}
}

func (m *metricsUpstreamsHealthyUpdater) init() {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				if c := reverseProxyMetrics.logger.Check(zapcore.ErrorLevel, "upstreams healthy metrics updater panicked"); c != nil {
					c.Write(
						zap.Any("error", err),
						zap.ByteString("stack", debug.Stack()),
					)
				}
			}
		}()

		m.update()

		ticker := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-ticker.C:
				m.update()
			case <-m.handler.ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

func (m *metricsUpstreamsHealthyUpdater) update() {
	for _, upstream := range m.handler.Upstreams {
		labels := prometheus.Labels{"upstream": upstream.Dial}

		gaugeValue := 0.0
		if upstream.Healthy() {
			gaugeValue = 1.0
		}

		reverseProxyMetrics.upstreamsHealthy.With(labels).Set(gaugeValue)
	}
}

func recordUpstreamMetrics(upstream string, method string, statusCode int, duration time.Duration) {
	// Guard for test cases that bypass Provision()
	if reverseProxyMetrics.upstreamRequests == nil {
		return
	}

	code := metrics.SanitizeCode(statusCode)
	method = metrics.SanitizeMethod(method)

	reverseProxyMetrics.upstreamRequests.With(prometheus.Labels{
		"upstream": upstream,
		"code":     code,
		"method":   method,
	}).Inc()

	reverseProxyMetrics.upstreamDuration.With(prometheus.Labels{
		"upstream": upstream,
	}).Observe(duration.Seconds())
}
