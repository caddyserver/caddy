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
)

var reverseProxyMetrics = struct {
	once             sync.Once
	upstreamsHealthy *prometheus.GaugeVec
	streamsActive    *prometheus.GaugeVec
	streamsTotal     *prometheus.CounterVec
	streamDuration   *prometheus.HistogramVec
	streamBytes      *prometheus.CounterVec
	logger           *zap.Logger
}{}

func initReverseProxyMetrics(handler *Handler, registry *prometheus.Registry) {
	const ns, sub = "caddy", "reverse_proxy"

	upstreamsLabels := []string{"upstream"}
	streamResultLabels := []string{"upstream", "result"}
	streamBytesLabels := []string{"upstream", "direction"}
	reverseProxyMetrics.once.Do(func() {
		reverseProxyMetrics.upstreamsHealthy = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "upstreams_healthy",
			Help:      "Health status of reverse proxy upstreams.",
		}, upstreamsLabels)
		reverseProxyMetrics.streamsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "streams_active",
			Help:      "Number of currently active upgraded reverse proxy streams.",
		}, upstreamsLabels)
		reverseProxyMetrics.streamsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "streams_total",
			Help:      "Total number of upgraded reverse proxy streams by close result.",
		}, streamResultLabels)
		reverseProxyMetrics.streamDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "stream_duration_seconds",
			Help:      "Duration of upgraded reverse proxy streams by close result.",
			Buckets:   prometheus.DefBuckets,
		}, streamResultLabels)
		reverseProxyMetrics.streamBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "stream_bytes_total",
			Help:      "Total bytes proxied across upgraded reverse proxy streams.",
		}, streamBytesLabels)
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
	if err := registry.Register(reverseProxyMetrics.streamsActive); err != nil &&
		!errors.Is(err, prometheus.AlreadyRegisteredError{
			ExistingCollector: reverseProxyMetrics.streamsActive,
			NewCollector:      reverseProxyMetrics.streamsActive,
		}) {
		panic(err)
	}
	if err := registry.Register(reverseProxyMetrics.streamsTotal); err != nil &&
		!errors.Is(err, prometheus.AlreadyRegisteredError{
			ExistingCollector: reverseProxyMetrics.streamsTotal,
			NewCollector:      reverseProxyMetrics.streamsTotal,
		}) {
		panic(err)
	}
	if err := registry.Register(reverseProxyMetrics.streamDuration); err != nil &&
		!errors.Is(err, prometheus.AlreadyRegisteredError{
			ExistingCollector: reverseProxyMetrics.streamDuration,
			NewCollector:      reverseProxyMetrics.streamDuration,
		}) {
		panic(err)
	}
	if err := registry.Register(reverseProxyMetrics.streamBytes); err != nil &&
		!errors.Is(err, prometheus.AlreadyRegisteredError{
			ExistingCollector: reverseProxyMetrics.streamBytes,
			NewCollector:      reverseProxyMetrics.streamBytes,
		}) {
		panic(err)
	}

	reverseProxyMetrics.logger = handler.logger.Named("reverse_proxy.metrics")
}

func trackActiveStream(upstream string) func(result string, duration time.Duration, toBackend, fromBackend int64) {
	labels := prometheus.Labels{"upstream": upstream}
	reverseProxyMetrics.streamsActive.With(labels).Inc()

	var once sync.Once
	return func(result string, duration time.Duration, toBackend, fromBackend int64) {
		once.Do(func() {
			reverseProxyMetrics.streamsActive.With(labels).Dec()
			reverseProxyMetrics.streamsTotal.WithLabelValues(upstream, result).Inc()
			reverseProxyMetrics.streamDuration.WithLabelValues(upstream, result).Observe(duration.Seconds())
			if toBackend > 0 {
				reverseProxyMetrics.streamBytes.WithLabelValues(upstream, "to_upstream").Add(float64(toBackend))
			}
			if fromBackend > 0 {
				reverseProxyMetrics.streamBytes.WithLabelValues(upstream, "from_upstream").Add(float64(fromBackend))
			}
		})
	}
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
