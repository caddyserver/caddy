package reverseproxy

import (
	"runtime/debug"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

var reverseProxyMetrics = struct {
	init             sync.Once
	upstreamsHealthy *prometheus.GaugeVec
	logger           *zap.Logger
}{}

func initReverseProxyMetrics(handler *Handler) {
	const ns, sub = "caddy", "reverse_proxy"

	upstreamsLabels := []string{"upstream"}
	reverseProxyMetrics.upstreamsHealthy = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns,
		Subsystem: sub,
		Name:      "upstreams_healthy",
		Help:      "Health status of reverse proxy upstreams.",
	}, upstreamsLabels)

	reverseProxyMetrics.logger = handler.logger.Named("reverse_proxy.metrics")
}

type metricsUpstreamsHealthyUpdater struct {
	handler *Handler
}

func newMetricsUpstreamsHealthyUpdater(handler *Handler) *metricsUpstreamsHealthyUpdater {
	reverseProxyMetrics.init.Do(func() {
		initReverseProxyMetrics(handler)
	})

	return &metricsUpstreamsHealthyUpdater{handler}
}

func (m *metricsUpstreamsHealthyUpdater) Init() {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				reverseProxyMetrics.logger.Error("upstreams healthy metrics updater panicked",
					zap.Any("error", err),
					zap.ByteString("stack", debug.Stack()))
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
