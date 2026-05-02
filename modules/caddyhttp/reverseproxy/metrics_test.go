package reverseproxy

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestTrackActiveStreamRecordsLifecycleAndBytes(t *testing.T) {
	const upstream = "127.0.0.1:7443"

	// Use fresh metric vectors for deterministic assertions in this unit test.
	reverseProxyMetrics.streamsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{}, []string{"upstream"})
	reverseProxyMetrics.streamsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{}, []string{"upstream", "result"})
	reverseProxyMetrics.streamDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{}, []string{"upstream", "result"})
	reverseProxyMetrics.streamBytes = prometheus.NewCounterVec(prometheus.CounterOpts{}, []string{"upstream", "direction"})

	finish := trackActiveStream(upstream)

	if got := testutil.ToFloat64(reverseProxyMetrics.streamsActive.WithLabelValues(upstream)); got != 1 {
		t.Fatalf("active streams = %v, want 1", got)
	}

	finish("closed", 150*time.Millisecond, 1234, 4321)

	if got := testutil.ToFloat64(reverseProxyMetrics.streamsActive.WithLabelValues(upstream)); got != 0 {
		t.Fatalf("active streams = %v, want 0", got)
	}
	if got := testutil.ToFloat64(reverseProxyMetrics.streamsTotal.WithLabelValues(upstream, "closed")); got != 1 {
		t.Fatalf("streams_total closed = %v, want 1", got)
	}
	if got := testutil.ToFloat64(reverseProxyMetrics.streamBytes.WithLabelValues(upstream, "to_upstream")); got != 1234 {
		t.Fatalf("bytes to_upstream = %v, want 1234", got)
	}
	if got := testutil.ToFloat64(reverseProxyMetrics.streamBytes.WithLabelValues(upstream, "from_upstream")); got != 4321 {
		t.Fatalf("bytes from_upstream = %v, want 4321", got)
	}

	// A second finish call should be ignored by the once guard.
	finish("error", 1*time.Second, 111, 222)
	if got := testutil.ToFloat64(reverseProxyMetrics.streamsTotal.WithLabelValues(upstream, "error")); got != 0 {
		t.Fatalf("streams_total error = %v, want 0", got)
	}
}

func TestTrackActiveStreamDoesNotCountZeroBytes(t *testing.T) {
	const upstream = "127.0.0.1:9000"

	reverseProxyMetrics.streamsActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{}, []string{"upstream"})
	reverseProxyMetrics.streamsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{}, []string{"upstream", "result"})
	reverseProxyMetrics.streamDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{}, []string{"upstream", "result"})
	reverseProxyMetrics.streamBytes = prometheus.NewCounterVec(prometheus.CounterOpts{}, []string{"upstream", "direction"})

	trackActiveStream(upstream)("timeout", 250*time.Millisecond, 0, 0)

	if got := testutil.ToFloat64(reverseProxyMetrics.streamBytes.WithLabelValues(upstream, "to_upstream")); got != 0 {
		t.Fatalf("bytes to_upstream = %v, want 0", got)
	}
	if got := testutil.ToFloat64(reverseProxyMetrics.streamBytes.WithLabelValues(upstream, "from_upstream")); got != 0 {
		t.Fatalf("bytes from_upstream = %v, want 0", got)
	}
	if got := testutil.ToFloat64(reverseProxyMetrics.streamsTotal.WithLabelValues(upstream, "timeout")); got != 1 {
		t.Fatalf("streams_total timeout = %v, want 1", got)
	}
}
