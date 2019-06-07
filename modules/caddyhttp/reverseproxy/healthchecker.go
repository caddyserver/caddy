package reverseproxy

import (
	"net/http"
	"time"
)

// Upstream represents the interface that must be satisfied to use the healthchecker.
type Upstream interface {
	SetHealthiness(bool)
}

// HealthChecker represents a worker that periodically evaluates if proxy upstream host is healthy.
type HealthChecker struct {
	upstream   Upstream
	Ticker     *time.Ticker
	HTTPClient *http.Client
	StopChan   chan bool
}

// ScheduleChecks periodically runs health checks against an upstream host.
func (h *HealthChecker) ScheduleChecks(url string) {
	// check if a host is healthy on start vs waiting for timer
	h.upstream.SetHealthiness(h.IsHealthy(url))
	stop := make(chan bool)
	h.StopChan = stop

	go func() {
		for {
			select {
			case <-h.Ticker.C:
				h.upstream.SetHealthiness(h.IsHealthy(url))
			case <-stop:
				return
			}
		}
	}()
}

// Stop stops the healthchecker from makeing further requests.
func (h *HealthChecker) Stop() {
	h.Ticker.Stop()
	close(h.StopChan)
}

// IsHealthy attempts to check if a upstream host is healthy.
func (h *HealthChecker) IsHealthy(url string) bool {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false
	}

	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return false
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false
	}

	return true
}

// NewHealthCheckWorker returns a new instance of a HealthChecker.
func NewHealthCheckWorker(u Upstream, interval time.Duration, client *http.Client) *HealthChecker {
	return &HealthChecker{
		upstream:   u,
		Ticker:     time.NewTicker(interval),
		HTTPClient: client,
	}
}
