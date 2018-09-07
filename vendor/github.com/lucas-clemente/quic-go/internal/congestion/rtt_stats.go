package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"
)

const (
	rttAlpha      float32 = 0.125
	oneMinusAlpha float32 = (1 - rttAlpha)
	rttBeta       float32 = 0.25
	oneMinusBeta  float32 = (1 - rttBeta)
	// The default RTT used before an RTT sample is taken.
	defaultInitialRTT = 100 * time.Millisecond
)

// RTTStats provides round-trip statistics
type RTTStats struct {
	minRTT        time.Duration
	latestRTT     time.Duration
	smoothedRTT   time.Duration
	meanDeviation time.Duration
}

// NewRTTStats makes a properly initialized RTTStats object
func NewRTTStats() *RTTStats {
	return &RTTStats{}
}

// MinRTT Returns the minRTT for the entire connection.
// May return Zero if no valid updates have occurred.
func (r *RTTStats) MinRTT() time.Duration { return r.minRTT }

// LatestRTT returns the most recent rtt measurement.
// May return Zero if no valid updates have occurred.
func (r *RTTStats) LatestRTT() time.Duration { return r.latestRTT }

// SmoothedRTT returns the EWMA smoothed RTT for the connection.
// May return Zero if no valid updates have occurred.
func (r *RTTStats) SmoothedRTT() time.Duration { return r.smoothedRTT }

// SmoothedOrInitialRTT returns the EWMA smoothed RTT for the connection.
// If no valid updates have occurred, it returns the initial RTT.
func (r *RTTStats) SmoothedOrInitialRTT() time.Duration {
	if r.smoothedRTT != 0 {
		return r.smoothedRTT
	}
	return defaultInitialRTT
}

// MeanDeviation gets the mean deviation
func (r *RTTStats) MeanDeviation() time.Duration { return r.meanDeviation }

// UpdateRTT updates the RTT based on a new sample.
func (r *RTTStats) UpdateRTT(sendDelta, ackDelay time.Duration, now time.Time) {
	if sendDelta == utils.InfDuration || sendDelta <= 0 {
		return
	}

	// Update r.minRTT first. r.minRTT does not use an rttSample corrected for
	// ackDelay but the raw observed sendDelta, since poor clock granularity at
	// the client may cause a high ackDelay to result in underestimation of the
	// r.minRTT.
	if r.minRTT == 0 || r.minRTT > sendDelta {
		r.minRTT = sendDelta
	}

	// Correct for ackDelay if information received from the peer results in a
	// an RTT sample at least as large as minRTT. Otherwise, only use the
	// sendDelta.
	sample := sendDelta
	if sample-r.minRTT >= ackDelay {
		sample -= ackDelay
	}
	r.latestRTT = sample
	// First time call.
	if r.smoothedRTT == 0 {
		r.smoothedRTT = sample
		r.meanDeviation = sample / 2
	} else {
		r.meanDeviation = time.Duration(oneMinusBeta*float32(r.meanDeviation/time.Microsecond)+rttBeta*float32(utils.AbsDuration(r.smoothedRTT-sample)/time.Microsecond)) * time.Microsecond
		r.smoothedRTT = time.Duration((float32(r.smoothedRTT/time.Microsecond)*oneMinusAlpha)+(float32(sample/time.Microsecond)*rttAlpha)) * time.Microsecond
	}
}

// OnConnectionMigration is called when connection migrates and rtt measurement needs to be reset.
func (r *RTTStats) OnConnectionMigration() {
	r.latestRTT = 0
	r.minRTT = 0
	r.smoothedRTT = 0
	r.meanDeviation = 0
}

// ExpireSmoothedMetrics causes the smoothed_rtt to be increased to the latest_rtt if the latest_rtt
// is larger. The mean deviation is increased to the most recent deviation if
// it's larger.
func (r *RTTStats) ExpireSmoothedMetrics() {
	r.meanDeviation = utils.MaxDuration(r.meanDeviation, utils.AbsDuration(r.smoothedRTT-r.latestRTT))
	r.smoothedRTT = utils.MaxDuration(r.smoothedRTT, r.latestRTT)
}
