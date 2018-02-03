package congestion

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"
)

const (
	// Note: This constant is also defined in the ackhandler package.
	initialRTTus          = 100 * 1000
	rttAlpha      float32 = 0.125
	oneMinusAlpha float32 = (1 - rttAlpha)
	rttBeta       float32 = 0.25
	oneMinusBeta  float32 = (1 - rttBeta)
	halfWindow    float32 = 0.5
	quarterWindow float32 = 0.25
)

type rttSample struct {
	rtt  time.Duration
	time time.Time
}

// RTTStats provides round-trip statistics
type RTTStats struct {
	initialRTTus int64

	recentMinRTTwindow time.Duration
	minRTT             time.Duration
	latestRTT          time.Duration
	smoothedRTT        time.Duration
	meanDeviation      time.Duration

	numMinRTTsamplesRemaining uint32

	newMinRTT        rttSample
	recentMinRTT     rttSample
	halfWindowRTT    rttSample
	quarterWindowRTT rttSample
}

// NewRTTStats makes a properly initialized RTTStats object
func NewRTTStats() *RTTStats {
	return &RTTStats{
		initialRTTus:       initialRTTus,
		recentMinRTTwindow: utils.InfDuration,
	}
}

// InitialRTTus is the initial RTT in us
func (r *RTTStats) InitialRTTus() int64 { return r.initialRTTus }

// MinRTT Returns the minRTT for the entire connection.
// May return Zero if no valid updates have occurred.
func (r *RTTStats) MinRTT() time.Duration { return r.minRTT }

// LatestRTT returns the most recent rtt measurement.
// May return Zero if no valid updates have occurred.
func (r *RTTStats) LatestRTT() time.Duration { return r.latestRTT }

// RecentMinRTT the minRTT since SampleNewRecentMinRtt has been called, or the
// minRTT for the entire connection if SampleNewMinRtt was never called.
func (r *RTTStats) RecentMinRTT() time.Duration { return r.recentMinRTT.rtt }

// SmoothedRTT returns the EWMA smoothed RTT for the connection.
// May return Zero if no valid updates have occurred.
func (r *RTTStats) SmoothedRTT() time.Duration { return r.smoothedRTT }

// GetQuarterWindowRTT gets the quarter window RTT
func (r *RTTStats) GetQuarterWindowRTT() time.Duration { return r.quarterWindowRTT.rtt }

// GetHalfWindowRTT gets the half window RTT
func (r *RTTStats) GetHalfWindowRTT() time.Duration { return r.halfWindowRTT.rtt }

// MeanDeviation gets the mean deviation
func (r *RTTStats) MeanDeviation() time.Duration { return r.meanDeviation }

// SetRecentMinRTTwindow sets how old a recent min rtt sample can be.
func (r *RTTStats) SetRecentMinRTTwindow(recentMinRTTwindow time.Duration) {
	r.recentMinRTTwindow = recentMinRTTwindow
}

// UpdateRTT updates the RTT based on a new sample.
func (r *RTTStats) UpdateRTT(sendDelta, ackDelay time.Duration, now time.Time) {
	if sendDelta == utils.InfDuration || sendDelta <= 0 {
		utils.Debugf("Ignoring measured sendDelta, because it's is either infinite, zero, or negative: %d", sendDelta/time.Microsecond)
		return
	}

	// Update r.minRTT first. r.minRTT does not use an rttSample corrected for
	// ackDelay but the raw observed sendDelta, since poor clock granularity at
	// the client may cause a high ackDelay to result in underestimation of the
	// r.minRTT.
	if r.minRTT == 0 || r.minRTT > sendDelta {
		r.minRTT = sendDelta
	}
	r.updateRecentMinRTT(sendDelta, now)

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

func (r *RTTStats) updateRecentMinRTT(sample time.Duration, now time.Time) { // Recent minRTT update.
	if r.numMinRTTsamplesRemaining > 0 {
		r.numMinRTTsamplesRemaining--
		if r.newMinRTT.rtt == 0 || sample <= r.newMinRTT.rtt {
			r.newMinRTT = rttSample{rtt: sample, time: now}
		}
		if r.numMinRTTsamplesRemaining == 0 {
			r.recentMinRTT = r.newMinRTT
			r.halfWindowRTT = r.newMinRTT
			r.quarterWindowRTT = r.newMinRTT
		}
	}

	// Update the three recent rtt samples.
	if r.recentMinRTT.rtt == 0 || sample <= r.recentMinRTT.rtt {
		r.recentMinRTT = rttSample{rtt: sample, time: now}
		r.halfWindowRTT = r.recentMinRTT
		r.quarterWindowRTT = r.recentMinRTT
	} else if sample <= r.halfWindowRTT.rtt {
		r.halfWindowRTT = rttSample{rtt: sample, time: now}
		r.quarterWindowRTT = r.halfWindowRTT
	} else if sample <= r.quarterWindowRTT.rtt {
		r.quarterWindowRTT = rttSample{rtt: sample, time: now}
	}

	// Expire old min rtt samples.
	if r.recentMinRTT.time.Before(now.Add(-r.recentMinRTTwindow)) {
		r.recentMinRTT = r.halfWindowRTT
		r.halfWindowRTT = r.quarterWindowRTT
		r.quarterWindowRTT = rttSample{rtt: sample, time: now}
	} else if r.halfWindowRTT.time.Before(now.Add(-time.Duration(float32(r.recentMinRTTwindow/time.Microsecond)*halfWindow) * time.Microsecond)) {
		r.halfWindowRTT = r.quarterWindowRTT
		r.quarterWindowRTT = rttSample{rtt: sample, time: now}
	} else if r.quarterWindowRTT.time.Before(now.Add(-time.Duration(float32(r.recentMinRTTwindow/time.Microsecond)*quarterWindow) * time.Microsecond)) {
		r.quarterWindowRTT = rttSample{rtt: sample, time: now}
	}
}

// SampleNewRecentMinRTT forces RttStats to sample a new recent min rtt within the next
// |numSamples| UpdateRTT calls.
func (r *RTTStats) SampleNewRecentMinRTT(numSamples uint32) {
	r.numMinRTTsamplesRemaining = numSamples
	r.newMinRTT = rttSample{}
}

// OnConnectionMigration is called when connection migrates and rtt measurement needs to be reset.
func (r *RTTStats) OnConnectionMigration() {
	r.latestRTT = 0
	r.minRTT = 0
	r.smoothedRTT = 0
	r.meanDeviation = 0
	r.initialRTTus = initialRTTus
	r.numMinRTTsamplesRemaining = 0
	r.recentMinRTTwindow = utils.InfDuration
	r.recentMinRTT = rttSample{}
	r.halfWindowRTT = rttSample{}
	r.quarterWindowRTT = rttSample{}
}

// ExpireSmoothedMetrics causes the smoothed_rtt to be increased to the latest_rtt if the latest_rtt
// is larger. The mean deviation is increased to the most recent deviation if
// it's larger.
func (r *RTTStats) ExpireSmoothedMetrics() {
	r.meanDeviation = utils.MaxDuration(r.meanDeviation, utils.AbsDuration(r.smoothedRTT-r.latestRTT))
	r.smoothedRTT = utils.MaxDuration(r.smoothedRTT, r.latestRTT)
}
