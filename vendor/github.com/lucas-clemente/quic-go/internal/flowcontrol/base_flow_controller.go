package flowcontrol

import (
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type baseFlowController struct {
	// for sending data
	bytesSent     protocol.ByteCount
	sendWindow    protocol.ByteCount
	lastBlockedAt protocol.ByteCount

	// for receiving data
	mutex                sync.RWMutex
	bytesRead            protocol.ByteCount
	highestReceived      protocol.ByteCount
	receiveWindow        protocol.ByteCount
	receiveWindowSize    protocol.ByteCount
	maxReceiveWindowSize protocol.ByteCount

	epochStartTime   time.Time
	epochStartOffset protocol.ByteCount
	rttStats         *congestion.RTTStats

	logger utils.Logger
}

// IsNewlyBlocked says if it is newly blocked by flow control.
// For every offset, it only returns true once.
// If it is blocked, the offset is returned.
func (c *baseFlowController) IsNewlyBlocked() (bool, protocol.ByteCount) {
	if c.sendWindowSize() != 0 || c.sendWindow == c.lastBlockedAt {
		return false, 0
	}
	c.lastBlockedAt = c.sendWindow
	return true, c.sendWindow
}

func (c *baseFlowController) AddBytesSent(n protocol.ByteCount) {
	c.bytesSent += n
}

// UpdateSendWindow should be called after receiving a WindowUpdateFrame
// it returns true if the window was actually updated
func (c *baseFlowController) UpdateSendWindow(offset protocol.ByteCount) {
	if offset > c.sendWindow {
		c.sendWindow = offset
	}
}

func (c *baseFlowController) sendWindowSize() protocol.ByteCount {
	// this only happens during connection establishment, when data is sent before we receive the peer's transport parameters
	if c.bytesSent > c.sendWindow {
		return 0
	}
	return c.sendWindow - c.bytesSent
}

func (c *baseFlowController) AddBytesRead(n protocol.ByteCount) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// pretend we sent a WindowUpdate when reading the first byte
	// this way auto-tuning of the window size already works for the first WindowUpdate
	if c.bytesRead == 0 {
		c.startNewAutoTuningEpoch()
	}
	c.bytesRead += n
}

func (c *baseFlowController) hasWindowUpdate() bool {
	bytesRemaining := c.receiveWindow - c.bytesRead
	// update the window when more than the threshold was consumed
	return bytesRemaining <= protocol.ByteCount((float64(c.receiveWindowSize) * float64((1 - protocol.WindowUpdateThreshold))))
}

// getWindowUpdate updates the receive window, if necessary
// it returns the new offset
func (c *baseFlowController) getWindowUpdate() protocol.ByteCount {
	if !c.hasWindowUpdate() {
		return 0
	}

	c.maybeAdjustWindowSize()
	c.receiveWindow = c.bytesRead + c.receiveWindowSize
	return c.receiveWindow
}

// maybeAdjustWindowSize increases the receiveWindowSize if we're sending updates too often.
// For details about auto-tuning, see https://docs.google.com/document/d/1SExkMmGiz8VYzV3s9E35JQlJ73vhzCekKkDi85F1qCE/edit?usp=sharing.
func (c *baseFlowController) maybeAdjustWindowSize() {
	bytesReadInEpoch := c.bytesRead - c.epochStartOffset
	// don't do anything if less than half the window has been consumed
	if bytesReadInEpoch <= c.receiveWindowSize/2 {
		return
	}
	rtt := c.rttStats.SmoothedRTT()
	if rtt == 0 {
		return
	}

	fraction := float64(bytesReadInEpoch) / float64(c.receiveWindowSize)
	if time.Since(c.epochStartTime) < time.Duration(4*fraction*float64(rtt)) {
		// window is consumed too fast, try to increase the window size
		c.receiveWindowSize = utils.MinByteCount(2*c.receiveWindowSize, c.maxReceiveWindowSize)
	}
	c.startNewAutoTuningEpoch()
}

func (c *baseFlowController) startNewAutoTuningEpoch() {
	c.epochStartTime = time.Now()
	c.epochStartOffset = c.bytesRead
}

func (c *baseFlowController) checkFlowControlViolation() bool {
	return c.highestReceived > c.receiveWindow
}
