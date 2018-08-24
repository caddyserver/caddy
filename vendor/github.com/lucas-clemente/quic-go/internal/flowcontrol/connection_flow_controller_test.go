package flowcontrol

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Connection Flow controller", func() {
	var (
		controller         *connectionFlowController
		queuedWindowUpdate bool
	)

	// update the congestion such that it returns a given value for the smoothed RTT
	setRtt := func(t time.Duration) {
		controller.rttStats.UpdateRTT(t, 0, time.Now())
		Expect(controller.rttStats.SmoothedRTT()).To(Equal(t)) // make sure it worked
	}

	BeforeEach(func() {
		controller = &connectionFlowController{}
		controller.rttStats = &congestion.RTTStats{}
		controller.logger = utils.DefaultLogger
		controller.queueWindowUpdate = func() { queuedWindowUpdate = true }
	})

	Context("Constructor", func() {
		rttStats := &congestion.RTTStats{}

		It("sets the send and receive windows", func() {
			receiveWindow := protocol.ByteCount(2000)
			maxReceiveWindow := protocol.ByteCount(3000)

			fc := NewConnectionFlowController(receiveWindow, maxReceiveWindow, nil, rttStats, utils.DefaultLogger).(*connectionFlowController)
			Expect(fc.receiveWindow).To(Equal(receiveWindow))
			Expect(fc.maxReceiveWindowSize).To(Equal(maxReceiveWindow))
		})
	})

	Context("receive flow control", func() {
		It("increases the highestReceived by a given window size", func() {
			controller.highestReceived = 1337
			controller.IncrementHighestReceived(123)
			Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337 + 123)))
		})

		Context("getting window updates", func() {
			BeforeEach(func() {
				controller.receiveWindow = 100
				controller.receiveWindowSize = 60
				controller.maxReceiveWindowSize = 1000
				controller.bytesRead = 100 - 60
			})

			It("queues window updates", func() {
				controller.MaybeQueueWindowUpdate()
				Expect(queuedWindowUpdate).To(BeFalse())
				controller.AddBytesRead(30)
				controller.MaybeQueueWindowUpdate()
				Expect(queuedWindowUpdate).To(BeTrue())
				Expect(controller.GetWindowUpdate()).ToNot(BeZero())
				queuedWindowUpdate = false
				controller.MaybeQueueWindowUpdate()
				Expect(queuedWindowUpdate).To(BeFalse())
			})

			It("gets a window update", func() {
				windowSize := controller.receiveWindowSize
				oldOffset := controller.bytesRead
				dataRead := windowSize/2 - 1 // make sure not to trigger auto-tuning
				controller.AddBytesRead(dataRead)
				offset := controller.GetWindowUpdate()
				Expect(offset).To(Equal(protocol.ByteCount(oldOffset + dataRead + 60)))
			})

			It("autotunes the window", func() {
				oldOffset := controller.bytesRead
				oldWindowSize := controller.receiveWindowSize
				rtt := scaleDuration(20 * time.Millisecond)
				setRtt(rtt)
				controller.epochStartTime = time.Now().Add(-time.Millisecond)
				controller.epochStartOffset = oldOffset
				dataRead := oldWindowSize/2 + 1
				controller.AddBytesRead(dataRead)
				offset := controller.GetWindowUpdate()
				newWindowSize := controller.receiveWindowSize
				Expect(newWindowSize).To(Equal(2 * oldWindowSize))
				Expect(offset).To(Equal(protocol.ByteCount(oldOffset + dataRead + newWindowSize)))
			})
		})
	})

	Context("setting the minimum window size", func() {
		var (
			oldWindowSize     protocol.ByteCount
			receiveWindow     protocol.ByteCount = 10000
			receiveWindowSize protocol.ByteCount = 1000
		)

		BeforeEach(func() {
			controller.receiveWindow = receiveWindow
			controller.receiveWindowSize = receiveWindowSize
			oldWindowSize = controller.receiveWindowSize
			controller.maxReceiveWindowSize = 3000
		})

		It("sets the minimum window window size", func() {
			controller.EnsureMinimumWindowSize(1800)
			Expect(controller.receiveWindowSize).To(Equal(protocol.ByteCount(1800)))
		})

		It("doesn't reduce the window window size", func() {
			controller.EnsureMinimumWindowSize(1)
			Expect(controller.receiveWindowSize).To(Equal(oldWindowSize))
		})

		It("doens't increase the window size beyond the maxReceiveWindowSize", func() {
			max := controller.maxReceiveWindowSize
			controller.EnsureMinimumWindowSize(2 * max)
			Expect(controller.receiveWindowSize).To(Equal(max))
		})

		It("starts a new epoch after the window size was increased", func() {
			controller.EnsureMinimumWindowSize(1912)
			Expect(controller.epochStartTime).To(BeTemporally("~", time.Now(), 100*time.Millisecond))
		})
	})
})
