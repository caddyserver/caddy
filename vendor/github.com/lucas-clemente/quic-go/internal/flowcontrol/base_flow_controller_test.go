package flowcontrol

import (
	"os"
	"strconv"
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// on the CIs, the timing is a lot less precise, so scale every duration by this factor
func scaleDuration(t time.Duration) time.Duration {
	scaleFactor := 1
	if f, err := strconv.Atoi(os.Getenv("TIMESCALE_FACTOR")); err == nil { // parsing "" errors, so this works fine if the env is not set
		scaleFactor = f
	}
	Expect(scaleFactor).ToNot(BeZero())
	return time.Duration(scaleFactor) * t
}

var _ = Describe("Base Flow controller", func() {
	var controller *baseFlowController

	BeforeEach(func() {
		controller = &baseFlowController{}
		controller.rttStats = &congestion.RTTStats{}
	})

	Context("send flow control", func() {
		It("adds bytes sent", func() {
			controller.bytesSent = 5
			controller.AddBytesSent(6)
			Expect(controller.bytesSent).To(Equal(protocol.ByteCount(5 + 6)))
		})

		It("gets the size of the remaining flow control window", func() {
			controller.bytesSent = 5
			controller.sendWindow = 12
			Expect(controller.sendWindowSize()).To(Equal(protocol.ByteCount(12 - 5)))
		})

		It("updates the size of the flow control window", func() {
			controller.AddBytesSent(5)
			controller.UpdateSendWindow(15)
			Expect(controller.sendWindow).To(Equal(protocol.ByteCount(15)))
			Expect(controller.sendWindowSize()).To(Equal(protocol.ByteCount(15 - 5)))
		})

		It("says that the window size is 0 if we sent more than we were allowed to", func() {
			controller.AddBytesSent(15)
			controller.UpdateSendWindow(10)
			Expect(controller.sendWindowSize()).To(BeZero())
		})

		It("does not decrease the flow control window", func() {
			controller.UpdateSendWindow(20)
			Expect(controller.sendWindowSize()).To(Equal(protocol.ByteCount(20)))
			controller.UpdateSendWindow(10)
			Expect(controller.sendWindowSize()).To(Equal(protocol.ByteCount(20)))
		})

		It("says when it's blocked", func() {
			controller.UpdateSendWindow(100)
			Expect(controller.IsNewlyBlocked()).To(BeFalse())
			controller.AddBytesSent(100)
			blocked, offset := controller.IsNewlyBlocked()
			Expect(blocked).To(BeTrue())
			Expect(offset).To(Equal(protocol.ByteCount(100)))
		})

		It("doesn't say that it's newly blocked multiple times for the same offset", func() {
			controller.UpdateSendWindow(100)
			controller.AddBytesSent(100)
			newlyBlocked, offset := controller.IsNewlyBlocked()
			Expect(newlyBlocked).To(BeTrue())
			Expect(offset).To(Equal(protocol.ByteCount(100)))
			newlyBlocked, _ = controller.IsNewlyBlocked()
			Expect(newlyBlocked).To(BeFalse())
			controller.UpdateSendWindow(150)
			controller.AddBytesSent(150)
			newlyBlocked, _ = controller.IsNewlyBlocked()
			Expect(newlyBlocked).To(BeTrue())
		})
	})

	Context("receive flow control", func() {
		var (
			receiveWindow     protocol.ByteCount = 10000
			receiveWindowSize protocol.ByteCount = 1000
		)

		BeforeEach(func() {
			controller.bytesRead = receiveWindow - receiveWindowSize
			controller.receiveWindow = receiveWindow
			controller.receiveWindowSize = receiveWindowSize
		})

		It("adds bytes read", func() {
			controller.bytesRead = 5
			controller.AddBytesRead(6)
			Expect(controller.bytesRead).To(Equal(protocol.ByteCount(5 + 6)))
		})

		It("triggers a window update when necessary", func() {
			bytesConsumed := float64(receiveWindowSize)*protocol.WindowUpdateThreshold + 1 // consumed 1 byte more than the threshold
			bytesRemaining := receiveWindowSize - protocol.ByteCount(bytesConsumed)
			readPosition := receiveWindow - bytesRemaining
			controller.bytesRead = readPosition
			offset := controller.getWindowUpdate()
			Expect(offset).To(Equal(readPosition + receiveWindowSize))
			Expect(controller.receiveWindow).To(Equal(readPosition + receiveWindowSize))
		})

		It("doesn't trigger a window update when not necessary", func() {
			bytesConsumed := float64(receiveWindowSize)*protocol.WindowUpdateThreshold - 1 // consumed 1 byte less than the threshold
			bytesRemaining := receiveWindowSize - protocol.ByteCount(bytesConsumed)
			readPosition := receiveWindow - bytesRemaining
			controller.bytesRead = readPosition
			offset := controller.getWindowUpdate()
			Expect(offset).To(BeZero())
		})

		Context("receive window size auto-tuning", func() {
			var oldWindowSize protocol.ByteCount

			BeforeEach(func() {
				oldWindowSize = controller.receiveWindowSize
				controller.maxReceiveWindowSize = 5000
			})

			// update the congestion such that it returns a given value for the smoothed RTT
			setRtt := func(t time.Duration) {
				controller.rttStats.UpdateRTT(t, 0, time.Now())
				Expect(controller.rttStats.SmoothedRTT()).To(Equal(t)) // make sure it worked
			}

			It("doesn't increase the window size for a new stream", func() {
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(oldWindowSize))
			})

			It("doesn't increase the window size when no RTT estimate is available", func() {
				setRtt(0)
				controller.startNewAutoTuningEpoch()
				controller.AddBytesRead(400)
				offset := controller.getWindowUpdate()
				Expect(offset).ToNot(BeZero()) // make sure a window update is sent
				Expect(controller.receiveWindowSize).To(Equal(oldWindowSize))
			})

			It("increases the window size if read so fast that the window would be consumed in less than 4 RTTs", func() {
				bytesRead := controller.bytesRead
				rtt := scaleDuration(20 * time.Millisecond)
				setRtt(rtt)
				// consume more than 2/3 of the window...
				dataRead := receiveWindowSize*2/3 + 1
				// ... in 4*2/3 of the RTT
				controller.epochStartOffset = controller.bytesRead
				controller.epochStartTime = time.Now().Add(-rtt * 4 * 2 / 3)
				controller.AddBytesRead(dataRead)
				offset := controller.getWindowUpdate()
				Expect(offset).ToNot(BeZero())
				// check that the window size was increased
				newWindowSize := controller.receiveWindowSize
				Expect(newWindowSize).To(Equal(2 * oldWindowSize))
				// check that the new window size was used to increase the offset
				Expect(offset).To(Equal(protocol.ByteCount(bytesRead + dataRead + newWindowSize)))
			})

			It("doesn't increase the window size if data is read so fast that the window would be consumed in less than 4 RTTs, but less than half the window has been read", func() {
				// this test only makes sense if a window update is triggered before half of the window has been consumed
				Expect(protocol.WindowUpdateThreshold).To(BeNumerically(">", 1/3))
				bytesRead := controller.bytesRead
				rtt := scaleDuration(20 * time.Millisecond)
				setRtt(rtt)
				// consume more than 2/3 of the window...
				dataRead := receiveWindowSize*1/3 + 1
				// ... in 4*2/3 of the RTT
				controller.epochStartOffset = controller.bytesRead
				controller.epochStartTime = time.Now().Add(-rtt * 4 * 1 / 3)
				controller.AddBytesRead(dataRead)
				offset := controller.getWindowUpdate()
				Expect(offset).ToNot(BeZero())
				// check that the window size was not increased
				newWindowSize := controller.receiveWindowSize
				Expect(newWindowSize).To(Equal(oldWindowSize))
				// check that the new window size was used to increase the offset
				Expect(offset).To(Equal(protocol.ByteCount(bytesRead + dataRead + newWindowSize)))
			})

			It("doesn't increase the window size if read too slowly", func() {
				bytesRead := controller.bytesRead
				rtt := scaleDuration(20 * time.Millisecond)
				setRtt(rtt)
				// consume less than 2/3 of the window...
				dataRead := receiveWindowSize*2/3 - 1
				// ... in 4*2/3 of the RTT
				controller.epochStartOffset = controller.bytesRead
				controller.epochStartTime = time.Now().Add(-rtt * 4 * 2 / 3)
				controller.AddBytesRead(dataRead)
				offset := controller.getWindowUpdate()
				Expect(offset).ToNot(BeZero())
				// check that the window size was not increased
				Expect(controller.receiveWindowSize).To(Equal(oldWindowSize))
				// check that the new window size was used to increase the offset
				Expect(offset).To(Equal(protocol.ByteCount(bytesRead + dataRead + oldWindowSize)))
			})

			It("doesn't increase the window size to a value higher than the maxReceiveWindowSize", func() {
				resetEpoch := func() {
					// make sure the next call to maybeAdjustWindowSize will increase the window
					controller.epochStartTime = time.Now().Add(-time.Millisecond)
					controller.epochStartOffset = controller.bytesRead
					controller.AddBytesRead(controller.receiveWindowSize/2 + 1)
				}
				setRtt(scaleDuration(20 * time.Millisecond))
				resetEpoch()
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(2 * oldWindowSize)) // 2000
				// because the lastWindowUpdateTime is updated by MaybeTriggerWindowUpdate(), we can just call maybeAdjustWindowSize() multiple times and get an increase of the window size every time
				resetEpoch()
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(2 * 2 * oldWindowSize)) // 4000
				resetEpoch()
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(controller.maxReceiveWindowSize)) // 5000
				controller.maybeAdjustWindowSize()
				Expect(controller.receiveWindowSize).To(Equal(controller.maxReceiveWindowSize)) // 5000
			})
		})
	})
})
