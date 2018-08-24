package flowcontrol

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/congestion"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Stream Flow controller", func() {
	var (
		controller             *streamFlowController
		queuedWindowUpdate     bool
		queuedConnWindowUpdate bool
	)

	BeforeEach(func() {
		queuedWindowUpdate = false
		queuedConnWindowUpdate = false
		rttStats := &congestion.RTTStats{}
		controller = &streamFlowController{
			streamID:   10,
			connection: NewConnectionFlowController(1000, 1000, func() { queuedConnWindowUpdate = true }, rttStats, utils.DefaultLogger).(*connectionFlowController),
		}
		controller.maxReceiveWindowSize = 10000
		controller.rttStats = rttStats
		controller.logger = utils.DefaultLogger
		controller.queueWindowUpdate = func() { queuedWindowUpdate = true }
	})

	Context("Constructor", func() {
		rttStats := &congestion.RTTStats{}
		receiveWindow := protocol.ByteCount(2000)
		maxReceiveWindow := protocol.ByteCount(3000)
		sendWindow := protocol.ByteCount(4000)

		It("sets the send and receive windows", func() {
			cc := NewConnectionFlowController(0, 0, nil, nil, utils.DefaultLogger)
			fc := NewStreamFlowController(5, true, cc, receiveWindow, maxReceiveWindow, sendWindow, nil, rttStats, utils.DefaultLogger).(*streamFlowController)
			Expect(fc.streamID).To(Equal(protocol.StreamID(5)))
			Expect(fc.receiveWindow).To(Equal(receiveWindow))
			Expect(fc.maxReceiveWindowSize).To(Equal(maxReceiveWindow))
			Expect(fc.sendWindow).To(Equal(sendWindow))
			Expect(fc.contributesToConnection).To(BeTrue())
		})

		It("queues window updates with the correction stream ID", func() {
			var queued bool
			queueWindowUpdate := func(id protocol.StreamID) {
				Expect(id).To(Equal(protocol.StreamID(5)))
				queued = true
			}

			cc := NewConnectionFlowController(0, 0, nil, nil, utils.DefaultLogger)
			fc := NewStreamFlowController(5, true, cc, receiveWindow, maxReceiveWindow, sendWindow, queueWindowUpdate, rttStats, utils.DefaultLogger).(*streamFlowController)
			fc.AddBytesRead(receiveWindow)
			fc.MaybeQueueWindowUpdate()
			Expect(queued).To(BeTrue())
		})
	})

	Context("receiving data", func() {
		Context("registering received offsets", func() {
			var receiveWindow protocol.ByteCount = 10000
			var receiveWindowSize protocol.ByteCount = 600

			BeforeEach(func() {
				controller.receiveWindow = receiveWindow
				controller.receiveWindowSize = receiveWindowSize
			})

			It("updates the highestReceived", func() {
				controller.highestReceived = 1337
				err := controller.UpdateHighestReceived(1338, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1338)))
			})

			It("informs the connection flow controller about received data", func() {
				controller.highestReceived = 10
				controller.contributesToConnection = true
				controller.connection.(*connectionFlowController).highestReceived = 100
				err := controller.UpdateHighestReceived(20, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.connection.(*connectionFlowController).highestReceived).To(Equal(protocol.ByteCount(100 + 10)))
			})

			It("doesn't informs the connection flow controller about received data if it doesn't contribute", func() {
				controller.highestReceived = 10
				controller.connection.(*connectionFlowController).highestReceived = 100
				err := controller.UpdateHighestReceived(20, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.connection.(*connectionFlowController).highestReceived).To(Equal(protocol.ByteCount(100)))
			})

			It("does not decrease the highestReceived", func() {
				controller.highestReceived = 1337
				err := controller.UpdateHighestReceived(1000, false)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(1337)))
			})

			It("does nothing when setting the same byte offset", func() {
				controller.highestReceived = 1337
				err := controller.UpdateHighestReceived(1337, false)
				Expect(err).ToNot(HaveOccurred())
			})

			It("does not give a flow control violation when using the window completely", func() {
				err := controller.UpdateHighestReceived(receiveWindow, false)
				Expect(err).ToNot(HaveOccurred())
			})

			It("detects a flow control violation", func() {
				err := controller.UpdateHighestReceived(receiveWindow+1, false)
				Expect(err).To(MatchError("FlowControlReceivedTooMuchData: Received 10001 bytes on stream 10, allowed 10000 bytes"))
			})

			It("accepts a final offset higher than the highest received", func() {
				controller.highestReceived = 100
				err := controller.UpdateHighestReceived(101, true)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(101)))
			})

			It("errors when receiving a final offset smaller than the highest offset received so far", func() {
				controller.highestReceived = 100
				err := controller.UpdateHighestReceived(99, true)
				Expect(err).To(MatchError(qerr.StreamDataAfterTermination))
			})

			It("accepts delayed data after receiving a final offset", func() {
				err := controller.UpdateHighestReceived(300, true)
				Expect(err).ToNot(HaveOccurred())
				err = controller.UpdateHighestReceived(250, false)
				Expect(err).ToNot(HaveOccurred())
			})

			It("errors when receiving a higher offset after receiving a final offset", func() {
				err := controller.UpdateHighestReceived(200, true)
				Expect(err).ToNot(HaveOccurred())
				err = controller.UpdateHighestReceived(250, false)
				Expect(err).To(MatchError(qerr.StreamDataAfterTermination))
			})

			It("accepts duplicate final offsets", func() {
				err := controller.UpdateHighestReceived(200, true)
				Expect(err).ToNot(HaveOccurred())
				err = controller.UpdateHighestReceived(200, true)
				Expect(err).ToNot(HaveOccurred())
				Expect(controller.highestReceived).To(Equal(protocol.ByteCount(200)))
			})

			It("errors when receiving inconsistent final offsets", func() {
				err := controller.UpdateHighestReceived(200, true)
				Expect(err).ToNot(HaveOccurred())
				err = controller.UpdateHighestReceived(201, true)
				Expect(err).To(MatchError("StreamDataAfterTermination: Received inconsistent final offset for stream 10 (old: 200, new: 201 bytes)"))
			})
		})

		Context("registering data read", func() {
			It("saves when data is read, on a stream not contributing to the connection", func() {
				controller.AddBytesRead(100)
				Expect(controller.bytesRead).To(Equal(protocol.ByteCount(100)))
				Expect(controller.connection.(*connectionFlowController).bytesRead).To(BeZero())
			})

			It("saves when data is read, on a stream not contributing to the connection", func() {
				controller.contributesToConnection = true
				controller.AddBytesRead(200)
				Expect(controller.bytesRead).To(Equal(protocol.ByteCount(200)))
				Expect(controller.connection.(*connectionFlowController).bytesRead).To(Equal(protocol.ByteCount(200)))
			})
		})

		Context("generating window updates", func() {
			var oldWindowSize protocol.ByteCount

			// update the congestion such that it returns a given value for the smoothed RTT
			setRtt := func(t time.Duration) {
				controller.rttStats.UpdateRTT(t, 0, time.Now())
				Expect(controller.rttStats.SmoothedRTT()).To(Equal(t)) // make sure it worked
			}

			BeforeEach(func() {
				controller.receiveWindow = 100
				controller.receiveWindowSize = 60
				controller.bytesRead = 100 - 60
				controller.connection.(*connectionFlowController).receiveWindow = 100
				controller.connection.(*connectionFlowController).receiveWindowSize = 120
				oldWindowSize = controller.receiveWindowSize
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

			It("queues connection-level window updates", func() {
				controller.contributesToConnection = true
				controller.MaybeQueueWindowUpdate()
				Expect(queuedConnWindowUpdate).To(BeFalse())
				controller.AddBytesRead(60)
				controller.MaybeQueueWindowUpdate()
				Expect(queuedConnWindowUpdate).To(BeTrue())
			})

			It("tells the connection flow controller when the window was autotuned", func() {
				oldOffset := controller.bytesRead
				controller.contributesToConnection = true
				setRtt(scaleDuration(20 * time.Millisecond))
				controller.epochStartOffset = oldOffset
				controller.epochStartTime = time.Now().Add(-time.Millisecond)
				controller.AddBytesRead(55)
				offset := controller.GetWindowUpdate()
				Expect(offset).To(Equal(protocol.ByteCount(oldOffset + 55 + 2*oldWindowSize)))
				Expect(controller.receiveWindowSize).To(Equal(2 * oldWindowSize))
				Expect(controller.connection.(*connectionFlowController).receiveWindowSize).To(Equal(protocol.ByteCount(float64(controller.receiveWindowSize) * protocol.ConnectionFlowControlMultiplier)))
			})

			It("doesn't tell the connection flow controller if it doesn't contribute", func() {
				oldOffset := controller.bytesRead
				controller.contributesToConnection = false
				setRtt(scaleDuration(20 * time.Millisecond))
				controller.epochStartOffset = oldOffset
				controller.epochStartTime = time.Now().Add(-time.Millisecond)
				controller.AddBytesRead(55)
				offset := controller.GetWindowUpdate()
				Expect(offset).ToNot(BeZero())
				Expect(controller.receiveWindowSize).To(Equal(2 * oldWindowSize))
				Expect(controller.connection.(*connectionFlowController).receiveWindowSize).To(Equal(protocol.ByteCount(2 * oldWindowSize))) // unchanged
			})

			It("doesn't increase the window after a final offset was already received", func() {
				controller.AddBytesRead(30)
				err := controller.UpdateHighestReceived(90, true)
				Expect(err).ToNot(HaveOccurred())
				controller.MaybeQueueWindowUpdate()
				Expect(queuedWindowUpdate).To(BeFalse())
				offset := controller.GetWindowUpdate()
				Expect(offset).To(BeZero())
			})
		})
	})

	Context("sending data", func() {
		It("gets the size of the send window", func() {
			controller.UpdateSendWindow(15)
			controller.AddBytesSent(5)
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(10)))
		})

		It("doesn't care about the connection-level window, if it doesn't contribute", func() {
			controller.UpdateSendWindow(15)
			controller.connection.UpdateSendWindow(1)
			controller.AddBytesSent(5)
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(10)))
		})

		It("makes sure that it doesn't overflow the connection-level window", func() {
			controller.contributesToConnection = true
			controller.connection.UpdateSendWindow(12)
			controller.UpdateSendWindow(20)
			controller.AddBytesSent(10)
			Expect(controller.SendWindowSize()).To(Equal(protocol.ByteCount(2)))
		})

		It("doesn't say that it's blocked, if only the connection is blocked", func() {
			controller.contributesToConnection = true
			controller.connection.UpdateSendWindow(50)
			controller.UpdateSendWindow(100)
			controller.AddBytesSent(50)
			blocked, _ := controller.connection.IsNewlyBlocked()
			Expect(blocked).To(BeTrue())
			Expect(controller.IsNewlyBlocked()).To(BeFalse())
		})
	})
})
