package wire

import (
	"bytes"
	"log"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Frame logging", func() {
	var (
		buf    *bytes.Buffer
		logger utils.Logger
	)

	BeforeEach(func() {
		buf = &bytes.Buffer{}
		logger = utils.DefaultLogger
		logger.SetLogLevel(utils.LogLevelDebug)
		log.SetOutput(buf)
	})

	AfterEach(func() {
		log.SetOutput(os.Stdout)
	})

	It("doesn't log when debug is disabled", func() {
		logger.SetLogLevel(utils.LogLevelInfo)
		LogFrame(logger, &RstStreamFrame{}, true)
		Expect(buf.Len()).To(BeZero())
	})

	It("logs sent frames", func() {
		LogFrame(logger, &RstStreamFrame{}, true)
		Expect(buf.Bytes()).To(ContainSubstring("\t-> &wire.RstStreamFrame{StreamID:0x0, ErrorCode:0x0, ByteOffset:0x0}\n"))
	})

	It("logs received frames", func() {
		LogFrame(logger, &RstStreamFrame{}, false)
		Expect(buf.Bytes()).To(ContainSubstring("\t<- &wire.RstStreamFrame{StreamID:0x0, ErrorCode:0x0, ByteOffset:0x0}\n"))
	})

	It("logs stream frames", func() {
		frame := &StreamFrame{
			StreamID: 42,
			Offset:   0x1337,
			Data:     bytes.Repeat([]byte{'f'}, 0x100),
		}
		LogFrame(logger, frame, false)
		Expect(buf.Bytes()).To(ContainSubstring("\t<- &wire.StreamFrame{StreamID: 42, FinBit: false, Offset: 0x1337, Data length: 0x100, Offset + Data length: 0x1437}\n"))
	})

	It("logs ACK frames without missing packets", func() {
		frame := &AckFrame{
			AckRanges: []AckRange{{Smallest: 0x42, Largest: 0x1337}},
			DelayTime: 1 * time.Millisecond,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.AckFrame{LargestAcked: 0x1337, LowestAcked: 0x42, DelayTime: 1ms}\n"))
	})

	It("logs ACK frames with missing packets", func() {
		frame := &AckFrame{
			AckRanges: []AckRange{
				{Smallest: 0x5, Largest: 0x8},
				{Smallest: 0x2, Largest: 0x3},
			},
			DelayTime: 12 * time.Millisecond,
		}
		LogFrame(logger, frame, false)
		Expect(buf.String()).To(ContainSubstring("\t<- &wire.AckFrame{LargestAcked: 0x8, LowestAcked: 0x2, AckRanges: {{Largest: 0x8, Smallest: 0x5}, {Largest: 0x3, Smallest: 0x2}}, DelayTime: 12ms}\n"))
	})

	It("logs incoming StopWaiting frames", func() {
		frame := &StopWaitingFrame{
			LeastUnacked: 0x1337,
		}
		LogFrame(logger, frame, false)
		Expect(buf.Bytes()).To(ContainSubstring("\t<- &wire.StopWaitingFrame{LeastUnacked: 0x1337}\n"))
	})

	It("logs outgoing StopWaiting frames", func() {
		frame := &StopWaitingFrame{
			LeastUnacked:    0x1337,
			PacketNumberLen: protocol.PacketNumberLen4,
		}
		LogFrame(logger, frame, true)
		Expect(buf.Bytes()).To(ContainSubstring("\t-> &wire.StopWaitingFrame{LeastUnacked: 0x1337, PacketNumberLen: 0x4}\n"))
	})
})
