package quic

import (
	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
)

type streamFramer struct {
	streamsMap *streamsMap

	flowControlManager flowcontrol.FlowControlManager

	retransmissionQueue []*frames.StreamFrame
	blockedFrameQueue   []*frames.BlockedFrame
}

func newStreamFramer(streamsMap *streamsMap, flowControlManager flowcontrol.FlowControlManager) *streamFramer {
	return &streamFramer{
		streamsMap:         streamsMap,
		flowControlManager: flowControlManager,
	}
}

func (f *streamFramer) AddFrameForRetransmission(frame *frames.StreamFrame) {
	f.retransmissionQueue = append(f.retransmissionQueue, frame)
}

func (f *streamFramer) PopStreamFrames(maxLen protocol.ByteCount) []*frames.StreamFrame {
	fs, currentLen := f.maybePopFramesForRetransmission(maxLen)
	return append(fs, f.maybePopNormalFrames(maxLen-currentLen)...)
}

func (f *streamFramer) PopBlockedFrame() *frames.BlockedFrame {
	if len(f.blockedFrameQueue) == 0 {
		return nil
	}
	frame := f.blockedFrameQueue[0]
	f.blockedFrameQueue = f.blockedFrameQueue[1:]
	return frame
}

func (f *streamFramer) HasFramesForRetransmission() bool {
	return len(f.retransmissionQueue) > 0
}

func (f *streamFramer) HasCryptoStreamFrame() bool {
	// TODO(#657): Flow control
	cs, _ := f.streamsMap.GetOrOpenStream(1)
	return cs.lenOfDataForWriting() > 0
}

// TODO(lclemente): This is somewhat duplicate with the normal path for generating frames.
// TODO(#657): Flow control
func (f *streamFramer) PopCryptoStreamFrame(maxLen protocol.ByteCount) *frames.StreamFrame {
	if !f.HasCryptoStreamFrame() {
		return nil
	}
	cs, _ := f.streamsMap.GetOrOpenStream(1)
	frame := &frames.StreamFrame{
		StreamID: 1,
		Offset:   cs.writeOffset,
	}
	frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
	frame.Data = cs.getDataForWriting(maxLen - frameHeaderBytes)
	return frame
}

func (f *streamFramer) maybePopFramesForRetransmission(maxLen protocol.ByteCount) (res []*frames.StreamFrame, currentLen protocol.ByteCount) {
	for len(f.retransmissionQueue) > 0 {
		frame := f.retransmissionQueue[0]
		frame.DataLenPresent = true

		frameHeaderLen, _ := frame.MinLength(protocol.VersionWhatever) // can never error
		if currentLen+frameHeaderLen >= maxLen {
			break
		}

		currentLen += frameHeaderLen

		splitFrame := maybeSplitOffFrame(frame, maxLen-currentLen)
		if splitFrame != nil { // StreamFrame was split
			res = append(res, splitFrame)
			currentLen += splitFrame.DataLen()
			break
		}

		f.retransmissionQueue = f.retransmissionQueue[1:]
		res = append(res, frame)
		currentLen += frame.DataLen()
	}
	return
}

func (f *streamFramer) maybePopNormalFrames(maxBytes protocol.ByteCount) (res []*frames.StreamFrame) {
	frame := &frames.StreamFrame{DataLenPresent: true}
	var currentLen protocol.ByteCount

	fn := func(s *stream) (bool, error) {
		if s == nil || s.streamID == 1 /* crypto stream is handled separately */ {
			return true, nil
		}

		frame.StreamID = s.streamID
		// not perfect, but thread-safe since writeOffset is only written when getting data
		frame.Offset = s.writeOffset
		frameHeaderBytes, _ := frame.MinLength(protocol.VersionWhatever) // can never error
		if currentLen+frameHeaderBytes > maxBytes {
			return false, nil // theoretically, we could find another stream that fits, but this is quite unlikely, so we stop here
		}
		maxLen := maxBytes - currentLen - frameHeaderBytes

		var sendWindowSize protocol.ByteCount
		lenStreamData := s.lenOfDataForWriting()
		if lenStreamData != 0 {
			sendWindowSize, _ = f.flowControlManager.SendWindowSize(s.streamID)
			maxLen = utils.MinByteCount(maxLen, sendWindowSize)
		}

		if maxLen == 0 {
			return true, nil
		}

		var data []byte
		if lenStreamData != 0 {
			// Only getDataForWriting() if we didn't have data earlier, so that we
			// don't send without FC approval (if a Write() raced).
			data = s.getDataForWriting(maxLen)
		}

		// This is unlikely, but check it nonetheless, the scheduler might have jumped in. Seems to happen in ~20% of cases in the tests.
		shouldSendFin := s.shouldSendFin()
		if data == nil && !shouldSendFin {
			return true, nil
		}

		if shouldSendFin {
			frame.FinBit = true
			s.sentFin()
		}

		frame.Data = data
		f.flowControlManager.AddBytesSent(s.streamID, protocol.ByteCount(len(data)))

		// Finally, check if we are now FC blocked and should queue a BLOCKED frame
		if f.flowControlManager.RemainingConnectionWindowSize() == 0 {
			// We are now connection-level FC blocked
			f.blockedFrameQueue = append(f.blockedFrameQueue, &frames.BlockedFrame{StreamID: 0})
		} else if !frame.FinBit && sendWindowSize-frame.DataLen() == 0 {
			// We are now stream-level FC blocked
			f.blockedFrameQueue = append(f.blockedFrameQueue, &frames.BlockedFrame{StreamID: s.StreamID()})
		}

		res = append(res, frame)
		currentLen += frameHeaderBytes + frame.DataLen()

		if currentLen == maxBytes {
			return false, nil
		}

		frame = &frames.StreamFrame{DataLenPresent: true}
		return true, nil
	}

	f.streamsMap.RoundRobinIterate(fn)

	return
}

// maybeSplitOffFrame removes the first n bytes and returns them as a separate frame. If n >= len(frame), nil is returned and nothing is modified.
func maybeSplitOffFrame(frame *frames.StreamFrame, n protocol.ByteCount) *frames.StreamFrame {
	if n >= frame.DataLen() {
		return nil
	}

	defer func() {
		frame.Data = frame.Data[n:]
		frame.Offset += n
	}()

	return &frames.StreamFrame{
		FinBit:         false,
		StreamID:       frame.StreamID,
		Offset:         frame.Offset,
		Data:           frame.Data[:n],
		DataLenPresent: frame.DataLenPresent,
	}
}
