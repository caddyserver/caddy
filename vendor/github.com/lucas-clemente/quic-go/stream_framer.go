package quic

import (
	"sync"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type streamFramer struct {
	streamGetter streamGetter
	cryptoStream cryptoStreamI
	version      protocol.VersionNumber

	retransmissionQueue []*wire.StreamFrame

	streamQueueMutex    sync.Mutex
	activeStreams       map[protocol.StreamID]struct{}
	streamQueue         []protocol.StreamID
	hasCryptoStreamData bool
}

func newStreamFramer(
	cryptoStream cryptoStreamI,
	streamGetter streamGetter,
	v protocol.VersionNumber,
) *streamFramer {
	return &streamFramer{
		streamGetter:  streamGetter,
		cryptoStream:  cryptoStream,
		activeStreams: make(map[protocol.StreamID]struct{}),
		version:       v,
	}
}

func (f *streamFramer) AddFrameForRetransmission(frame *wire.StreamFrame) {
	f.retransmissionQueue = append(f.retransmissionQueue, frame)
}

func (f *streamFramer) AddActiveStream(id protocol.StreamID) {
	if id == f.version.CryptoStreamID() { // the crypto stream is handled separately
		f.streamQueueMutex.Lock()
		f.hasCryptoStreamData = true
		f.streamQueueMutex.Unlock()
		return
	}
	f.streamQueueMutex.Lock()
	if _, ok := f.activeStreams[id]; !ok {
		f.streamQueue = append(f.streamQueue, id)
		f.activeStreams[id] = struct{}{}
	}
	f.streamQueueMutex.Unlock()
}

func (f *streamFramer) PopStreamFrames(maxLen protocol.ByteCount) []*wire.StreamFrame {
	fs, currentLen := f.maybePopFramesForRetransmission(maxLen)
	return append(fs, f.maybePopNormalFrames(maxLen-currentLen)...)
}

func (f *streamFramer) HasFramesForRetransmission() bool {
	return len(f.retransmissionQueue) > 0
}

func (f *streamFramer) HasCryptoStreamData() bool {
	f.streamQueueMutex.Lock()
	hasCryptoStreamData := f.hasCryptoStreamData
	f.streamQueueMutex.Unlock()
	return hasCryptoStreamData
}

func (f *streamFramer) PopCryptoStreamFrame(maxLen protocol.ByteCount) *wire.StreamFrame {
	f.streamQueueMutex.Lock()
	frame, hasMoreData := f.cryptoStream.popStreamFrame(maxLen)
	f.hasCryptoStreamData = hasMoreData
	f.streamQueueMutex.Unlock()
	return frame
}

func (f *streamFramer) maybePopFramesForRetransmission(maxTotalLen protocol.ByteCount) (res []*wire.StreamFrame, currentLen protocol.ByteCount) {
	for len(f.retransmissionQueue) > 0 {
		frame := f.retransmissionQueue[0]
		frame.DataLenPresent = true

		frameHeaderLen := frame.MinLength(f.version) // can never error
		maxLen := maxTotalLen - currentLen
		if frameHeaderLen+frame.DataLen() > maxLen && maxLen < protocol.MinStreamFrameSize {
			break
		}

		splitFrame := maybeSplitOffFrame(frame, maxLen-frameHeaderLen)
		if splitFrame != nil { // StreamFrame was split
			res = append(res, splitFrame)
			currentLen += frameHeaderLen + splitFrame.DataLen()
			break
		}

		f.retransmissionQueue = f.retransmissionQueue[1:]
		res = append(res, frame)
		currentLen += frameHeaderLen + frame.DataLen()
	}
	return
}

func (f *streamFramer) maybePopNormalFrames(maxTotalLen protocol.ByteCount) []*wire.StreamFrame {
	var currentLen protocol.ByteCount
	var frames []*wire.StreamFrame
	f.streamQueueMutex.Lock()
	// pop STREAM frames, until less than MinStreamFrameSize bytes are left in the packet
	numActiveStreams := len(f.streamQueue)
	for i := 0; i < numActiveStreams; i++ {
		if maxTotalLen-currentLen < protocol.MinStreamFrameSize {
			break
		}
		id := f.streamQueue[0]
		f.streamQueue = f.streamQueue[1:]
		// This should never return an error. Better check it anyway.
		// The stream will only be in the streamQueue, if it enqueued itself there.
		str, err := f.streamGetter.GetOrOpenSendStream(id)
		// The stream can be nil if it completed after it said it had data.
		if str == nil || err != nil {
			delete(f.activeStreams, id)
			continue
		}
		frame, hasMoreData := str.popStreamFrame(maxTotalLen - currentLen)
		if hasMoreData { // put the stream back in the queue (at the end)
			f.streamQueue = append(f.streamQueue, id)
		} else { // no more data to send. Stream is not active any more
			delete(f.activeStreams, id)
		}
		if frame == nil { // can happen if the receiveStream was canceled after it said it had data
			continue
		}
		frames = append(frames, frame)
		currentLen += frame.MinLength(f.version) + frame.DataLen()
	}
	f.streamQueueMutex.Unlock()
	return frames
}

// maybeSplitOffFrame removes the first n bytes and returns them as a separate frame. If n >= len(frame), nil is returned and nothing is modified.
func maybeSplitOffFrame(frame *wire.StreamFrame, n protocol.ByteCount) *wire.StreamFrame {
	if n >= frame.DataLen() {
		return nil
	}

	defer func() {
		frame.Data = frame.Data[n:]
		frame.Offset += n
	}()

	return &wire.StreamFrame{
		FinBit:         false,
		StreamID:       frame.StreamID,
		Offset:         frame.Offset,
		Data:           frame.Data[:n],
		DataLenPresent: frame.DataLenPresent,
	}
}
