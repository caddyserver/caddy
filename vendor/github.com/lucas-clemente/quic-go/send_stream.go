package quic

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type sendStreamI interface {
	SendStream
	handleStopSendingFrame(*wire.StopSendingFrame)
	hasData() bool
	popStreamFrame(maxBytes protocol.ByteCount) (*wire.StreamFrame, bool)
	closeForShutdown(error)
	handleMaxStreamDataFrame(*wire.MaxStreamDataFrame)
}

type sendStream struct {
	mutex sync.Mutex

	ctx       context.Context
	ctxCancel context.CancelFunc

	streamID protocol.StreamID
	sender   streamSender

	writeOffset protocol.ByteCount

	cancelWriteErr      error
	closeForShutdownErr error

	closedForShutdown bool // set when CloseForShutdown() is called
	finishedWriting   bool // set once Close() is called
	canceledWrite     bool // set when CancelWrite() is called, or a STOP_SENDING frame is received
	finSent           bool // set when a STREAM_FRAME with FIN bit has b

	dataForWriting []byte

	writeChan chan struct{}
	deadline  time.Time

	flowController flowcontrol.StreamFlowController

	version protocol.VersionNumber
}

var _ SendStream = &sendStream{}
var _ sendStreamI = &sendStream{}

func newSendStream(
	streamID protocol.StreamID,
	sender streamSender,
	flowController flowcontrol.StreamFlowController,
	version protocol.VersionNumber,
) *sendStream {
	s := &sendStream{
		streamID:       streamID,
		sender:         sender,
		flowController: flowController,
		writeChan:      make(chan struct{}, 1),
		version:        version,
	}
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())
	return s
}

func (s *sendStream) StreamID() protocol.StreamID {
	return s.streamID // same for receiveStream and sendStream
}

func (s *sendStream) Write(p []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.finishedWriting {
		return 0, fmt.Errorf("write on closed stream %d", s.streamID)
	}
	if s.canceledWrite {
		return 0, s.cancelWriteErr
	}
	if s.closeForShutdownErr != nil {
		return 0, s.closeForShutdownErr
	}
	if !s.deadline.IsZero() && !time.Now().Before(s.deadline) {
		return 0, errDeadline
	}
	if len(p) == 0 {
		return 0, nil
	}

	s.dataForWriting = p

	var (
		deadlineTimer  *utils.Timer
		bytesWritten   int
		notifiedSender bool
	)
	for {
		bytesWritten = len(p) - len(s.dataForWriting)
		deadline := s.deadline
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				s.dataForWriting = nil
				return bytesWritten, errDeadline
			}
			if deadlineTimer == nil {
				deadlineTimer = utils.NewTimer()
			}
			deadlineTimer.Reset(deadline)
		}
		if s.dataForWriting == nil || s.canceledWrite || s.closedForShutdown {
			break
		}

		s.mutex.Unlock()
		if !notifiedSender {
			s.sender.onHasStreamData(s.streamID) // must be called without holding the mutex
			notifiedSender = true
		}
		if deadline.IsZero() {
			<-s.writeChan
		} else {
			select {
			case <-s.writeChan:
			case <-deadlineTimer.Chan():
				deadlineTimer.SetRead()
			}
		}
		s.mutex.Lock()
	}

	if s.closeForShutdownErr != nil {
		return bytesWritten, s.closeForShutdownErr
	} else if s.cancelWriteErr != nil {
		return bytesWritten, s.cancelWriteErr
	}
	return bytesWritten, nil
}

// popStreamFrame returns the next STREAM frame that is supposed to be sent on this stream
// maxBytes is the maximum length this frame (including frame header) will have.
func (s *sendStream) popStreamFrame(maxBytes protocol.ByteCount) (*wire.StreamFrame, bool /* has more data to send */) {
	completed, frame, hasMoreData := s.popStreamFrameImpl(maxBytes)
	if completed {
		s.sender.onStreamCompleted(s.streamID)
	}
	return frame, hasMoreData
}

func (s *sendStream) popStreamFrameImpl(maxBytes protocol.ByteCount) (bool /* completed */, *wire.StreamFrame, bool /* has more data to send */) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.closeForShutdownErr != nil {
		return false, nil, false
	}

	frame := &wire.StreamFrame{
		StreamID:       s.streamID,
		Offset:         s.writeOffset,
		DataLenPresent: true,
	}
	maxDataLen := frame.MaxDataLen(maxBytes, s.version)
	if maxDataLen == 0 { // a STREAM frame must have at least one byte of data
		return false, nil, s.dataForWriting != nil
	}
	frame.Data, frame.FinBit = s.getDataForWriting(maxDataLen)
	if len(frame.Data) == 0 && !frame.FinBit {
		// this can happen if:
		// - popStreamFrame is called but there's no data for writing
		// - there's data for writing, but the stream is stream-level flow control blocked
		// - there's data for writing, but the stream is connection-level flow control blocked
		if s.dataForWriting == nil {
			return false, nil, false
		}
		if isBlocked, offset := s.flowController.IsNewlyBlocked(); isBlocked {
			s.sender.queueControlFrame(&wire.StreamBlockedFrame{
				StreamID: s.streamID,
				Offset:   offset,
			})
			return false, nil, false
		}
		return false, nil, true
	}
	if frame.FinBit {
		s.finSent = true
	}
	return frame.FinBit, frame, s.dataForWriting != nil
}

func (s *sendStream) hasData() bool {
	s.mutex.Lock()
	hasData := len(s.dataForWriting) > 0
	s.mutex.Unlock()
	return hasData
}

func (s *sendStream) getDataForWriting(maxBytes protocol.ByteCount) ([]byte, bool /* should send FIN */) {
	if s.dataForWriting == nil {
		return nil, s.finishedWriting && !s.finSent
	}

	if s.streamID != s.version.CryptoStreamID() {
		maxBytes = utils.MinByteCount(maxBytes, s.flowController.SendWindowSize())
	}
	if maxBytes == 0 {
		return nil, false
	}

	var ret []byte
	if protocol.ByteCount(len(s.dataForWriting)) > maxBytes {
		ret = make([]byte, int(maxBytes))
		copy(ret, s.dataForWriting[:maxBytes])
		s.dataForWriting = s.dataForWriting[maxBytes:]
	} else {
		ret = make([]byte, len(s.dataForWriting))
		copy(ret, s.dataForWriting)
		s.dataForWriting = nil
		s.signalWrite()
	}
	s.writeOffset += protocol.ByteCount(len(ret))
	s.flowController.AddBytesSent(protocol.ByteCount(len(ret)))
	return ret, s.finishedWriting && s.dataForWriting == nil && !s.finSent
}

func (s *sendStream) Close() error {
	s.mutex.Lock()
	if s.canceledWrite {
		s.mutex.Unlock()
		return fmt.Errorf("Close called for canceled stream %d", s.streamID)
	}
	s.finishedWriting = true
	s.mutex.Unlock()

	s.sender.onHasStreamData(s.streamID) // need to send the FIN, must be called without holding the mutex
	s.ctxCancel()
	return nil
}

func (s *sendStream) CancelWrite(errorCode protocol.ApplicationErrorCode) error {
	s.mutex.Lock()
	completed, err := s.cancelWriteImpl(errorCode, fmt.Errorf("Write on stream %d canceled with error code %d", s.streamID, errorCode))
	s.mutex.Unlock()

	if completed {
		s.sender.onStreamCompleted(s.streamID) // must be called without holding the mutex
	}
	return err
}

// must be called after locking the mutex
func (s *sendStream) cancelWriteImpl(errorCode protocol.ApplicationErrorCode, writeErr error) (bool /*completed */, error) {
	if s.canceledWrite {
		return false, nil
	}
	if s.finishedWriting {
		return false, fmt.Errorf("CancelWrite for closed stream %d", s.streamID)
	}
	s.canceledWrite = true
	s.cancelWriteErr = writeErr
	s.signalWrite()
	s.sender.queueControlFrame(&wire.RstStreamFrame{
		StreamID:   s.streamID,
		ByteOffset: s.writeOffset,
		ErrorCode:  errorCode,
	})
	// TODO(#991): cancel retransmissions for this stream
	s.ctxCancel()
	return true, nil
}

func (s *sendStream) handleStopSendingFrame(frame *wire.StopSendingFrame) {
	if completed := s.handleStopSendingFrameImpl(frame); completed {
		s.sender.onStreamCompleted(s.streamID)
	}
}

func (s *sendStream) handleMaxStreamDataFrame(frame *wire.MaxStreamDataFrame) {
	s.mutex.Lock()
	hasStreamData := s.dataForWriting != nil
	s.mutex.Unlock()
	s.flowController.UpdateSendWindow(frame.ByteOffset)
	if hasStreamData {
		s.sender.onHasStreamData(s.streamID)
	}
}

// must be called after locking the mutex
func (s *sendStream) handleStopSendingFrameImpl(frame *wire.StopSendingFrame) bool /*completed*/ {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	writeErr := streamCanceledError{
		errorCode: frame.ErrorCode,
		error:     fmt.Errorf("Stream %d was reset with error code %d", s.streamID, frame.ErrorCode),
	}
	errorCode := errorCodeStopping
	if !s.version.UsesIETFFrameFormat() {
		errorCode = errorCodeStoppingGQUIC
	}
	completed, _ := s.cancelWriteImpl(errorCode, writeErr)
	return completed
}

func (s *sendStream) Context() context.Context {
	return s.ctx
}

func (s *sendStream) SetWriteDeadline(t time.Time) error {
	s.mutex.Lock()
	s.deadline = t
	s.mutex.Unlock()
	s.signalWrite()
	return nil
}

// CloseForShutdown closes a stream abruptly.
// It makes Write unblock (and return the error) immediately.
// The peer will NOT be informed about this: the stream is closed without sending a FIN or RST.
func (s *sendStream) closeForShutdown(err error) {
	s.mutex.Lock()
	s.closedForShutdown = true
	s.closeForShutdownErr = err
	s.mutex.Unlock()
	s.signalWrite()
	s.ctxCancel()
}

func (s *sendStream) getWriteOffset() protocol.ByteCount {
	return s.writeOffset
}

// signalWrite performs a non-blocking send on the writeChan
func (s *sendStream) signalWrite() {
	select {
	case s.writeChan <- struct{}{}:
	default:
	}
}
