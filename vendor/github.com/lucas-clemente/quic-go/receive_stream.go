package quic

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/flowcontrol"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

type receiveStreamI interface {
	ReceiveStream

	handleStreamFrame(*wire.StreamFrame) error
	handleRstStreamFrame(*wire.RstStreamFrame) error
	closeForShutdown(error)
	getWindowUpdate() protocol.ByteCount
}

type receiveStream struct {
	mutex sync.Mutex

	streamID protocol.StreamID

	sender streamSender

	frameQueue     *streamFrameSorter
	readPosInFrame int
	readOffset     protocol.ByteCount

	closeForShutdownErr error
	cancelReadErr       error
	resetRemotelyErr    StreamError

	closedForShutdown bool // set when CloseForShutdown() is called
	finRead           bool // set once we read a frame with a FinBit
	canceledRead      bool // set when CancelRead() is called
	resetRemotely     bool // set when HandleRstStreamFrame() is called

	readChan     chan struct{}
	readDeadline time.Time

	flowController flowcontrol.StreamFlowController
	version        protocol.VersionNumber
}

var _ ReceiveStream = &receiveStream{}
var _ receiveStreamI = &receiveStream{}

func newReceiveStream(
	streamID protocol.StreamID,
	sender streamSender,
	flowController flowcontrol.StreamFlowController,
	version protocol.VersionNumber,
) *receiveStream {
	return &receiveStream{
		streamID:       streamID,
		sender:         sender,
		flowController: flowController,
		frameQueue:     newStreamFrameSorter(),
		readChan:       make(chan struct{}, 1),
		version:        version,
	}
}

func (s *receiveStream) StreamID() protocol.StreamID {
	return s.streamID
}

// Read implements io.Reader. It is not thread safe!
func (s *receiveStream) Read(p []byte) (int, error) {
	completed, n, err := s.readImpl(p)
	if completed {
		s.sender.onStreamCompleted(s.streamID)
	}
	return n, err
}

func (s *receiveStream) readImpl(p []byte) (bool /*stream completed */, int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.finRead {
		return false, 0, io.EOF
	}
	if s.canceledRead {
		return false, 0, s.cancelReadErr
	}
	if s.resetRemotely {
		return false, 0, s.resetRemotelyErr
	}
	if s.closedForShutdown {
		return false, 0, s.closeForShutdownErr
	}

	bytesRead := 0
	for bytesRead < len(p) {
		frame := s.frameQueue.Head()
		if frame == nil && bytesRead > 0 {
			return false, bytesRead, s.closeForShutdownErr
		}

		for {
			// Stop waiting on errors
			if s.closedForShutdown {
				return false, bytesRead, s.closeForShutdownErr
			}
			if s.canceledRead {
				return false, bytesRead, s.cancelReadErr
			}
			if s.resetRemotely {
				return false, bytesRead, s.resetRemotelyErr
			}

			deadline := s.readDeadline
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				return false, bytesRead, errDeadline
			}

			if frame != nil {
				s.readPosInFrame = int(s.readOffset - frame.Offset)
				break
			}

			s.mutex.Unlock()
			if deadline.IsZero() {
				<-s.readChan
			} else {
				select {
				case <-s.readChan:
				case <-time.After(time.Until(deadline)):
				}
			}
			s.mutex.Lock()
			frame = s.frameQueue.Head()
		}

		if bytesRead > len(p) {
			return false, bytesRead, fmt.Errorf("BUG: bytesRead (%d) > len(p) (%d) in stream.Read", bytesRead, len(p))
		}
		if s.readPosInFrame > int(frame.DataLen()) {
			return false, bytesRead, fmt.Errorf("BUG: readPosInFrame (%d) > frame.DataLen (%d) in stream.Read", s.readPosInFrame, frame.DataLen())
		}

		s.mutex.Unlock()

		copy(p[bytesRead:], frame.Data[s.readPosInFrame:])
		m := utils.Min(len(p)-bytesRead, int(frame.DataLen())-s.readPosInFrame)
		s.readPosInFrame += m
		bytesRead += m
		s.readOffset += protocol.ByteCount(m)

		s.mutex.Lock()
		// when a RST_STREAM was received, the was already informed about the final byteOffset for this stream
		if !s.resetRemotely {
			s.flowController.AddBytesRead(protocol.ByteCount(m))
		}
		// increase the flow control window, if necessary
		s.flowController.MaybeQueueWindowUpdate()

		if s.readPosInFrame >= int(frame.DataLen()) {
			s.frameQueue.Pop()
			s.finRead = frame.FinBit
			if frame.FinBit {
				return true, bytesRead, io.EOF
			}
		}
	}
	return false, bytesRead, nil
}

func (s *receiveStream) CancelRead(errorCode protocol.ApplicationErrorCode) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.finRead {
		return nil
	}
	if s.canceledRead {
		return nil
	}
	s.canceledRead = true
	s.cancelReadErr = fmt.Errorf("Read on stream %d canceled with error code %d", s.streamID, errorCode)
	s.signalRead()
	if s.version.UsesIETFFrameFormat() {
		s.sender.queueControlFrame(&wire.StopSendingFrame{
			StreamID:  s.streamID,
			ErrorCode: errorCode,
		})
	}
	return nil
}

func (s *receiveStream) handleStreamFrame(frame *wire.StreamFrame) error {
	maxOffset := frame.Offset + frame.DataLen()
	if err := s.flowController.UpdateHighestReceived(maxOffset, frame.FinBit); err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.frameQueue.Push(frame); err != nil && err != errDuplicateStreamData {
		return err
	}
	s.signalRead()
	return nil
}

func (s *receiveStream) handleRstStreamFrame(frame *wire.RstStreamFrame) error {
	completed, err := s.handleRstStreamFrameImpl(frame)
	if completed {
		s.sender.onStreamCompleted(s.streamID)
	}
	return err
}

func (s *receiveStream) handleRstStreamFrameImpl(frame *wire.RstStreamFrame) (bool /*completed */, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.closedForShutdown {
		return false, nil
	}
	if err := s.flowController.UpdateHighestReceived(frame.ByteOffset, true); err != nil {
		return false, err
	}
	// In gQUIC, error code 0 has a special meaning.
	// The peer will reliably continue transmitting, but is not interested in reading from the stream.
	// We should therefore just continue reading from the stream, until we encounter the FIN bit.
	if !s.version.UsesIETFFrameFormat() && frame.ErrorCode == 0 {
		return false, nil
	}

	// ignore duplicate RST_STREAM frames for this stream (after checking their final offset)
	if s.resetRemotely {
		return false, nil
	}
	s.resetRemotely = true
	s.resetRemotelyErr = streamCanceledError{
		errorCode: frame.ErrorCode,
		error:     fmt.Errorf("Stream %d was reset with error code %d", s.streamID, frame.ErrorCode),
	}
	s.signalRead()
	return true, nil
}

func (s *receiveStream) CloseRemote(offset protocol.ByteCount) {
	s.handleStreamFrame(&wire.StreamFrame{FinBit: true, Offset: offset})
}

func (s *receiveStream) onClose(offset protocol.ByteCount) {
	if s.canceledRead && !s.version.UsesIETFFrameFormat() {
		s.sender.queueControlFrame(&wire.RstStreamFrame{
			StreamID:   s.streamID,
			ByteOffset: offset,
			ErrorCode:  0,
		})
	}
}

func (s *receiveStream) SetReadDeadline(t time.Time) error {
	s.mutex.Lock()
	oldDeadline := s.readDeadline
	s.readDeadline = t
	s.mutex.Unlock()
	// if the new deadline is before the currently set deadline, wake up Read()
	if t.Before(oldDeadline) {
		s.signalRead()
	}
	return nil
}

// CloseForShutdown closes a stream abruptly.
// It makes Read unblock (and return the error) immediately.
// The peer will NOT be informed about this: the stream is closed without sending a FIN or RST.
func (s *receiveStream) closeForShutdown(err error) {
	s.mutex.Lock()
	s.closedForShutdown = true
	s.closeForShutdownErr = err
	s.mutex.Unlock()
	s.signalRead()
}

func (s *receiveStream) getWindowUpdate() protocol.ByteCount {
	return s.flowController.GetWindowUpdate()
}

// signalRead performs a non-blocking send on the readChan
func (s *receiveStream) signalRead() {
	select {
	case s.readChan <- struct{}{}:
	default:
	}
}
