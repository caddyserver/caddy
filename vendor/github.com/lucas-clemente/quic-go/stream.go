package quic

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/flowcontrol"
	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
)

// A Stream assembles the data from StreamFrames and provides a super-convenient Read-Interface
//
// Read() and Write() may be called concurrently, but multiple calls to Read() or Write() individually must be synchronized manually.
type stream struct {
	mutex sync.Mutex

	streamID protocol.StreamID
	onData   func()
	// onReset is a callback that should send a RST_STREAM
	onReset func(protocol.StreamID, protocol.ByteCount)

	readPosInFrame int
	writeOffset    protocol.ByteCount
	readOffset     protocol.ByteCount

	// Once set, the errors must not be changed!
	err error

	// cancelled is set when Cancel() is called
	cancelled utils.AtomicBool
	// finishedReading is set once we read a frame with a FinBit
	finishedReading utils.AtomicBool
	// finisedWriting is set once Close() is called
	finishedWriting utils.AtomicBool
	// resetLocally is set if Reset() is called
	resetLocally utils.AtomicBool
	// resetRemotely is set if RegisterRemoteError() is called
	resetRemotely utils.AtomicBool

	frameQueue   *streamFrameSorter
	readChan     chan struct{}
	readDeadline time.Time

	dataForWriting []byte
	finSent        utils.AtomicBool
	rstSent        utils.AtomicBool
	writeChan      chan struct{}
	writeDeadline  time.Time

	flowControlManager flowcontrol.FlowControlManager
}

type deadlineError struct{}

func (deadlineError) Error() string   { return "deadline exceeded" }
func (deadlineError) Temporary() bool { return true }
func (deadlineError) Timeout() bool   { return true }

var errDeadline net.Error = &deadlineError{}

// newStream creates a new Stream
func newStream(StreamID protocol.StreamID,
	onData func(),
	onReset func(protocol.StreamID, protocol.ByteCount),
	flowControlManager flowcontrol.FlowControlManager) *stream {
	return &stream{
		onData:             onData,
		onReset:            onReset,
		streamID:           StreamID,
		flowControlManager: flowControlManager,
		frameQueue:         newStreamFrameSorter(),
		readChan:           make(chan struct{}, 1),
		writeChan:          make(chan struct{}, 1),
	}
}

// Read implements io.Reader. It is not thread safe!
func (s *stream) Read(p []byte) (int, error) {
	s.mutex.Lock()
	err := s.err
	s.mutex.Unlock()
	if s.cancelled.Get() || s.resetLocally.Get() {
		return 0, err
	}
	if s.finishedReading.Get() {
		return 0, io.EOF
	}

	bytesRead := 0
	for bytesRead < len(p) {
		s.mutex.Lock()
		frame := s.frameQueue.Head()
		if frame == nil && bytesRead > 0 {
			err = s.err
			s.mutex.Unlock()
			return bytesRead, err
		}

		var err error
		for {
			// Stop waiting on errors
			if s.resetLocally.Get() || s.cancelled.Get() {
				err = s.err
				break
			}

			deadline := s.readDeadline
			if !deadline.IsZero() && !time.Now().Before(deadline) {
				err = errDeadline
				break
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
				case <-time.After(deadline.Sub(time.Now())):
				}
			}
			s.mutex.Lock()
			frame = s.frameQueue.Head()
		}
		s.mutex.Unlock()

		if err != nil {
			return bytesRead, err
		}

		m := utils.Min(len(p)-bytesRead, int(frame.DataLen())-s.readPosInFrame)

		if bytesRead > len(p) {
			return bytesRead, fmt.Errorf("BUG: bytesRead (%d) > len(p) (%d) in stream.Read", bytesRead, len(p))
		}
		if s.readPosInFrame > int(frame.DataLen()) {
			return bytesRead, fmt.Errorf("BUG: readPosInFrame (%d) > frame.DataLen (%d) in stream.Read", s.readPosInFrame, frame.DataLen())
		}
		copy(p[bytesRead:], frame.Data[s.readPosInFrame:])

		s.readPosInFrame += m
		bytesRead += m
		s.readOffset += protocol.ByteCount(m)

		// when a RST_STREAM was received, the was already informed about the final byteOffset for this stream
		if !s.resetRemotely.Get() {
			s.flowControlManager.AddBytesRead(s.streamID, protocol.ByteCount(m))
		}
		s.onData() // so that a possible WINDOW_UPDATE is sent

		if s.readPosInFrame >= int(frame.DataLen()) {
			fin := frame.FinBit
			s.mutex.Lock()
			s.frameQueue.Pop()
			s.mutex.Unlock()
			if fin {
				s.finishedReading.Set(true)
				return bytesRead, io.EOF
			}
		}
	}

	return bytesRead, nil
}

func (s *stream) Write(p []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resetLocally.Get() || s.err != nil {
		return 0, s.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	s.dataForWriting = make([]byte, len(p))
	copy(s.dataForWriting, p)
	s.onData()

	var err error
	for {
		deadline := s.writeDeadline
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			err = errDeadline
			break
		}
		if s.dataForWriting == nil || s.err != nil {
			break
		}

		s.mutex.Unlock()
		if deadline.IsZero() {
			<-s.writeChan
		} else {
			select {
			case <-s.writeChan:
			case <-time.After(deadline.Sub(time.Now())):
			}
		}
		s.mutex.Lock()
	}

	if err != nil {
		return 0, err
	}
	if s.err != nil {
		return len(p) - len(s.dataForWriting), s.err
	}
	return len(p), nil
}

func (s *stream) lenOfDataForWriting() protocol.ByteCount {
	s.mutex.Lock()
	var l protocol.ByteCount
	if s.err == nil {
		l = protocol.ByteCount(len(s.dataForWriting))
	}
	s.mutex.Unlock()
	return l
}

func (s *stream) getDataForWriting(maxBytes protocol.ByteCount) []byte {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.err != nil || s.dataForWriting == nil {
		return nil
	}

	var ret []byte
	if protocol.ByteCount(len(s.dataForWriting)) > maxBytes {
		ret = s.dataForWriting[:maxBytes]
		s.dataForWriting = s.dataForWriting[maxBytes:]
	} else {
		ret = s.dataForWriting
		s.dataForWriting = nil
		s.signalWrite()
	}
	s.writeOffset += protocol.ByteCount(len(ret))
	return ret
}

// Close implements io.Closer
func (s *stream) Close() error {
	s.finishedWriting.Set(true)
	s.onData()
	return nil
}

func (s *stream) shouldSendReset() bool {
	if s.rstSent.Get() {
		return false
	}
	return (s.resetLocally.Get() || s.resetRemotely.Get()) && !s.finishedWriteAndSentFin()
}

func (s *stream) shouldSendFin() bool {
	s.mutex.Lock()
	res := s.finishedWriting.Get() && !s.finSent.Get() && s.err == nil && s.dataForWriting == nil
	s.mutex.Unlock()
	return res
}

func (s *stream) sentFin() {
	s.finSent.Set(true)
}

// AddStreamFrame adds a new stream frame
func (s *stream) AddStreamFrame(frame *frames.StreamFrame) error {
	maxOffset := frame.Offset + frame.DataLen()
	err := s.flowControlManager.UpdateHighestReceived(s.streamID, maxOffset)
	if err != nil {
		return err
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	err = s.frameQueue.Push(frame)
	if err != nil && err != errDuplicateStreamData {
		return err
	}
	s.signalRead()
	return nil
}

// signalRead performs a non-blocking send on the readChan
func (s *stream) signalRead() {
	select {
	case s.readChan <- struct{}{}:
	default:
	}
}

// signalRead performs a non-blocking send on the writeChan
func (s *stream) signalWrite() {
	select {
	case s.writeChan <- struct{}{}:
	default:
	}
}

func (s *stream) SetReadDeadline(t time.Time) error {
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

func (s *stream) SetWriteDeadline(t time.Time) error {
	s.mutex.Lock()
	oldDeadline := s.writeDeadline
	s.writeDeadline = t
	s.mutex.Unlock()
	if t.Before(oldDeadline) {
		s.signalWrite()
	}
	return nil
}

func (s *stream) SetDeadline(t time.Time) error {
	_ = s.SetReadDeadline(t)  // SetReadDeadline never errors
	_ = s.SetWriteDeadline(t) // SetWriteDeadline never errors
	return nil
}

// CloseRemote makes the stream receive a "virtual" FIN stream frame at a given offset
func (s *stream) CloseRemote(offset protocol.ByteCount) {
	s.AddStreamFrame(&frames.StreamFrame{FinBit: true, Offset: offset})
}

// Cancel is called by session to indicate that an error occurred
// The stream should will be closed immediately
func (s *stream) Cancel(err error) {
	s.mutex.Lock()
	s.cancelled.Set(true)
	// errors must not be changed!
	if s.err == nil {
		s.err = err
		s.signalRead()
		s.signalWrite()
	}
	s.mutex.Unlock()
}

// resets the stream locally
func (s *stream) Reset(err error) {
	if s.resetLocally.Get() {
		return
	}
	s.mutex.Lock()
	s.resetLocally.Set(true)
	// errors must not be changed!
	if s.err == nil {
		s.err = err
		s.signalRead()
		s.signalWrite()
	}
	if s.shouldSendReset() {
		s.onReset(s.streamID, s.writeOffset)
		s.rstSent.Set(true)
	}
	s.mutex.Unlock()
}

// resets the stream remotely
func (s *stream) RegisterRemoteError(err error) {
	if s.resetRemotely.Get() {
		return
	}
	s.mutex.Lock()
	s.resetRemotely.Set(true)
	// errors must not be changed!
	if s.err == nil {
		s.err = err
		s.signalWrite()
	}
	if s.shouldSendReset() {
		s.onReset(s.streamID, s.writeOffset)
		s.rstSent.Set(true)
	}
	s.mutex.Unlock()
}

func (s *stream) finishedWriteAndSentFin() bool {
	return s.finishedWriting.Get() && s.finSent.Get()
}

func (s *stream) finished() bool {
	return s.cancelled.Get() ||
		(s.finishedReading.Get() && s.finishedWriteAndSentFin()) ||
		(s.resetRemotely.Get() && s.rstSent.Get()) ||
		(s.finishedReading.Get() && s.rstSent.Get()) ||
		(s.finishedWriteAndSentFin() && s.resetRemotely.Get())
}

func (s *stream) StreamID() protocol.StreamID {
	return s.streamID
}
