package flowcontrol

import (
	"errors"
	"fmt"
	"sync"

	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

type flowControlManager struct {
	connectionParameters handshake.ConnectionParametersManager
	rttStats             *congestion.RTTStats

	streamFlowController map[protocol.StreamID]*flowController
	connFlowController   *flowController
	mutex                sync.RWMutex
}

var _ FlowControlManager = &flowControlManager{}

var errMapAccess = errors.New("Error accessing the flowController map.")

// NewFlowControlManager creates a new flow control manager
func NewFlowControlManager(connectionParameters handshake.ConnectionParametersManager, rttStats *congestion.RTTStats) FlowControlManager {
	return &flowControlManager{
		connectionParameters: connectionParameters,
		rttStats:             rttStats,
		streamFlowController: make(map[protocol.StreamID]*flowController),
		connFlowController:   newFlowController(0, false, connectionParameters, rttStats),
	}
}

// NewStream creates new flow controllers for a stream
// it does nothing if the stream already exists
func (f *flowControlManager) NewStream(streamID protocol.StreamID, contributesToConnection bool) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if _, ok := f.streamFlowController[streamID]; ok {
		return
	}

	f.streamFlowController[streamID] = newFlowController(streamID, contributesToConnection, f.connectionParameters, f.rttStats)
}

// RemoveStream removes a closed stream from flow control
func (f *flowControlManager) RemoveStream(streamID protocol.StreamID) {
	f.mutex.Lock()
	delete(f.streamFlowController, streamID)
	f.mutex.Unlock()
}

// ResetStream should be called when receiving a RstStreamFrame
// it updates the byte offset to the value in the RstStreamFrame
// streamID must not be 0 here
func (f *flowControlManager) ResetStream(streamID protocol.StreamID, byteOffset protocol.ByteCount) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	streamFlowController, err := f.getFlowController(streamID)
	if err != nil {
		return err
	}
	increment, err := streamFlowController.UpdateHighestReceived(byteOffset)
	if err != nil {
		return qerr.StreamDataAfterTermination
	}

	if streamFlowController.CheckFlowControlViolation() {
		return qerr.Error(qerr.FlowControlReceivedTooMuchData, fmt.Sprintf("Received %d bytes on stream %d, allowed %d bytes", byteOffset, streamID, streamFlowController.receiveWindow))
	}

	if streamFlowController.ContributesToConnection() {
		f.connFlowController.IncrementHighestReceived(increment)
		if f.connFlowController.CheckFlowControlViolation() {
			return qerr.Error(qerr.FlowControlReceivedTooMuchData, fmt.Sprintf("Received %d bytes for the connection, allowed %d bytes", f.connFlowController.highestReceived, f.connFlowController.receiveWindow))
		}
	}

	return nil
}

// UpdateHighestReceived updates the highest received byte offset for a stream
// it adds the number of additional bytes to connection level flow control
// streamID must not be 0 here
func (f *flowControlManager) UpdateHighestReceived(streamID protocol.StreamID, byteOffset protocol.ByteCount) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	streamFlowController, err := f.getFlowController(streamID)
	if err != nil {
		return err
	}
	// UpdateHighestReceived returns an ErrReceivedSmallerByteOffset when StreamFrames got reordered
	// this error can be ignored here
	increment, _ := streamFlowController.UpdateHighestReceived(byteOffset)

	if streamFlowController.CheckFlowControlViolation() {
		return qerr.Error(qerr.FlowControlReceivedTooMuchData, fmt.Sprintf("Received %d bytes on stream %d, allowed %d bytes", byteOffset, streamID, streamFlowController.receiveWindow))
	}

	if streamFlowController.ContributesToConnection() {
		f.connFlowController.IncrementHighestReceived(increment)
		if f.connFlowController.CheckFlowControlViolation() {
			return qerr.Error(qerr.FlowControlReceivedTooMuchData, fmt.Sprintf("Received %d bytes for the connection, allowed %d bytes", f.connFlowController.highestReceived, f.connFlowController.receiveWindow))
		}
	}

	return nil
}

// streamID must not be 0 here
func (f *flowControlManager) AddBytesRead(streamID protocol.StreamID, n protocol.ByteCount) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	fc, err := f.getFlowController(streamID)
	if err != nil {
		return err
	}

	fc.AddBytesRead(n)
	if fc.ContributesToConnection() {
		f.connFlowController.AddBytesRead(n)
	}

	return nil
}

func (f *flowControlManager) GetWindowUpdates() (res []WindowUpdate) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// get WindowUpdates for streams
	for id, fc := range f.streamFlowController {
		if necessary, newIncrement, offset := fc.MaybeUpdateWindow(); necessary {
			res = append(res, WindowUpdate{StreamID: id, Offset: offset})
			if fc.ContributesToConnection() && newIncrement != 0 {
				f.connFlowController.EnsureMinimumWindowIncrement(protocol.ByteCount(float64(newIncrement) * protocol.ConnectionFlowControlMultiplier))
			}
		}
	}
	// get a WindowUpdate for the connection
	if necessary, _, offset := f.connFlowController.MaybeUpdateWindow(); necessary {
		res = append(res, WindowUpdate{StreamID: 0, Offset: offset})
	}

	return
}

func (f *flowControlManager) GetReceiveWindow(streamID protocol.StreamID) (protocol.ByteCount, error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	// StreamID can be 0 when retransmitting
	if streamID == 0 {
		return f.connFlowController.receiveWindow, nil
	}

	flowController, err := f.getFlowController(streamID)
	if err != nil {
		return 0, err
	}
	return flowController.receiveWindow, nil
}

// streamID must not be 0 here
func (f *flowControlManager) AddBytesSent(streamID protocol.StreamID, n protocol.ByteCount) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	fc, err := f.getFlowController(streamID)
	if err != nil {
		return err
	}

	fc.AddBytesSent(n)
	if fc.ContributesToConnection() {
		f.connFlowController.AddBytesSent(n)
	}

	return nil
}

// must not be called with StreamID 0
func (f *flowControlManager) SendWindowSize(streamID protocol.StreamID) (protocol.ByteCount, error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	fc, err := f.getFlowController(streamID)
	if err != nil {
		return 0, err
	}
	res := fc.SendWindowSize()

	if fc.ContributesToConnection() {
		res = utils.MinByteCount(res, f.connFlowController.SendWindowSize())
	}

	return res, nil
}

func (f *flowControlManager) RemainingConnectionWindowSize() protocol.ByteCount {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	return f.connFlowController.SendWindowSize()
}

// streamID may be 0 here
func (f *flowControlManager) UpdateWindow(streamID protocol.StreamID, offset protocol.ByteCount) (bool, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	var fc *flowController
	if streamID == 0 {
		fc = f.connFlowController
	} else {
		var err error
		fc, err = f.getFlowController(streamID)
		if err != nil {
			return false, err
		}
	}

	return fc.UpdateSendWindow(offset), nil
}

func (f *flowControlManager) getFlowController(streamID protocol.StreamID) (*flowController, error) {
	streamFlowController, ok := f.streamFlowController[streamID]
	if !ok {
		return nil, errMapAccess
	}
	return streamFlowController, nil
}
