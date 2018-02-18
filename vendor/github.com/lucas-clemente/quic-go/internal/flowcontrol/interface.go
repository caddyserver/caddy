package flowcontrol

import "github.com/lucas-clemente/quic-go/internal/protocol"

type flowController interface {
	// for sending
	SendWindowSize() protocol.ByteCount
	UpdateSendWindow(protocol.ByteCount)
	AddBytesSent(protocol.ByteCount)
	// for receiving
	AddBytesRead(protocol.ByteCount)
	GetWindowUpdate() protocol.ByteCount // returns 0 if no update is necessary
}

// A StreamFlowController is a flow controller for a QUIC stream.
type StreamFlowController interface {
	flowController
	// for sending
	IsBlocked() (bool, protocol.ByteCount)
	// for receiving
	// UpdateHighestReceived should be called when a new highest offset is received
	// final has to be to true if this is the final offset of the stream, as contained in a STREAM frame with FIN bit, and the RST_STREAM frame
	UpdateHighestReceived(offset protocol.ByteCount, final bool) error
	// HasWindowUpdate says if it is necessary to update the window
	HasWindowUpdate() bool
}

// The ConnectionFlowController is the flow controller for the connection.
type ConnectionFlowController interface {
	flowController
	// for sending
	IsNewlyBlocked() (bool, protocol.ByteCount)
}

type connectionFlowControllerI interface {
	ConnectionFlowController
	// The following two methods are not supposed to be called from outside this packet, but are needed internally
	// for sending
	EnsureMinimumWindowSize(protocol.ByteCount)
	// for receiving
	IncrementHighestReceived(protocol.ByteCount) error
}
