package handshake

import (
	"bytes"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
)

// ConnectionParametersManager negotiates and stores the connection parameters
// A ConnectionParametersManager can be used for a server as well as a client
// For the server:
// 1. call SetFromMap with the values received in the CHLO. This sets the corresponding values here, subject to negotiation
// 2. call GetHelloMap to get the values to send in the SHLO
// For the client:
// 1. call GetHelloMap to get the values to send in a CHLO
// 2. call SetFromMap with the values received in the SHLO
type ConnectionParametersManager interface {
	SetFromMap(map[Tag][]byte) error
	GetHelloMap() (map[Tag][]byte, error)

	GetSendStreamFlowControlWindow() protocol.ByteCount
	GetSendConnectionFlowControlWindow() protocol.ByteCount
	GetReceiveStreamFlowControlWindow() protocol.ByteCount
	GetMaxReceiveStreamFlowControlWindow() protocol.ByteCount
	GetReceiveConnectionFlowControlWindow() protocol.ByteCount
	GetMaxReceiveConnectionFlowControlWindow() protocol.ByteCount
	GetMaxOutgoingStreams() uint32
	GetMaxIncomingStreams() uint32
	GetIdleConnectionStateLifetime() time.Duration
	TruncateConnectionID() bool
}

type connectionParametersManager struct {
	mutex sync.RWMutex

	version     protocol.VersionNumber
	perspective protocol.Perspective

	flowControlNegotiated bool

	truncateConnectionID                   bool
	maxStreamsPerConnection                uint32
	maxIncomingDynamicStreamsPerConnection uint32
	idleConnectionStateLifetime            time.Duration
	sendStreamFlowControlWindow            protocol.ByteCount
	sendConnectionFlowControlWindow        protocol.ByteCount
	receiveStreamFlowControlWindow         protocol.ByteCount
	receiveConnectionFlowControlWindow     protocol.ByteCount
	maxReceiveStreamFlowControlWindow      protocol.ByteCount
	maxReceiveConnectionFlowControlWindow  protocol.ByteCount
}

var _ ConnectionParametersManager = &connectionParametersManager{}

// ErrMalformedTag is returned when the tag value cannot be read
var (
	ErrMalformedTag                         = qerr.Error(qerr.InvalidCryptoMessageParameter, "malformed Tag value")
	ErrFlowControlRenegotiationNotSupported = qerr.Error(qerr.InvalidCryptoMessageParameter, "renegotiation of flow control parameters not supported")
)

// NewConnectionParamatersManager creates a new connection parameters manager
func NewConnectionParamatersManager(
	pers protocol.Perspective, v protocol.VersionNumber,
	maxReceiveStreamFlowControlWindow protocol.ByteCount, maxReceiveConnectionFlowControlWindow protocol.ByteCount,
) ConnectionParametersManager {
	h := &connectionParametersManager{
		perspective:                           pers,
		version:                               v,
		sendStreamFlowControlWindow:           protocol.InitialStreamFlowControlWindow,     // can only be changed by the client
		sendConnectionFlowControlWindow:       protocol.InitialConnectionFlowControlWindow, // can only be changed by the client
		receiveStreamFlowControlWindow:        protocol.ReceiveStreamFlowControlWindow,
		receiveConnectionFlowControlWindow:    protocol.ReceiveConnectionFlowControlWindow,
		maxReceiveStreamFlowControlWindow:     maxReceiveStreamFlowControlWindow,
		maxReceiveConnectionFlowControlWindow: maxReceiveConnectionFlowControlWindow,
	}

	if h.perspective == protocol.PerspectiveServer {
		h.idleConnectionStateLifetime = protocol.DefaultIdleTimeout
		h.maxStreamsPerConnection = protocol.MaxStreamsPerConnection                // this is the value negotiated based on what the client sent
		h.maxIncomingDynamicStreamsPerConnection = protocol.MaxStreamsPerConnection // "incoming" seen from the client's perspective
	} else {
		h.idleConnectionStateLifetime = protocol.MaxIdleTimeoutClient
		h.maxStreamsPerConnection = protocol.MaxStreamsPerConnection                // this is the value negotiated based on what the client sent
		h.maxIncomingDynamicStreamsPerConnection = protocol.MaxStreamsPerConnection // "incoming" seen from the server's perspective
	}

	return h
}

// SetFromMap reads all params
func (h *connectionParametersManager) SetFromMap(params map[Tag][]byte) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if value, ok := params[TagTCID]; ok && h.perspective == protocol.PerspectiveServer {
		clientValue, err := utils.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return ErrMalformedTag
		}
		h.truncateConnectionID = (clientValue == 0)
	}
	if value, ok := params[TagMSPC]; ok {
		clientValue, err := utils.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return ErrMalformedTag
		}
		h.maxStreamsPerConnection = h.negotiateMaxStreamsPerConnection(clientValue)
	}
	if value, ok := params[TagMIDS]; ok {
		clientValue, err := utils.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return ErrMalformedTag
		}
		h.maxIncomingDynamicStreamsPerConnection = h.negotiateMaxIncomingDynamicStreamsPerConnection(clientValue)
	}
	if value, ok := params[TagICSL]; ok {
		clientValue, err := utils.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return ErrMalformedTag
		}
		h.idleConnectionStateLifetime = h.negotiateIdleConnectionStateLifetime(time.Duration(clientValue) * time.Second)
	}
	if value, ok := params[TagSFCW]; ok {
		if h.flowControlNegotiated {
			return ErrFlowControlRenegotiationNotSupported
		}
		sendStreamFlowControlWindow, err := utils.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return ErrMalformedTag
		}
		h.sendStreamFlowControlWindow = protocol.ByteCount(sendStreamFlowControlWindow)
	}
	if value, ok := params[TagCFCW]; ok {
		if h.flowControlNegotiated {
			return ErrFlowControlRenegotiationNotSupported
		}
		sendConnectionFlowControlWindow, err := utils.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return ErrMalformedTag
		}
		h.sendConnectionFlowControlWindow = protocol.ByteCount(sendConnectionFlowControlWindow)
	}

	_, containsSFCW := params[TagSFCW]
	_, containsCFCW := params[TagCFCW]
	if containsCFCW || containsSFCW {
		h.flowControlNegotiated = true
	}

	return nil
}

func (h *connectionParametersManager) negotiateMaxStreamsPerConnection(clientValue uint32) uint32 {
	return utils.MinUint32(clientValue, protocol.MaxStreamsPerConnection)
}

func (h *connectionParametersManager) negotiateMaxIncomingDynamicStreamsPerConnection(clientValue uint32) uint32 {
	return utils.MinUint32(clientValue, protocol.MaxIncomingDynamicStreamsPerConnection)
}

func (h *connectionParametersManager) negotiateIdleConnectionStateLifetime(clientValue time.Duration) time.Duration {
	if h.perspective == protocol.PerspectiveServer {
		return utils.MinDuration(clientValue, protocol.MaxIdleTimeoutServer)
	}
	return utils.MinDuration(clientValue, protocol.MaxIdleTimeoutClient)
}

// GetHelloMap gets all parameters needed for the Hello message
func (h *connectionParametersManager) GetHelloMap() (map[Tag][]byte, error) {
	sfcw := bytes.NewBuffer([]byte{})
	utils.WriteUint32(sfcw, uint32(h.GetReceiveStreamFlowControlWindow()))
	cfcw := bytes.NewBuffer([]byte{})
	utils.WriteUint32(cfcw, uint32(h.GetReceiveConnectionFlowControlWindow()))
	mspc := bytes.NewBuffer([]byte{})
	utils.WriteUint32(mspc, h.maxStreamsPerConnection)
	mids := bytes.NewBuffer([]byte{})
	utils.WriteUint32(mids, protocol.MaxIncomingDynamicStreamsPerConnection)
	icsl := bytes.NewBuffer([]byte{})
	utils.WriteUint32(icsl, uint32(h.GetIdleConnectionStateLifetime()/time.Second))

	return map[Tag][]byte{
		TagICSL: icsl.Bytes(),
		TagMSPC: mspc.Bytes(),
		TagMIDS: mids.Bytes(),
		TagCFCW: cfcw.Bytes(),
		TagSFCW: sfcw.Bytes(),
	}, nil
}

// GetSendStreamFlowControlWindow gets the size of the stream-level flow control window for sending data
func (h *connectionParametersManager) GetSendStreamFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.sendStreamFlowControlWindow
}

// GetSendConnectionFlowControlWindow gets the size of the stream-level flow control window for sending data
func (h *connectionParametersManager) GetSendConnectionFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.sendConnectionFlowControlWindow
}

// GetReceiveStreamFlowControlWindow gets the size of the stream-level flow control window for receiving data
func (h *connectionParametersManager) GetReceiveStreamFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.receiveStreamFlowControlWindow
}

// GetMaxReceiveStreamFlowControlWindow gets the maximum size of the stream-level flow control window for sending data
func (h *connectionParametersManager) GetMaxReceiveStreamFlowControlWindow() protocol.ByteCount {
	return h.maxReceiveStreamFlowControlWindow
}

// GetReceiveConnectionFlowControlWindow gets the size of the stream-level flow control window for receiving data
func (h *connectionParametersManager) GetReceiveConnectionFlowControlWindow() protocol.ByteCount {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.receiveConnectionFlowControlWindow
}

// GetMaxReceiveConnectionFlowControlWindow gets the maximum size of the stream-level flow control window for sending data
func (h *connectionParametersManager) GetMaxReceiveConnectionFlowControlWindow() protocol.ByteCount {
	return h.maxReceiveConnectionFlowControlWindow
}

// GetMaxOutgoingStreams gets the maximum number of outgoing streams per connection
func (h *connectionParametersManager) GetMaxOutgoingStreams() uint32 {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	return h.maxIncomingDynamicStreamsPerConnection
}

// GetMaxIncomingStreams get the maximum number of incoming streams per connection
func (h *connectionParametersManager) GetMaxIncomingStreams() uint32 {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	maxStreams := protocol.MaxIncomingDynamicStreamsPerConnection
	return utils.MaxUint32(uint32(maxStreams)+protocol.MaxStreamsMinimumIncrement, uint32(float64(maxStreams)*protocol.MaxStreamsMultiplier))
}

// GetIdleConnectionStateLifetime gets the idle timeout
func (h *connectionParametersManager) GetIdleConnectionStateLifetime() time.Duration {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.idleConnectionStateLifetime
}

// TruncateConnectionID determines if the client requests truncated ConnectionIDs
func (h *connectionParametersManager) TruncateConnectionID() bool {
	if h.perspective == protocol.PerspectiveClient {
		return false
	}

	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.truncateConnectionID
}
