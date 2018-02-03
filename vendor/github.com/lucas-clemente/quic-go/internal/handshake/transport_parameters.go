package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/qerr"
)

// errMalformedTag is returned when the tag value cannot be read
var errMalformedTag = qerr.Error(qerr.InvalidCryptoMessageParameter, "malformed Tag value")

// TransportParameters are parameters sent to the peer during the handshake
type TransportParameters struct {
	StreamFlowControlWindow     protocol.ByteCount
	ConnectionFlowControlWindow protocol.ByteCount

	MaxStreams uint32

	OmitConnectionID bool
	IdleTimeout      time.Duration
}

// readHelloMap reads the transport parameters from the tags sent in a gQUIC handshake message
func readHelloMap(tags map[Tag][]byte) (*TransportParameters, error) {
	params := &TransportParameters{}
	if value, ok := tags[TagTCID]; ok {
		v, err := utils.LittleEndian.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return nil, errMalformedTag
		}
		params.OmitConnectionID = (v == 0)
	}
	if value, ok := tags[TagMIDS]; ok {
		v, err := utils.LittleEndian.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return nil, errMalformedTag
		}
		params.MaxStreams = v
	}
	if value, ok := tags[TagICSL]; ok {
		v, err := utils.LittleEndian.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return nil, errMalformedTag
		}
		params.IdleTimeout = utils.MaxDuration(protocol.MinRemoteIdleTimeout, time.Duration(v)*time.Second)
	}
	if value, ok := tags[TagSFCW]; ok {
		v, err := utils.LittleEndian.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return nil, errMalformedTag
		}
		params.StreamFlowControlWindow = protocol.ByteCount(v)
	}
	if value, ok := tags[TagCFCW]; ok {
		v, err := utils.LittleEndian.ReadUint32(bytes.NewBuffer(value))
		if err != nil {
			return nil, errMalformedTag
		}
		params.ConnectionFlowControlWindow = protocol.ByteCount(v)
	}
	return params, nil
}

// GetHelloMap gets all parameters needed for the Hello message in the gQUIC handshake.
func (p *TransportParameters) getHelloMap() map[Tag][]byte {
	sfcw := bytes.NewBuffer([]byte{})
	utils.LittleEndian.WriteUint32(sfcw, uint32(p.StreamFlowControlWindow))
	cfcw := bytes.NewBuffer([]byte{})
	utils.LittleEndian.WriteUint32(cfcw, uint32(p.ConnectionFlowControlWindow))
	mids := bytes.NewBuffer([]byte{})
	utils.LittleEndian.WriteUint32(mids, p.MaxStreams)
	icsl := bytes.NewBuffer([]byte{})
	utils.LittleEndian.WriteUint32(icsl, uint32(p.IdleTimeout/time.Second))

	tags := map[Tag][]byte{
		TagICSL: icsl.Bytes(),
		TagMIDS: mids.Bytes(),
		TagCFCW: cfcw.Bytes(),
		TagSFCW: sfcw.Bytes(),
	}
	if p.OmitConnectionID {
		tags[TagTCID] = []byte{0, 0, 0, 0}
	}
	return tags
}

// readTransportParameters reads the transport parameters sent in the QUIC TLS extension
func readTransportParamters(paramsList []transportParameter) (*TransportParameters, error) {
	params := &TransportParameters{}

	var foundInitialMaxStreamData bool
	var foundInitialMaxData bool
	var foundIdleTimeout bool

	for _, p := range paramsList {
		switch p.Parameter {
		case initialMaxStreamDataParameterID:
			foundInitialMaxStreamData = true
			if len(p.Value) != 4 {
				return nil, fmt.Errorf("wrong length for initial_max_stream_data: %d (expected 4)", len(p.Value))
			}
			params.StreamFlowControlWindow = protocol.ByteCount(binary.BigEndian.Uint32(p.Value))
		case initialMaxDataParameterID:
			foundInitialMaxData = true
			if len(p.Value) != 4 {
				return nil, fmt.Errorf("wrong length for initial_max_data: %d (expected 4)", len(p.Value))
			}
			params.ConnectionFlowControlWindow = protocol.ByteCount(binary.BigEndian.Uint32(p.Value))
		case initialMaxStreamIDBiDiParameterID:
			if len(p.Value) != 4 {
				return nil, fmt.Errorf("wrong length for initial_max_stream_id_bidi: %d (expected 4)", len(p.Value))
			}
			// TODO: handle this value
		case initialMaxStreamIDUniParameterID:
			if len(p.Value) != 4 {
				return nil, fmt.Errorf("wrong length for initial_max_stream_id_uni: %d (expected 4)", len(p.Value))
			}
			// TODO: handle this value
		case idleTimeoutParameterID:
			foundIdleTimeout = true
			if len(p.Value) != 2 {
				return nil, fmt.Errorf("wrong length for idle_timeout: %d (expected 2)", len(p.Value))
			}
			params.IdleTimeout = utils.MaxDuration(protocol.MinRemoteIdleTimeout, time.Duration(binary.BigEndian.Uint16(p.Value))*time.Second)
		case omitConnectionIDParameterID:
			if len(p.Value) != 0 {
				return nil, fmt.Errorf("wrong length for omit_connection_id: %d (expected empty)", len(p.Value))
			}
			params.OmitConnectionID = true
		}
	}

	if !(foundInitialMaxStreamData && foundInitialMaxData && foundIdleTimeout) {
		return nil, errors.New("missing parameter")
	}
	return params, nil
}

// GetTransportParameters gets the parameters needed for the TLS handshake.
// It doesn't send the initial_max_stream_id_uni parameter, so the peer isn't allowed to open any unidirectional streams.
func (p *TransportParameters) getTransportParameters() []transportParameter {
	initialMaxStreamData := make([]byte, 4)
	binary.BigEndian.PutUint32(initialMaxStreamData, uint32(p.StreamFlowControlWindow))
	initialMaxData := make([]byte, 4)
	binary.BigEndian.PutUint32(initialMaxData, uint32(p.ConnectionFlowControlWindow))
	initialMaxStreamIDBiDi := make([]byte, 4)
	// TODO: use a reasonable value here
	binary.BigEndian.PutUint32(initialMaxStreamIDBiDi, math.MaxUint32)
	idleTimeout := make([]byte, 2)
	binary.BigEndian.PutUint16(idleTimeout, uint16(p.IdleTimeout/time.Second))
	maxPacketSize := make([]byte, 2)
	binary.BigEndian.PutUint16(maxPacketSize, uint16(protocol.MaxReceivePacketSize))
	params := []transportParameter{
		{initialMaxStreamDataParameterID, initialMaxStreamData},
		{initialMaxDataParameterID, initialMaxData},
		{initialMaxStreamIDBiDiParameterID, initialMaxStreamIDBiDi},
		{idleTimeoutParameterID, idleTimeout},
		{maxPacketSizeParameterID, maxPacketSize},
	}
	if p.OmitConnectionID {
		params = append(params, transportParameter{omitConnectionIDParameterID, []byte{}})
	}
	return params
}
