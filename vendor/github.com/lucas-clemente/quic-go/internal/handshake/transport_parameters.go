package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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

	MaxPacketSize protocol.ByteCount

	MaxUniStreams  uint16 // only used for IETF QUIC
	MaxBidiStreams uint16 // only used for IETF QUIC
	MaxStreams     uint32 // only used for gQUIC

	OmitConnectionID    bool // only used for gQUIC
	IdleTimeout         time.Duration
	DisableMigration    bool   // only used for IETF QUIC
	StatelessResetToken []byte // only used for IETF QUIC
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

func (p *TransportParameters) unmarshal(data []byte) error {
	var foundIdleTimeout bool

	for len(data) >= 4 {
		paramID := binary.BigEndian.Uint16(data[:2])
		paramLen := int(binary.BigEndian.Uint16(data[2:4]))
		data = data[4:]
		if len(data) < paramLen {
			return fmt.Errorf("remaining length (%d) smaller than parameter length (%d)", len(data), paramLen)
		}
		switch transportParameterID(paramID) {
		case initialMaxStreamDataParameterID:
			if paramLen != 4 {
				return fmt.Errorf("wrong length for initial_max_stream_data: %d (expected 4)", paramLen)
			}
			p.StreamFlowControlWindow = protocol.ByteCount(binary.BigEndian.Uint32(data[:4]))
		case initialMaxDataParameterID:
			if paramLen != 4 {
				return fmt.Errorf("wrong length for initial_max_data: %d (expected 4)", paramLen)
			}
			p.ConnectionFlowControlWindow = protocol.ByteCount(binary.BigEndian.Uint32(data[:4]))
		case initialMaxBidiStreamsParameterID:
			if paramLen != 2 {
				return fmt.Errorf("wrong length for initial_max_stream_id_bidi: %d (expected 2)", paramLen)
			}
			p.MaxBidiStreams = binary.BigEndian.Uint16(data[:2])
		case initialMaxUniStreamsParameterID:
			if paramLen != 2 {
				return fmt.Errorf("wrong length for initial_max_stream_id_uni: %d (expected 2)", paramLen)
			}
			p.MaxUniStreams = binary.BigEndian.Uint16(data[:2])
		case idleTimeoutParameterID:
			foundIdleTimeout = true
			if paramLen != 2 {
				return fmt.Errorf("wrong length for idle_timeout: %d (expected 2)", paramLen)
			}
			p.IdleTimeout = utils.MaxDuration(protocol.MinRemoteIdleTimeout, time.Duration(binary.BigEndian.Uint16(data[:2]))*time.Second)
		case maxPacketSizeParameterID:
			if paramLen != 2 {
				return fmt.Errorf("wrong length for max_packet_size: %d (expected 2)", paramLen)
			}
			maxPacketSize := protocol.ByteCount(binary.BigEndian.Uint16(data[:2]))
			if maxPacketSize < 1200 {
				return fmt.Errorf("invalid value for max_packet_size: %d (minimum 1200)", maxPacketSize)
			}
			p.MaxPacketSize = maxPacketSize
		case disableMigrationParameterID:
			if paramLen != 0 {
				return fmt.Errorf("wrong length for disable_migration: %d (expected empty)", paramLen)
			}
			p.DisableMigration = true
		case statelessResetTokenParameterID:
			if paramLen != 16 {
				return fmt.Errorf("wrong length for stateless_reset_token: %d (expected 16)", paramLen)
			}
			p.StatelessResetToken = data[:16]
		}
		data = data[paramLen:]
	}

	if len(data) != 0 {
		return fmt.Errorf("should have read all data. Still have %d bytes", len(data))
	}
	if !foundIdleTimeout {
		return errors.New("missing parameter")
	}
	return nil
}

func (p *TransportParameters) marshal(b *bytes.Buffer) {
	// initial_max_stream_data
	utils.BigEndian.WriteUint16(b, uint16(initialMaxStreamDataParameterID))
	utils.BigEndian.WriteUint16(b, 4)
	utils.BigEndian.WriteUint32(b, uint32(p.StreamFlowControlWindow))
	// initial_max_data
	utils.BigEndian.WriteUint16(b, uint16(initialMaxDataParameterID))
	utils.BigEndian.WriteUint16(b, 4)
	utils.BigEndian.WriteUint32(b, uint32(p.ConnectionFlowControlWindow))
	// initial_max_bidi_streams
	utils.BigEndian.WriteUint16(b, uint16(initialMaxBidiStreamsParameterID))
	utils.BigEndian.WriteUint16(b, 2)
	utils.BigEndian.WriteUint16(b, p.MaxBidiStreams)
	// initial_max_uni_streams
	utils.BigEndian.WriteUint16(b, uint16(initialMaxUniStreamsParameterID))
	utils.BigEndian.WriteUint16(b, 2)
	utils.BigEndian.WriteUint16(b, p.MaxUniStreams)
	// idle_timeout
	utils.BigEndian.WriteUint16(b, uint16(idleTimeoutParameterID))
	utils.BigEndian.WriteUint16(b, 2)
	utils.BigEndian.WriteUint16(b, uint16(p.IdleTimeout/time.Second))
	// max_packet_size
	utils.BigEndian.WriteUint16(b, uint16(maxPacketSizeParameterID))
	utils.BigEndian.WriteUint16(b, 2)
	utils.BigEndian.WriteUint16(b, uint16(protocol.MaxReceivePacketSize))
	// disable_migration
	if p.DisableMigration {
		utils.BigEndian.WriteUint16(b, uint16(disableMigrationParameterID))
		utils.BigEndian.WriteUint16(b, 0)
	}
	if len(p.StatelessResetToken) > 0 {
		utils.BigEndian.WriteUint16(b, uint16(statelessResetTokenParameterID))
		utils.BigEndian.WriteUint16(b, uint16(len(p.StatelessResetToken))) // should always be 16 bytes
		b.Write(p.StatelessResetToken)
	}
}

// String returns a string representation, intended for logging.
// It should only used for IETF QUIC.
func (p *TransportParameters) String() string {
	return fmt.Sprintf("&handshake.TransportParameters{StreamFlowControlWindow: %#x, ConnectionFlowControlWindow: %#x, MaxBidiStreams: %d, MaxUniStreams: %d, IdleTimeout: %s}", p.StreamFlowControlWindow, p.ConnectionFlowControlWindow, p.MaxBidiStreams, p.MaxUniStreams, p.IdleTimeout)
}
