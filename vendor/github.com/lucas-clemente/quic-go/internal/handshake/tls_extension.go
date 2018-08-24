package handshake

import (
	"github.com/bifurcation/mint"
)

type transportParameterID uint16

const quicTLSExtensionType = 0xff5

const (
	initialMaxStreamDataParameterID  transportParameterID = 0x0
	initialMaxDataParameterID        transportParameterID = 0x1
	initialMaxBidiStreamsParameterID transportParameterID = 0x2
	idleTimeoutParameterID           transportParameterID = 0x3
	maxPacketSizeParameterID         transportParameterID = 0x5
	statelessResetTokenParameterID   transportParameterID = 0x6
	initialMaxUniStreamsParameterID  transportParameterID = 0x8
	disableMigrationParameterID      transportParameterID = 0x9
)

type transportParameter struct {
	Parameter transportParameterID
	Value     []byte `tls:"head=2"`
}

type clientHelloTransportParameters struct {
	InitialVersion uint32               // actually a protocol.VersionNumber
	Parameters     []transportParameter `tls:"head=2"`
}

type encryptedExtensionsTransportParameters struct {
	NegotiatedVersion uint32               // actually a protocol.VersionNumber
	SupportedVersions []uint32             `tls:"head=1"` // actually a protocol.VersionNumber
	Parameters        []transportParameter `tls:"head=2"`
}

type tlsExtensionBody struct {
	data []byte
}

var _ mint.ExtensionBody = &tlsExtensionBody{}

func (e *tlsExtensionBody) Type() mint.ExtensionType {
	return quicTLSExtensionType
}

func (e *tlsExtensionBody) Marshal() ([]byte, error) {
	return e.data, nil
}

func (e *tlsExtensionBody) Unmarshal(data []byte) (int, error) {
	e.data = data
	return len(data), nil
}
