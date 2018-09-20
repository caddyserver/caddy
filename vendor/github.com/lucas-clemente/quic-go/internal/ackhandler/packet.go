package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// A Packet is a packet
type Packet struct {
	PacketNumber    protocol.PacketNumber
	PacketType      protocol.PacketType
	Frames          []wire.Frame
	Length          protocol.ByteCount
	EncryptionLevel protocol.EncryptionLevel
	SendTime        time.Time

	largestAcked protocol.PacketNumber // if the packet contains an ACK, the LargestAcked value of that ACK

	// There are two reasons why a packet cannot be retransmitted:
	// * it was already retransmitted
	// * this packet is a retransmission, and we already received an ACK for the original packet
	canBeRetransmitted      bool
	includedInBytesInFlight bool
	retransmittedAs         []protocol.PacketNumber
	isRetransmission        bool // we need a separate bool here because 0 is a valid packet number
	retransmissionOf        protocol.PacketNumber
}
