package frames

import "github.com/lucas-clemente/quic-go/protocol"

// AckRange is an ACK range
type AckRange struct {
	FirstPacketNumber protocol.PacketNumber
	LastPacketNumber  protocol.PacketNumber
}
