package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// A Packet is a packet
// +gen linkedlist
type Packet struct {
	PacketNumber    protocol.PacketNumber
	Frames          []wire.Frame
	Length          protocol.ByteCount
	EncryptionLevel protocol.EncryptionLevel

	largestAcked protocol.PacketNumber // if the packet contains an ACK, the LargestAcked value of that ACK
	sendTime     time.Time
}

// GetFramesForRetransmission gets all the frames for retransmission
func (p *Packet) GetFramesForRetransmission() []wire.Frame {
	var fs []wire.Frame
	for _, frame := range p.Frames {
		switch frame.(type) {
		case *wire.AckFrame:
			continue
		case *wire.StopWaitingFrame:
			continue
		}
		fs = append(fs, frame)
	}
	return fs
}
