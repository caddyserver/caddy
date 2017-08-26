package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// A Packet is a packet
// +gen linkedlist
type Packet struct {
	PacketNumber    protocol.PacketNumber
	Frames          []frames.Frame
	Length          protocol.ByteCount
	EncryptionLevel protocol.EncryptionLevel

	SendTime time.Time
}

// GetFramesForRetransmission gets all the frames for retransmission
func (p *Packet) GetFramesForRetransmission() []frames.Frame {
	var fs []frames.Frame
	for _, frame := range p.Frames {
		switch frame.(type) {
		case *frames.AckFrame:
			continue
		case *frames.StopWaitingFrame:
			continue
		}
		fs = append(fs, frame)
	}
	return fs
}
