package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/frames"
	"github.com/lucas-clemente/quic-go/protocol"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	// SentPacket may modify the packet
	SentPacket(packet *Packet) error
	ReceivedAck(ackFrame *frames.AckFrame, withPacketNumber protocol.PacketNumber, recvTime time.Time) error

	SendingAllowed() bool
	GetStopWaitingFrame(force bool) *frames.StopWaitingFrame
	DequeuePacketForRetransmission() (packet *Packet)
	GetLeastUnacked() protocol.PacketNumber

	GetAlarmTimeout() time.Time
	OnAlarm()
}

// ReceivedPacketHandler handles ACKs needed to send for incoming packets
type ReceivedPacketHandler interface {
	ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool) error
	ReceivedStopWaiting(*frames.StopWaitingFrame) error

	GetAlarmTimeout() time.Time
	GetAckFrame() *frames.AckFrame
}
