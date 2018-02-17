package ackhandler

import (
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	// SentPacket may modify the packet
	SentPacket(packet *Packet) error
	ReceivedAck(ackFrame *wire.AckFrame, withPacketNumber protocol.PacketNumber, encLevel protocol.EncryptionLevel, recvTime time.Time) error
	SetHandshakeComplete()

	// SendingAllowed says if a packet can be sent.
	// Sending packets might not be possible because:
	// * we're congestion limited
	// * we're tracking the maximum number of sent packets
	SendingAllowed() bool
	// TimeUntilSend is the time when the next packet should be sent.
	// It is used for pacing packets.
	TimeUntilSend() time.Time
	// ShouldSendNumPackets returns the number of packets that should be sent immediately.
	// It always returns a number greater or equal than 1.
	// A number greater than 1 is returned when the pacing delay is smaller than the minimum pacing delay.
	// Note that the number of packets is only calculated based on the pacing algorithm.
	// Before sending any packet, SendingAllowed() must be called to learn if we can actually send it.
	ShouldSendNumPackets() int

	GetStopWaitingFrame(force bool) *wire.StopWaitingFrame
	GetLowestPacketNotConfirmedAcked() protocol.PacketNumber
	DequeuePacketForRetransmission() (packet *Packet)
	GetLeastUnacked() protocol.PacketNumber

	GetAlarmTimeout() time.Time
	OnAlarm()
}

// ReceivedPacketHandler handles ACKs needed to send for incoming packets
type ReceivedPacketHandler interface {
	ReceivedPacket(packetNumber protocol.PacketNumber, rcvTime time.Time, shouldInstigateAck bool) error
	IgnoreBelow(protocol.PacketNumber)

	GetAlarmTimeout() time.Time
	GetAckFrame() *wire.AckFrame
}
