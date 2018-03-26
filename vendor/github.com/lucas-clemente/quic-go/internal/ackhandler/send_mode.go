package ackhandler

import "fmt"

// The SendMode says what kind of packets can be sent.
type SendMode uint8

const (
	// SendNone means that no packets should be sent
	SendNone SendMode = iota
	// SendAck means an ACK-only packet should be sent
	SendAck
	// SendRetransmission means that retransmissions should be sent
	SendRetransmission
	// SendAny packet should be sent
	SendAny
)

func (s SendMode) String() string {
	switch s {
	case SendNone:
		return "none"
	case SendAck:
		return "ack"
	case SendRetransmission:
		return "retransmission"
	case SendAny:
		return "any"
	default:
		return fmt.Sprintf("invalid send mode: %d", s)
	}
}
