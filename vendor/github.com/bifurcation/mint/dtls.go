package mint

import (
	"fmt"
	"github.com/bifurcation/mint/syntax"
	"time"
)

const (
	initialMtu     = 1200
	initialTimeout = 100
)

// labels for timers
const (
	retransmitTimerLabel = "handshake retransmit"
	ackTimerLabel        = "ack timer"
)

type SentHandshakeFragment struct {
	seq        uint32
	offset     int
	fragLength int
	record     uint64
	acked      bool
}

type DtlsAck struct {
	RecordNumbers []uint64 `tls:"head=2"`
}

func wireVersion(h *HandshakeLayer) uint16 {
	if h.datagram {
		return dtls12WireVersion
	}
	return tls12Version
}

func dtlsConvertVersion(version uint16) uint16 {
	if version == tls12Version {
		return dtls12WireVersion
	}
	if version == tls10Version {
		return 0xfeff
	}
	panic(fmt.Sprintf("Internal error, unexpected version=%d", version))
}

// TODO(ekr@rtfm.com): Move these to state-machine.go
func (h *HandshakeContext) handshakeRetransmit() error {
	if _, err := h.hOut.SendQueuedMessages(); err != nil {
		return err
	}

	h.timers.start(retransmitTimerLabel,
		h.handshakeRetransmit,
		h.timeoutMS)

	// TODO(ekr@rtfm.com): Back off timer
	return nil
}

func (h *HandshakeContext) sendAck() error {
	toack := h.hIn.recvdRecords

	count := (initialMtu - 2) / 8 // TODO(ekr@rtfm.com): Current MTU
	if len(toack) > count {
		toack = toack[:count]
	}
	logf(logTypeHandshake, "Sending ACK: [%x]", toack)

	ack := &DtlsAck{toack}
	body, err := syntax.Marshal(&ack)
	if err != nil {
		return err
	}
	err = h.hOut.conn.WriteRecord(&TLSPlaintext{
		contentType: RecordTypeAck,
		fragment:    body,
	})
	if err != nil {
		return err
	}
	return nil
}

func (h *HandshakeContext) processAck(data []byte) error {
	// Cancel the retransmit timer because we will be resending
	// and possibly re-arming later.
	h.timers.cancel(retransmitTimerLabel)

	ack := &DtlsAck{}
	read, err := syntax.Unmarshal(data, &ack)
	if err != nil {
		return err
	}
	if len(data) != read {
		return fmt.Errorf("Invalid encoding: Extra data not consumed")
	}
	logf(logTypeHandshake, "ACK: [%x]", ack.RecordNumbers)

	for _, r := range ack.RecordNumbers {
		for _, m := range h.sentFragments {
			if r == m.record {
				logf(logTypeHandshake, "Marking %v %v(%v) as acked",
					m.seq, m.offset, m.fragLength)
				m.acked = true
			}
		}
	}

	count, err := h.hOut.SendQueuedMessages()
	if err != nil {
		return err
	}

	if count == 0 {
		logf(logTypeHandshake, "All messages ACKed")
		h.hOut.ClearQueuedMessages()
		return nil
	}

	// Reset the timer
	h.timers.start(retransmitTimerLabel,
		h.handshakeRetransmit,
		h.timeoutMS)

	return nil
}

func (c *Conn) GetDTLSTimeout() (bool, time.Duration) {
	return c.hsCtx.timers.remaining()
}

func (h *HandshakeContext) receivedHandshakeMessage() {
	logf(logTypeHandshake, "%p Received handshake, waiting for start of flight = %v", h, h.waitingNextFlight)
	// This just enables tests.
	if h.hIn == nil {
		return
	}

	if !h.hIn.datagram {
		return
	}

	if h.waitingNextFlight {
		logf(logTypeHandshake, "Received the start of the flight")

		// Clear the outgoing DTLS queue and terminate the retransmit timer
		h.hOut.ClearQueuedMessages()
		h.timers.cancel(retransmitTimerLabel)

		// OK, we're not waiting any more.
		h.waitingNextFlight = false
	}

	// Now pre-emptively arm the ACK timer if it's not armed already.
	// We'll automatically dis-arm it at the end of the handshake.
	if h.timers.getTimer(ackTimerLabel) == nil {
		h.timers.start(ackTimerLabel, h.sendAck, h.timeoutMS/4)
	}
}

func (h *HandshakeContext) receivedEndOfFlight() {
	logf(logTypeHandshake, "%p Received the end of the flight", h)
	if !h.hIn.datagram {
		return
	}

	// Empty incoming queue
	h.hIn.queued = nil

	// Note that we are waiting for the next flight.
	h.waitingNextFlight = true

	// Clear the ACK queue.
	h.hIn.recvdRecords = nil

	// Disarm the ACK timer
	h.timers.cancel(ackTimerLabel)
}

func (h *HandshakeContext) receivedFinalFlight() {
	logf(logTypeHandshake, "%p Received final flight", h)
	if !h.hIn.datagram {
		return
	}

	// Disarm the ACK timer
	h.timers.cancel(ackTimerLabel)

	// But send an ACK immediately.
	h.sendAck()
}

func (h *HandshakeContext) fragmentAcked(seq uint32, offset int, fraglen int) bool {
	logf(logTypeHandshake, "Looking to see if fragment %v %v(%v) was acked", seq, offset, fraglen)
	for _, f := range h.sentFragments {
		if !f.acked {
			continue
		}

		if f.seq != seq {
			continue
		}

		if f.offset > offset {
			continue
		}

		// At this point, we know that the stored fragment starts
		// at or before what we want to send, so check where the end
		// is.
		if f.offset+f.fragLength < offset+fraglen {
			continue
		}

		return true
	}

	return false
}
