package ackhandler

import (
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type sentPacketHistory struct {
	packetList *PacketList
	packetMap  map[protocol.PacketNumber]*PacketElement

	numOutstandingPackets          int
	numOutstandingHandshakePackets int

	firstOutstanding *PacketElement
}

func newSentPacketHistory() *sentPacketHistory {
	return &sentPacketHistory{
		packetList: NewPacketList(),
		packetMap:  make(map[protocol.PacketNumber]*PacketElement),
	}
}

func (h *sentPacketHistory) SentPacket(p *Packet) {
	h.sentPacketImpl(p)
}

func (h *sentPacketHistory) sentPacketImpl(p *Packet) *PacketElement {
	el := h.packetList.PushBack(*p)
	h.packetMap[p.PacketNumber] = el
	if h.firstOutstanding == nil {
		h.firstOutstanding = el
	}
	if p.canBeRetransmitted {
		h.numOutstandingPackets++
		if p.EncryptionLevel < protocol.EncryptionForwardSecure {
			h.numOutstandingHandshakePackets++
		}
	}
	return el
}

func (h *sentPacketHistory) SentPacketsAsRetransmission(packets []*Packet, retransmissionOf protocol.PacketNumber) {
	retransmission, ok := h.packetMap[retransmissionOf]
	// The retransmitted packet is not present anymore.
	// This can happen if it was acked in between dequeueing of the retransmission and sending.
	// Just treat the retransmissions as normal packets.
	// TODO: This won't happen if we clear packets queued for retransmission on new ACKs.
	if !ok {
		for _, packet := range packets {
			h.sentPacketImpl(packet)
		}
		return
	}
	retransmission.Value.retransmittedAs = make([]protocol.PacketNumber, len(packets))
	for i, packet := range packets {
		retransmission.Value.retransmittedAs[i] = packet.PacketNumber
		el := h.sentPacketImpl(packet)
		el.Value.isRetransmission = true
		el.Value.retransmissionOf = retransmissionOf
	}
}

func (h *sentPacketHistory) GetPacket(p protocol.PacketNumber) *Packet {
	if el, ok := h.packetMap[p]; ok {
		return &el.Value
	}
	return nil
}

// Iterate iterates through all packets.
// The callback must not modify the history.
func (h *sentPacketHistory) Iterate(cb func(*Packet) (cont bool, err error)) error {
	cont := true
	for el := h.packetList.Front(); cont && el != nil; el = el.Next() {
		var err error
		cont, err = cb(&el.Value)
		if err != nil {
			return err
		}
	}
	return nil
}

// FirstOutStanding returns the first outstanding packet.
// It must not be modified (e.g. retransmitted).
// Use DequeueFirstPacketForRetransmission() to retransmit it.
func (h *sentPacketHistory) FirstOutstanding() *Packet {
	if h.firstOutstanding == nil {
		return nil
	}
	return &h.firstOutstanding.Value
}

// QueuePacketForRetransmission marks a packet for retransmission.
// A packet can only be queued once.
func (h *sentPacketHistory) MarkCannotBeRetransmitted(pn protocol.PacketNumber) error {
	el, ok := h.packetMap[pn]
	if !ok {
		return fmt.Errorf("sent packet history: packet %d not found", pn)
	}
	if el.Value.canBeRetransmitted {
		h.numOutstandingPackets--
		if h.numOutstandingPackets < 0 {
			panic("numOutstandingHandshakePackets negative")
		}
		if el.Value.EncryptionLevel < protocol.EncryptionForwardSecure {
			h.numOutstandingHandshakePackets--
			if h.numOutstandingHandshakePackets < 0 {
				panic("numOutstandingHandshakePackets negative")
			}
		}
	}
	el.Value.canBeRetransmitted = false
	if el == h.firstOutstanding {
		h.readjustFirstOutstanding()
	}
	return nil
}

// readjustFirstOutstanding readjusts the pointer to the first outstanding packet.
// This is necessary every time the first outstanding packet is deleted or retransmitted.
func (h *sentPacketHistory) readjustFirstOutstanding() {
	el := h.firstOutstanding.Next()
	for el != nil && !el.Value.canBeRetransmitted {
		el = el.Next()
	}
	h.firstOutstanding = el
}

func (h *sentPacketHistory) Len() int {
	return len(h.packetMap)
}

func (h *sentPacketHistory) Remove(p protocol.PacketNumber) error {
	el, ok := h.packetMap[p]
	if !ok {
		return fmt.Errorf("packet %d not found in sent packet history", p)
	}
	if el == h.firstOutstanding {
		h.readjustFirstOutstanding()
	}
	if el.Value.canBeRetransmitted {
		h.numOutstandingPackets--
		if h.numOutstandingPackets < 0 {
			panic("numOutstandingHandshakePackets negative")
		}
		if el.Value.EncryptionLevel < protocol.EncryptionForwardSecure {
			h.numOutstandingHandshakePackets--
			if h.numOutstandingHandshakePackets < 0 {
				panic("numOutstandingHandshakePackets negative")
			}
		}
	}
	h.packetList.Remove(el)
	delete(h.packetMap, p)
	return nil
}

func (h *sentPacketHistory) HasOutstandingPackets() bool {
	return h.numOutstandingPackets > 0
}

func (h *sentPacketHistory) HasOutstandingHandshakePackets() bool {
	return h.numOutstandingHandshakePackets > 0
}
