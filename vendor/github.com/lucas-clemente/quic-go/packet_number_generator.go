package quic

import (
	"crypto/rand"
	"math"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// The packetNumberGenerator generates the packet number for the next packet
// it randomly skips a packet number every averagePeriod packets (on average)
// it is guarantued to never skip two consecutive packet numbers
type packetNumberGenerator struct {
	averagePeriod protocol.PacketNumber

	next       protocol.PacketNumber
	nextToSkip protocol.PacketNumber
}

func newPacketNumberGenerator(initial, averagePeriod protocol.PacketNumber) *packetNumberGenerator {
	return &packetNumberGenerator{
		next:          initial,
		averagePeriod: averagePeriod,
	}
}

func (p *packetNumberGenerator) Peek() protocol.PacketNumber {
	return p.next
}

func (p *packetNumberGenerator) Pop() protocol.PacketNumber {
	next := p.next

	// generate a new packet number for the next packet
	p.next++

	if p.next == p.nextToSkip {
		p.next++
		p.generateNewSkip()
	}

	return next
}

func (p *packetNumberGenerator) generateNewSkip() error {
	num, err := p.getRandomNumber()
	if err != nil {
		return err
	}

	skip := protocol.PacketNumber(num) * (p.averagePeriod - 1) / (math.MaxUint16 / 2)
	// make sure that there are never two consecutive packet numbers that are skipped
	p.nextToSkip = p.next + 2 + skip

	return nil
}

// getRandomNumber() generates a cryptographically secure random number between 0 and MaxUint16 (= 65535)
// The expectation value is 65535/2
func (p *packetNumberGenerator) getRandomNumber() (uint16, error) {
	b := make([]byte, 2)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}

	num := uint16(b[0])<<8 + uint16(b[1])
	return num, nil
}
