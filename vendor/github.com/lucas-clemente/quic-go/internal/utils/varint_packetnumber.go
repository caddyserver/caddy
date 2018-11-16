package utils

import (
	"bytes"
	"fmt"

	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// ReadVarIntPacketNumber reads a number in the QUIC varint packet number format
func ReadVarIntPacketNumber(b *bytes.Reader) (protocol.PacketNumber, protocol.PacketNumberLen, error) {
	b1, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	if b1&0x80 == 0 {
		return protocol.PacketNumber(b1), protocol.PacketNumberLen1, nil
	}
	b2, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	if b1&0x40 == 0 {
		return protocol.PacketNumber(uint64(b1&0x3f)<<8 + uint64(b2)), protocol.PacketNumberLen2, nil
	}
	b3, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	b4, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	return protocol.PacketNumber(uint64(b1&0x3f)<<24 + uint64(b2)<<16 + uint64(b3)<<8 + uint64(b4)), protocol.PacketNumberLen4, nil
}

// WriteVarIntPacketNumber writes a packet number in the QUIC varint packet number format
func WriteVarIntPacketNumber(b *bytes.Buffer, i protocol.PacketNumber, len protocol.PacketNumberLen) error {
	switch len {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(i & 0x7f))
	case protocol.PacketNumberLen2:
		b.Write([]byte{(uint8(i>>8) & 0x3f) | 0x80, uint8(i)})
	case protocol.PacketNumberLen4:
		b.Write([]byte{(uint8(i>>24) & 0x3f) | 0xc0, uint8(i >> 16), uint8(i >> 8), uint8(i)})
	default:
		return fmt.Errorf("invalid packet number length: %d", len)
	}
	return nil
}
